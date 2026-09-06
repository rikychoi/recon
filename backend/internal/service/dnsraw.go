package service

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// rawResolver는 CNAME을 raw DNS 질의(TYPE=CNAME)로, 가능하면 해당 도메인의 "권위 네임서버"에
// 직접 물어보는 cnameLookuper 구현이다.
//
// 표준 net.LookupCNAME은 체인을 따라가며 대상을 해석하려다 댕글링(대상 NXDOMAIN) 시 실패한다.
// 게다가 실환경에서는 (1) 로컬/ISP 리졸버가 옛 CNAME을 캐시하거나 (2) 공개 리졸버(1.1.1.1 등)가
// 댕글링 이름에 SERVFAIL을 주는 일이 잦다. 그래서 대상 도메인의 권위 NS에 직접 TYPE=CNAME을
// 질의하여 캐시·재귀 리졸버 문제를 우회하고 CNAME 레코드를 정확히 얻는다.
type rawResolver struct {
	fallback []string      // 권위 NS를 못 찾을 때 쓸 리졸버(host:port)
	client   *dns.Client   // miekg/dns 클라이언트
	netres   *net.Resolver // NS/호스트 해석용 표준 리졸버
}

// newRawResolver는 시스템 리졸버(/etc/resolv.conf)를 폴백으로 사용하는 rawResolver를 생성한다.
func newRawResolver() *rawResolver {
	return &rawResolver{
		fallback: systemDNSServers(),
		client:   &dns.Client{Timeout: 5 * time.Second},
		netres:   net.DefaultResolver,
	}
}

// LookupCNAME은 호스트의 CNAME 대상을 반환한다.
// 대상 도메인의 권위 NS에 TYPE=CNAME을 직접 질의하며(캐시/재귀 우회), 못 찾으면 폴백 리졸버로 질의한다.
// CNAME이 없으면 호스트 자신을, 모든 질의 실패 시 오류를 반환한다.
// 대상이 NXDOMAIN이어도 CNAME 레코드가 있으면 그 대상을 반환한다(댕글링 탐지의 핵심).
func (r *rawResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	servers := r.authoritativeServers(ctx, host)
	servers = append(servers, r.fallback...) // 권위 NS 우선, 실패 시 폴백

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeCNAME)

	var lastErr error
	for _, srv := range servers {
		resp, _, err := r.client.ExchangeContext(ctx, m, srv)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			lastErr = &dnsRcodeError{resp.Rcode} // SERVFAIL 등은 다음 서버로.
			continue
		}
		for _, ans := range resp.Answer {
			if cn, ok := ans.(*dns.CNAME); ok {
				return cn.Target, nil // 대상이 해석 안 돼도 CNAME RR은 반환됨.
			}
		}
		return host, nil // 정상 응답이나 CNAME 없음 → 외부 CNAME 없음.
	}
	if lastErr == nil {
		return host, nil
	}
	return "", lastErr
}

// LookupHost는 표준 리졸버로 호스트를 IP 해석한다. 대상이 사라지면 오류(NXDOMAIN)를 반환한다.
func (r *rawResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return r.netres.LookupHost(ctx, host)
}

// authoritativeServers는 host가 속한 존의 권위 네임서버 주소(host:port) 목록을 찾는다.
// host부터 상위 라벨로 올라가며 NS 레코드를 조회하고, 찾으면 그 NS들을 IP로 해석해 반환한다.
// 못 찾으면 빈 목록(호출측이 폴백 사용).
func (r *rawResolver) authoritativeServers(ctx context.Context, host string) []string {
	name := strings.TrimSuffix(host, ".")
	for name != "" && strings.Contains(name, ".") {
		if ns := r.lookupNS(ctx, name); len(ns) > 0 {
			var out []string
			for _, h := range ns {
				if ips, err := r.netres.LookupHost(ctx, h); err == nil {
					for _, ip := range ips {
						out = append(out, net.JoinHostPort(ip, "53"))
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
		// 상위 존으로: 맨 앞 라벨 제거
		if i := strings.Index(name, "."); i >= 0 {
			name = name[i+1:]
		} else {
			break
		}
	}
	return nil
}

// lookupNS는 폴백 리졸버로 이름의 NS 레코드(존 이름)를 조회한다(응답/권한 섹션 모두 확인).
func (r *rawResolver) lookupNS(ctx context.Context, name string) []string {
	if len(r.fallback) == 0 {
		return nil
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeNS)
	resp, _, err := r.client.ExchangeContext(ctx, m, r.fallback[0])
	if err != nil || resp == nil {
		return nil
	}
	var ns []string
	for _, rr := range append(resp.Answer, resp.Ns...) {
		if n, ok := rr.(*dns.NS); ok {
			ns = append(ns, strings.TrimSuffix(n.Ns, "."))
		}
	}
	return ns
}

// dnsRcodeError는 성공/NXDOMAIN이 아닌 응답 코드(SERVFAIL 등)를 나타낸다.
type dnsRcodeError struct{ rcode int }

func (e *dnsRcodeError) Error() string { return "dns rcode " + dns.RcodeToString[e.rcode] }

// systemDNSServers는 /etc/resolv.conf의 DNS 서버를 host:port로 반환한다.
// 읽지 못하면 공개 리졸버(1.1.1.1:53)로 폴백한다.
func systemDNSServers() []string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(cfg.Servers) > 0 {
		out := make([]string, 0, len(cfg.Servers))
		for _, s := range cfg.Servers {
			out = append(out, net.JoinHostPort(s, cfg.Port))
		}
		return out
	}
	return []string{"1.1.1.1:53"}
}
