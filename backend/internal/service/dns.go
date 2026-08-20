package service

import (
	"context"
	"net"
	"strings"

	"github.com/rikychoi/recon/internal/model"
)

// NetDNSResolver는 Go 표준 net 패키지를 사용하는 DNSResolver 구현이다.
type NetDNSResolver struct {
	resolver *net.Resolver
}

// NewNetDNSResolver는 시스템 기본 리졸버를 사용하는 NetDNSResolver를 생성한다.
func NewNetDNSResolver() *NetDNSResolver {
	return &NetDNSResolver{resolver: net.DefaultResolver}
}

// Resolve는 도메인의 CNAME, A/AAAA, MX, TXT 레코드를 조회한다.
// 개별 레코드 조회 실패는 무시하고 조회 가능한 레코드만 수집한다.
func (d *NetDNSResolver) Resolve(ctx context.Context, domain string) ([]model.DNSRecord, []model.MailServer, error) {
	var records []model.DNSRecord
	var mailServers []model.MailServer

	// CNAME 조회 (자산 식별의 핵심 레코드)
	if cname, err := d.resolver.LookupCNAME(ctx, domain); err == nil {
		if c := strings.TrimSuffix(cname, "."); c != "" && c != domain {
			records = append(records, model.DNSRecord{Type: "CNAME", Name: domain, Value: c})
		}
	}

	// A/AAAA 조회
	if ips, err := d.resolver.LookupIPAddr(ctx, domain); err == nil {
		for _, ip := range ips {
			t := "A"
			if ip.IP.To4() == nil {
				t = "AAAA"
			}
			records = append(records, model.DNSRecord{Type: t, Name: domain, Value: ip.IP.String()})
		}
	}

	// MX(메일 서버) 조회
	if mxs, err := d.resolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			host := strings.TrimSuffix(mx.Host, ".")
			if host == "" {
				continue // RFC 7505 null MX(빈 호스트): 메일을 받지 않는 도메인이므로 제외한다.
			}
			mailServers = append(mailServers, model.MailServer{Host: host, Preference: mx.Pref})
			records = append(records, model.DNSRecord{Type: "MX", Name: domain, Value: host})
		}
	}

	// TXT 조회 (SPF 등 부가 정보)
	if txts, err := d.resolver.LookupTXT(ctx, domain); err == nil {
		for _, txt := range txts {
			records = append(records, model.DNSRecord{Type: "TXT", Name: domain, Value: txt})
		}
	}

	return records, mailServers, nil
}
