package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"sync"

	"github.com/rikychoi/recon/internal/model"
)

// DefaultSubdomainWordlist는 브루트포스에 사용할 기본 서브도메인 후보 목록이다.
var DefaultSubdomainWordlist = []string{
	"www", "mail", "smtp", "pop", "imap", "webmail", "ns1", "ns2", "dns",
	"api", "dev", "staging", "test", "admin", "portal", "vpn", "remote",
	"git", "gitlab", "jenkins", "ci", "ftp", "cdn", "static", "assets",
	"img", "blog", "shop", "store", "app", "mobile", "m", "secure",
	"login", "auth", "sso", "dashboard", "grafana", "prometheus", "kibana",
	"db", "database", "backup", "internal", "beta", "demo", "docs", "status",
}

// wildcardProbes는 와일드카드/DNS 하이재킹 판정을 위해 조회할 무작위 서브도메인 개수이다.
const wildcardProbes = 3

// hostLookuper는 호스트명을 IP로 해석하는 최소 인터페이스이다.
// 실제로는 *net.Resolver를, 테스트에는 가짜 구현을 주입한다.
type hostLookuper interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// BruteSubdomainScanner는 워드리스트 기반 DNS 조회로 서브도메인을 열거한다.
// 조회 전에 와일드카드/하이재킹(존재하지 않는 이름이 특정 IP로 응답되는 것)을 탐지하여,
// 그 IP로만 해석되는 가짜 후보를 결과에서 제외한다.
type BruteSubdomainScanner struct {
	resolver    hostLookuper // DNS 조회에 사용할 리졸버(주입 가능)
	wordlist    []string     // 서브도메인 후보 목록
	concurrency int          // 동시 조회 고루틴 수
	progress    io.Writer    // 진행 상황 출력 대상(nil이면 미출력)
}

// NewBruteSubdomainScanner는 워드리스트 기반 서브도메인 스캐너를 생성한다.
// wordlist가 비어 있으면 DefaultSubdomainWordlist를, concurrency가 0 이하이면 20을 사용한다.
func NewBruteSubdomainScanner(wordlist []string, concurrency int) *BruteSubdomainScanner {
	if len(wordlist) == 0 {
		wordlist = DefaultSubdomainWordlist
	}
	if concurrency <= 0 {
		concurrency = 20
	}
	return &BruteSubdomainScanner{
		resolver:    net.DefaultResolver,
		wordlist:    wordlist,
		concurrency: concurrency,
	}
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (s *BruteSubdomainScanner) SetProgress(w io.Writer) { s.progress = w }

// Enumerate는 워드리스트의 각 후보를 도메인 앞에 붙여 DNS 조회로 존재 여부를 확인한다.
// 와일드카드/하이재킹이 감지되면 그 IP로만 해석되는 후보는 가짜로 보고 제외한다.
func (s *BruteSubdomainScanner) Enumerate(ctx context.Context, domain string) ([]model.Subdomain, error) {
	// 0) 와일드카드/하이재킹 탐지: 존재할 리 없는 무작위 이름이 해석되면 그 IP를 기록한다.
	wildcard := s.detectWildcardIPs(ctx, domain)
	if len(wildcard) > 0 {
		progressf(s.progress, "    - 와일드카드 DNS(하이재킹) 감지: %d개 IP — 해당 IP로만 해석되는 후보는 제외합니다.\n", len(wildcard))
	}

	jobs := make(chan string)
	results := make(chan model.Subdomain)
	var wg sync.WaitGroup

	// 워커 고루틴: 후보 FQDN을 DNS 조회한다.
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				fqdn := word + "." + domain
				ips, err := s.resolver.LookupHost(ctx, fqdn)
				if err != nil || len(ips) == 0 {
					continue
				}
				// 와일드카드 IP로만 해석되면 실제 존재하는 서브도메인이 아니므로 건너뛴다.
				if isAllWildcard(ips, wildcard) {
					continue
				}
				results <- model.Subdomain{Name: fqdn, IPs: ips}
			}
		}()
	}

	// 생산자 고루틴: 후보를 워커에 분배한다. 컨텍스트 취소 시 즉시 중단한다.
	go func() {
		defer close(jobs)
		for _, w := range s.wordlist {
			select {
			case <-ctx.Done():
				return
			case jobs <- w:
			}
		}
	}()

	// 모든 워커 종료 후 결과 채널을 닫는다.
	go func() {
		wg.Wait()
		close(results)
	}()

	var found []model.Subdomain
	for r := range results {
		found = append(found, r)
	}
	return found, nil
}

// detectWildcardIPs는 무작위 서브도메인을 여러 번 조회해, 해석되는 경우 그 IP들을 집합으로 모은다.
// 정상 DNS라면 존재하지 않는 이름은 NXDOMAIN이라 빈 집합을 반환한다.
// ISP의 NXDOMAIN 하이재킹이나 와일드카드(*) 레코드가 있으면 그 응답 IP가 담긴다.
func (s *BruteSubdomainScanner) detectWildcardIPs(ctx context.Context, domain string) map[string]bool {
	wildcard := make(map[string]bool)
	for i := 0; i < wildcardProbes; i++ {
		label := randomLabel()
		ips, err := s.resolver.LookupHost(ctx, label+"."+domain)
		if err != nil || len(ips) == 0 {
			continue
		}
		for _, ip := range ips {
			wildcard[ip] = true
		}
	}
	return wildcard
}

// isAllWildcard는 해석된 IP가 모두 와일드카드 IP 집합에 속하는지(=가짜 후보인지) 판정한다.
// 와일드카드 집합이 비어 있으면 항상 false(정상 판정)이다.
func isAllWildcard(ips []string, wildcard map[string]bool) bool {
	if len(wildcard) == 0 || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !wildcard[ip] {
			return false // 와일드카드가 아닌 IP가 하나라도 있으면 실제 서브도메인으로 본다.
		}
	}
	return true
}

// randomLabel은 존재할 가능성이 없는 무작위 DNS 라벨을 생성한다(와일드카드 탐지용).
func randomLabel() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "recon-wildcard-probe-0"
	}
	return "recon-" + hex.EncodeToString(b)
}
