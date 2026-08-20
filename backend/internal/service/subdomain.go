package service

import (
	"context"
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

// BruteSubdomainScanner는 워드리스트 기반 DNS 조회로 서브도메인을 열거한다.
type BruteSubdomainScanner struct {
	resolver    *net.Resolver // DNS 조회에 사용할 리졸버
	wordlist    []string      // 서브도메인 후보 목록
	concurrency int           // 동시 조회 고루틴 수
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

// Enumerate는 워드리스트의 각 후보를 도메인 앞에 붙여 DNS 조회로 존재 여부를 확인한다.
// 조회에 성공(레코드 존재)한 후보만 결과에 포함한다.
func (s *BruteSubdomainScanner) Enumerate(ctx context.Context, domain string) ([]model.Subdomain, error) {
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
