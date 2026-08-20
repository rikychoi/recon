package service

import (
	"context"
	"time"

	"github.com/rikychoi/recon/internal/model"
)

// Recon은 자산 식별부터 취약점 점검까지의 전체 흐름을 조율하는 인터페이스이다.
type Recon interface {
	// Run은 대상 도메인에 대해 점검을 수행하고 결과를 반환한다.
	Run(ctx context.Context, domain string) (model.ScanResult, error)
}

// Orchestrator는 각 스캐너를 조합하여 점검을 수행하는 Recon 구현이다.
// 각 스캐너는 nil일 수 있으며, nil인 단계는 건너뛴다.
type Orchestrator struct {
	dns  DNSResolver          // DNS/메일 서버 조회
	subs SubdomainScanner     // 서브도메인 열거
	vuln VulnerabilityScanner // 취약점 점검
}

// NewOrchestrator는 주어진 스캐너들로 Orchestrator를 생성한다.
func NewOrchestrator(dns DNSResolver, subs SubdomainScanner, vuln VulnerabilityScanner) *Orchestrator {
	return &Orchestrator{dns: dns, subs: subs, vuln: vuln}
}

// Run은 DNS 조회 → 서브도메인 열거 → 취약점 점검 순으로 실행하여 결과를 집계한다.
func (o *Orchestrator) Run(ctx context.Context, domain string) (model.ScanResult, error) {
	result := model.ScanResult{Target: domain, StartedAt: time.Now()}
	result.Asset.Domain = domain

	// 1) DNS/메일 서버 조회
	if o.dns != nil {
		if records, mails, err := o.dns.Resolve(ctx, domain); err == nil {
			result.Asset.DNSRecords = records
			result.Asset.MailServers = mails
		}
	}

	// 2) 서브도메인 열거
	if o.subs != nil {
		if subs, err := o.subs.Enumerate(ctx, domain); err == nil {
			result.Asset.Subdomains = subs
		}
	}

	// 3) 취약점 점검 (대상: 루트 도메인 + 발견된 서브도메인)
	if o.vuln != nil {
		targets := []string{domain}
		for _, s := range result.Asset.Subdomains {
			targets = append(targets, s.Name)
		}
		if vulns, err := o.vuln.Scan(ctx, targets); err == nil {
			result.Vulnerabilities = vulns
		}
	}

	result.FinishedAt = time.Now()
	return result, nil
}
