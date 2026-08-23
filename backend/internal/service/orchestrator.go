package service

import (
	"context"
	"io"
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
	dns      DNSResolver          // DNS/메일 서버 조회
	subs     SubdomainScanner     // 서브도메인 열거
	port     PortScanner          // 포트 스캔
	vuln     VulnerabilityScanner // 취약점 점검
	progress io.Writer            // 진행 상황 출력 대상(nil이면 미출력)
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(보통 os.Stderr).
// nil을 넘기면 진행 로그를 출력하지 않는다.
func (o *Orchestrator) SetProgress(w io.Writer) {
	o.progress = w
}

// NewOrchestrator는 주어진 스캐너들로 Orchestrator를 생성한다.
func NewOrchestrator(dns DNSResolver, subs SubdomainScanner, vuln VulnerabilityScanner) *Orchestrator {
	return NewOrchestratorWithPortScan(dns, subs, nil, vuln)
}

// NewOrchestratorWithPortScan은 포트 스캔 단계가 포함된 Orchestrator를 생성한다.
func NewOrchestratorWithPortScan(dns DNSResolver, subs SubdomainScanner, port PortScanner, vuln VulnerabilityScanner) *Orchestrator {
	return &Orchestrator{dns: dns, subs: subs, port: port, vuln: vuln}
}

// Run은 DNS 조회 → 서브도메인 열거 → 포트 스캔 → 취약점 점검 순으로 실행하여 결과를 집계한다.
func (o *Orchestrator) Run(ctx context.Context, domain string) (model.ScanResult, error) {
	result := model.ScanResult{Target: domain, StartedAt: time.Now()}
	result.Asset.Domain = domain

	progressf(o.progress, "[*] %s 점검 시작\n", domain)

	// 1) DNS/메일 서버 조회
	if o.dns != nil {
		progressf(o.progress, "[*] DNS/메일 서버 조회 중...\n")
		if records, mails, err := o.dns.Resolve(ctx, domain); err == nil {
			result.Asset.DNSRecords = records
			result.Asset.MailServers = mails
			progressf(o.progress, "[+] DNS 레코드 %d개, 메일 서버 %d개\n", len(records), len(mails))
		} else {
			progressf(o.progress, "[!] DNS 조회 실패: %v\n", err)
		}
	}

	// 2) 서브도메인 열거
	if o.subs != nil {
		progressf(o.progress, "[*] 서브도메인 열거 중...\n")
		if subs, err := o.subs.Enumerate(ctx, domain); err == nil {
			result.Asset.Subdomains = subs
			progressf(o.progress, "[+] 서브도메인 %d개 발견\n", len(subs))
		} else {
			progressf(o.progress, "[!] 서브도메인 열거 실패: %v\n", err)
		}
	}

	// 3) 포트 스캔 (대상: 루트 도메인 + 발견된 서브도메인)
	if o.port != nil {
		targets := []string{domain}
		for _, s := range result.Asset.Subdomains {
			targets = append(targets, s.Name)
		}
		progressf(o.progress, "[*] 포트 스캔 시작 (대상 %d개)...\n", len(targets))
		if ports, err := o.port.Scan(ctx, targets); err == nil {
			result.Asset.Ports = ports
			progressf(o.progress, "[+] 열린 포트 %d개\n", len(ports))
		} else {
			progressf(o.progress, "[!] 포트 스캔 실패: %v\n", err)
		}
	}

	// 4) 취약점 점검 (대상: 루트 도메인 + 발견된 서브도메인)
	if o.vuln != nil {
		targets := []string{domain}
		for _, s := range result.Asset.Subdomains {
			targets = append(targets, s.Name)
		}
		progressf(o.progress, "[*] 취약점 점검 시작 (대상 %d개)...\n", len(targets))
		if vulns, err := o.vuln.Scan(ctx, targets); err == nil {
			result.Vulnerabilities = vulns
			progressf(o.progress, "[+] 취약점 %d건 발견\n", len(vulns))
		} else {
			progressf(o.progress, "[!] 취약점 점검 실패: %v\n", err)
		}
	}

	result.FinishedAt = time.Now()
	progressf(o.progress, "[*] 점검 완료 (소요 %s)\n", result.FinishedAt.Sub(result.StartedAt).Round(time.Millisecond))
	return result, nil
}
