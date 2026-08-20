package service

import (
	"context"
	"errors"
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// --- 테스트용 페이크 스캐너 구현 ---

// fakeDNS는 고정된 DNS/메일 서버 결과를 반환하는 DNSResolver 페이크이다.
type fakeDNS struct {
	records []model.DNSRecord
	mails   []model.MailServer
	err     error
}

func (f fakeDNS) Resolve(ctx context.Context, domain string) ([]model.DNSRecord, []model.MailServer, error) {
	return f.records, f.mails, f.err
}

// fakeSubs는 고정된 서브도메인 목록을 반환하는 SubdomainScanner 페이크이다.
type fakeSubs struct {
	subs []model.Subdomain
	err  error
}

func (f fakeSubs) Enumerate(ctx context.Context, domain string) ([]model.Subdomain, error) {
	return f.subs, f.err
}

// fakeVuln은 전달받은 대상 목록을 기록하고 고정 취약점을 반환하는 VulnerabilityScanner 페이크이다.
type fakeVuln struct {
	gotTargets []string
	vulns      []model.Vulnerability
}

func (f *fakeVuln) Scan(ctx context.Context, targets []string) ([]model.Vulnerability, error) {
	f.gotTargets = targets
	return f.vulns, nil
}

// TestOrchestratorRun은 자산 식별 → 취약점 점검 흐름이 순서대로 이어지고
// 취약점 스캐너에 루트 도메인 + 서브도메인이 전달되는지 검증한다.
func TestOrchestratorRun(t *testing.T) {
	dns := fakeDNS{
		records: []model.DNSRecord{{Type: "MX", Name: "example.com", Value: "mx.example.com"}},
		mails:   []model.MailServer{{Host: "mx.example.com", Preference: 10}},
	}
	subs := fakeSubs{subs: []model.Subdomain{{Name: "www.example.com", IPs: []string{"1.2.3.4"}}}}
	vuln := &fakeVuln{vulns: []model.Vulnerability{{ID: "cve-x", CVSS: 9.1, Severity: "critical"}}}

	orch := NewOrchestrator(dns, subs, vuln)
	result, err := orch.Run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run 오류: %v", err)
	}

	if result.Target != "example.com" || result.Asset.Domain != "example.com" {
		t.Errorf("대상 도메인 누락: %+v", result.Asset)
	}
	if len(result.Asset.Subdomains) != 1 || len(result.Asset.MailServers) != 1 {
		t.Errorf("자산 식별 결과 집계 오류: %+v", result.Asset)
	}
	if len(result.Vulnerabilities) != 1 {
		t.Errorf("취약점 집계 오류: %+v", result.Vulnerabilities)
	}

	// 취약점 점검 대상은 루트 도메인 + 발견된 서브도메인이어야 한다.
	wantTargets := map[string]bool{"example.com": true, "www.example.com": true}
	if len(vuln.gotTargets) != len(wantTargets) {
		t.Fatalf("취약점 점검 대상 = %v, want %v", vuln.gotTargets, wantTargets)
	}
	for _, tg := range vuln.gotTargets {
		if !wantTargets[tg] {
			t.Errorf("예상치 못한 점검 대상: %q", tg)
		}
	}

	// 시작/종료 시각이 기록되어야 한다.
	if result.FinishedAt.Before(result.StartedAt) {
		t.Error("FinishedAt이 StartedAt보다 이전임")
	}
}

// TestOrchestratorSkipsNilScanners는 nil 스캐너 단계를 건너뛰고도 정상 동작하는지 검증한다.
func TestOrchestratorSkipsNilScanners(t *testing.T) {
	orch := NewOrchestrator(nil, nil, nil)
	result, err := orch.Run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run 오류: %v", err)
	}
	if len(result.Asset.Subdomains) != 0 || len(result.Vulnerabilities) != 0 {
		t.Errorf("nil 스캐너인데 결과가 채워짐: %+v", result)
	}
}

// TestOrchestratorToleratesDNSError는 DNS 조회 오류가 전체 실행을 막지 않는지 검증한다.
func TestOrchestratorToleratesDNSError(t *testing.T) {
	orch := NewOrchestrator(
		fakeDNS{err: errors.New("dns 실패")},
		fakeSubs{subs: []model.Subdomain{{Name: "www.example.com"}}},
		nil,
	)
	result, err := orch.Run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run 오류: %v", err)
	}
	if len(result.Asset.Subdomains) != 1 {
		t.Errorf("DNS 오류 후 서브도메인 단계가 진행되지 않음: %+v", result.Asset)
	}
}
