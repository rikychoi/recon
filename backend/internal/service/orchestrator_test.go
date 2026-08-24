package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

// recordingPorts는 호출된 대상 목록을 스레드 세이프하게 기록하는 PortScanner 페이크이다.
// 자산별로 병렬 호출되므로 뮤텍스로 보호한다. 각 대상에 대해 80 포트가 열린 것으로 반환한다.
type recordingPorts struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recordingPorts) Scan(ctx context.Context, targets []string) ([]model.Port, error) {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), targets...))
	r.mu.Unlock()

	var ports []model.Port
	for _, t := range targets {
		ports = append(ports, model.Port{Target: t, Number: 80, Protocol: "tcp", State: "open", Service: "http"})
	}
	return ports, nil
}

// scannedKeys는 포트 스캔이 호출된 서로 다른 대상(키)의 집합을 반환한다.
func (r *recordingPorts) scannedKeys() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	keys := map[string]int{}
	for _, call := range r.calls {
		for _, t := range call {
			keys[t]++
		}
	}
	return keys
}

// recordingVuln은 호출된 대상 목록을 스레드 세이프하게 기록하는 VulnerabilityScanner 페이크이다.
type recordingVuln struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recordingVuln) Scan(ctx context.Context, targets []string) ([]model.Vulnerability, error) {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string(nil), targets...))
	r.mu.Unlock()

	if len(targets) == 0 {
		return nil, nil
	}
	return []model.Vulnerability{{
		ID:       "v-" + targets[0],
		Target:   targets[0],
		CVSS:     9.1,
		Severity: "critical",
		Source:   "fake",
	}}, nil
}

// TestOrchestratorRun은 자산 식별 후 자산별 (포트스캔→취약점점검) 파이프라인이
// 병렬 실행되고 결과가 하나의 보고서로 취합되는지 검증한다.
func TestOrchestratorRun(t *testing.T) {
	dns := fakeDNS{
		records: []model.DNSRecord{
			{Type: "A", Name: "example.com", Value: "1.2.3.4"},
			{Type: "MX", Name: "example.com", Value: "mx.example.com"},
		},
		mails: []model.MailServer{{Host: "mx.example.com", Preference: 10}},
	}
	subs := fakeSubs{subs: []model.Subdomain{
		{Name: "api.example.com", IPs: []string{"5.6.7.8"}},
	}}
	ports := &recordingPorts{}
	vuln := &recordingVuln{}

	orch := NewOrchestratorWithPortScan(dns, subs, ports, vuln)
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

	// 포트 스캔은 IP 기준으로 1.2.3.4, 5.6.7.8 두 자산에 대해 각각 1회씩만 수행되어야 한다.
	keys := ports.scannedKeys()
	if len(keys) != 2 || keys["1.2.3.4"] != 1 || keys["5.6.7.8"] != 1 {
		t.Errorf("포트 스캔 대상/중복 오류: %v", keys)
	}

	// 취합된 포트는 2개(각 IP당 80), 정렬되어 있어야 한다.
	if len(result.Asset.Ports) != 2 {
		t.Fatalf("취합 포트 수 = %d, 기대값 2 (%+v)", len(result.Asset.Ports), result.Asset.Ports)
	}
	if result.Asset.Ports[0].Target != "1.2.3.4" || result.Asset.Ports[1].Target != "5.6.7.8" {
		t.Errorf("포트 정렬 오류: %+v", result.Asset.Ports)
	}

	// 취약점도 자산별로 취합되어 2건이어야 한다.
	if len(result.Vulnerabilities) != 2 {
		t.Errorf("취약점 취합 오류: %+v", result.Vulnerabilities)
	}

	if result.FinishedAt.Before(result.StartedAt) {
		t.Error("FinishedAt이 StartedAt보다 이전임")
	}
}

// TestOrchestratorDedupsSharedIP는 여러 도메인이 같은 IP를 가리킬 때
// 포트 스캔과 취약점 점검이 모두 그 IP에 대해 IP 단위로 한 번씩만 실행되는지 검증한다.
func TestOrchestratorDedupsSharedIP(t *testing.T) {
	dns := fakeDNS{records: []model.DNSRecord{
		{Type: "A", Name: "example.com", Value: "1.2.3.4"},
	}}
	// www 는 루트와 같은 IP(1.2.3.4)를 공유한다 → 스캔 중복 금지 대상.
	subs := fakeSubs{subs: []model.Subdomain{
		{Name: "www.example.com", IPs: []string{"1.2.3.4"}},
	}}
	ports := &recordingPorts{}
	vuln := &recordingVuln{}

	orch := NewOrchestratorWithPortScan(dns, subs, ports, vuln)
	_, err := orch.Run(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Run 오류: %v", err)
	}

	// 공유 IP는 단 하나의 자산으로 묶여 포트 스캔이 정확히 1회여야 한다.
	keys := ports.scannedKeys()
	if len(keys) != 1 || keys["1.2.3.4"] != 1 {
		t.Fatalf("공유 IP 포트 스캔 중복 발생: %v", keys)
	}

	// 취약점 점검도 IP 단위로 정확히 1회(대상 [1.2.3.4])여야 한다. 도메인별 중복 금지.
	vuln.mu.Lock()
	defer vuln.mu.Unlock()
	if len(vuln.calls) != 1 {
		t.Fatalf("취약점 점검 호출 수 = %d, 기대값 1", len(vuln.calls))
	}
	if len(vuln.calls[0]) != 1 || vuln.calls[0][0] != "1.2.3.4" {
		t.Errorf("취약점 점검 대상 = %v, 기대값 [1.2.3.4] (IP 단위)", vuln.calls[0])
	}
}

// TestOrchestratorRunsAssetsInParallel은 자산별 파이프라인이 실제로 고루틴 병렬 실행되는지
// 동시 실행 카운터로 검증한다(동시에 2개 이상 활성 상태가 관측되어야 한다).
func TestOrchestratorRunsAssetsInParallel(t *testing.T) {
	dns := fakeDNS{records: []model.DNSRecord{
		{Type: "A", Name: "example.com", Value: "1.1.1.1"},
	}}
	subs := fakeSubs{subs: []model.Subdomain{
		{Name: "a.example.com", IPs: []string{"2.2.2.2"}},
		{Name: "b.example.com", IPs: []string{"3.3.3.3"}},
		{Name: "c.example.com", IPs: []string{"4.4.4.4"}},
	}}

	cp := &concurrentPorts{}
	orch := NewOrchestratorWithPortScan(dns, subs, cp, nil)
	if _, err := orch.Run(context.Background(), "example.com"); err != nil {
		t.Fatalf("Run 오류: %v", err)
	}

	if got := atomic.LoadInt32(&cp.maxActive); got < 2 {
		t.Errorf("최대 동시 실행 자산 수 = %d, 병렬 실행이 관측되지 않음(>=2 기대)", got)
	}
}

// concurrentPorts는 동시에 활성화된 스캔 수의 최댓값을 기록하는 PortScanner 페이크이다.
type concurrentPorts struct {
	active    int32
	maxActive int32
}

func (c *concurrentPorts) Scan(ctx context.Context, targets []string) ([]model.Port, error) {
	n := atomic.AddInt32(&c.active, 1)
	for {
		old := atomic.LoadInt32(&c.maxActive)
		if n <= old || atomic.CompareAndSwapInt32(&c.maxActive, old, n) {
			break
		}
	}
	time.Sleep(30 * time.Millisecond) // 동시 실행 창을 확보하기 위한 짧은 지연
	atomic.AddInt32(&c.active, -1)
	return nil, nil
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
