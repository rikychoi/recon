package service

import (
	"context"
	"errors"
	"net"
	"strconv"
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

func (r *recordingVuln) Scan(ctx context.Context, targets []model.Port) ([]model.Vulnerability, error) {
	// 대상 포트를 host 또는 host:port 문자열로 기록한다.
	strs := make([]string, 0, len(targets))
	for _, p := range targets {
		s := p.Target
		if p.Number > 0 {
			s = net.JoinHostPort(p.Target, strconv.Itoa(p.Number))
		}
		strs = append(strs, s)
	}
	r.mu.Lock()
	r.calls = append(r.calls, strs)
	r.mu.Unlock()

	if len(strs) == 0 {
		return nil, nil
	}
	return []model.Vulnerability{{
		ID:       "v-" + strs[0],
		Target:   strs[0],
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
	orch.SetAllowPublic(true) // 이 테스트는 공인 IP 가드가 아닌 취합/중복제거 로직을 검증한다
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
	orch.SetAllowPublic(true) // 이 테스트는 공인 IP 가드가 아닌 IP 중복제거 로직을 검증한다
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
	// 열린 포트(80)가 host:port 엔드포인트로 연계되어 IP 단위로 한 번만 전달되어야 한다.
	if len(vuln.calls[0]) != 1 || vuln.calls[0][0] != "1.2.3.4:80" {
		t.Errorf("취약점 점검 대상 = %v, 기대값 [1.2.3.4:80] (열린 포트 연계, IP 단위)", vuln.calls[0])
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
	orch.SetAllowPublic(true) // 이 테스트는 공인 IP 가드가 아닌 병렬 실행을 검증한다
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

// TestIsPublicIP는 공인/사설/로컬 IP 판정을 검증한다.
func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"218.38.137.27", true}, // 예: ISP 하이재킹 응답 IP
		{"1.1.1.1", true},
		{"192.168.0.10", false},        // 사설
		{"10.1.2.3", false},            // 사설
		{"172.16.5.5", false},          // 사설
		{"127.0.0.1", false},           // 루프백
		{"169.254.1.1", false},         // 링크로컬
		{"::1", false},                 // IPv6 루프백
		{"fd00::1", false},             // IPv6 유니크 로컬(사설)
		{"2001:4860:4860::8888", true}, // IPv6 공인
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if got := isPublicIP(ip); got != c.public {
			t.Errorf("isPublicIP(%s) = %v, want %v", c.ip, got, c.public)
		}
	}
}

// TestOrchestratorBlocksPublicIP는 기본 설정에서 공인 IP 자산이 스캔에서 제외되고,
// -allow-public(SetAllowPublic) 시에는 스캔되는지 검증한다.
func TestOrchestratorBlocksPublicIP(t *testing.T) {
	dns := fakeDNS{records: []model.DNSRecord{
		{Type: "A", Name: "app.test.local", Value: "8.8.8.8"}, // 공인 IP(예: 하이재킹)
	}}
	subs := fakeSubs{subs: []model.Subdomain{
		{Name: "vm.test.local", IPs: []string{"192.168.10.20"}}, // 사설 IP
	}}

	// 기본(차단): 공인 IP는 스캔되지 않고 사설 IP만 스캔되어야 한다.
	ports := &recordingPorts{}
	orch := NewOrchestratorWithPortScan(dns, subs, ports, nil)
	if _, err := orch.Run(context.Background(), "app.test.local"); err != nil {
		t.Fatalf("Run 오류: %v", err)
	}
	keys := ports.scannedKeys()
	if _, scanned := keys["8.8.8.8"]; scanned {
		t.Errorf("공인 IP가 차단되지 않고 스캔됨: %v", keys)
	}
	if keys["192.168.10.20"] != 1 {
		t.Errorf("사설 IP는 스캔되어야 함: %v", keys)
	}

	// 허용: -allow-public 지정 시 공인 IP도 스캔되어야 한다.
	ports2 := &recordingPorts{}
	orch2 := NewOrchestratorWithPortScan(dns, subs, ports2, nil)
	orch2.SetAllowPublic(true)
	if _, err := orch2.Run(context.Background(), "app.test.local"); err != nil {
		t.Fatalf("Run 오류: %v", err)
	}
	if ports2.scannedKeys()["8.8.8.8"] != 1 {
		t.Errorf("-allow-public 인데 공인 IP가 스캔되지 않음: %v", ports2.scannedKeys())
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
