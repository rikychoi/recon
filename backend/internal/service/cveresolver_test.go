package service

import (
	"context"
	"strings"
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// TestCPEToVirtualMatch는 nmap CPE(2.2/2.3)를 NVD용 2.3 문자열로 변환하고,
// 버전이 없으면 변환하지 않는지 검증한다.
func TestCPEToVirtualMatch(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"cpe:/a:apache:http_server:2.4.49", "cpe:2.3:a:apache:http_server:2.4.49"},
		{"cpe:2.3:a:apache:struts:2.5.10", "cpe:2.3:a:apache:struts:2.5.10"},
		{"cpe:/a:apache:http_server", ""},   // 버전 없음 → 변환 안 함
		{"cpe:/a:apache:http_server:*", ""}, // 와일드카드 버전 → 변환 안 함
		{"not-a-cpe", ""},
	}
	for _, c := range cases {
		if got := cpeToVirtualMatch(c.in); got != c.want {
			t.Errorf("cpeToVirtualMatch(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestNVDResolver_ResolveCVEs는 NVD 응답에서 CVE ID를 추출·정렬·중복제거하는지 검증한다(가짜 HTTP).
func TestNVDResolver_ResolveCVEs(t *testing.T) {
	doer := &fakeDoer{respond: func(url string) (string, int) {
		if !strings.Contains(url, "virtualMatchString=cpe%3A2.3%3Aa%3Aapache%3Ahttp_server%3A2.4.49") &&
			!strings.Contains(url, "cpe:2.3:a:apache:http_server:2.4.49") {
			t.Errorf("예상 CPE 질의가 아님: %s", url)
		}
		return `{"vulnerabilities":[
			{"cve":{"id":"CVE-2021-42013"}},
			{"cve":{"id":"CVE-2021-41773"}},
			{"cve":{"id":"CVE-2021-41773"}}
		]}`, 200
	}}
	r := NewNVDResolver(doer)

	cves := r.ResolveCVEs(context.Background(), "cpe:/a:apache:http_server:2.4.49")
	if len(cves) != 2 {
		t.Fatalf("CVE 2개(중복 제거)를 기대했으나 %d개: %v", len(cves), cves)
	}
	if cves[0] != "CVE-2021-41773" || cves[1] != "CVE-2021-42013" {
		t.Errorf("정렬/추출 오류: %v", cves)
	}
}

// TestNVDResolver_NoVersion은 버전 없는 CPE는 조회하지 않는지 검증한다(HTTP 호출 없음).
func TestNVDResolver_NoVersion(t *testing.T) {
	called := false
	doer := &fakeDoer{respond: func(string) (string, int) { called = true; return "{}", 200 }}
	r := NewNVDResolver(doer)
	if got := r.ResolveCVEs(context.Background(), "cpe:/a:apache:http_server"); got != nil {
		t.Errorf("버전 없는 CPE는 nil이어야 함: %v", got)
	}
	if called {
		t.Error("버전 없는 CPE에서 HTTP 호출이 발생하면 안 됨")
	}
}

// TestMSFSearch_VersionBased는 CVE 조회기가 있으면 검색이 cve: 기반으로 만들어지는지 검증한다.
func TestMSFSearch_VersionBased(t *testing.T) {
	// 가짜 조회기: CPE → 특정 CVE 목록
	resolver := fakeCVEResolver{cves: []string{"CVE-2021-41773", "CVE-2021-42013"}}

	var searchScript string
	s := NewMSFSearchScanner("")
	s.SetCVEResolver(resolver)
	s.runner = fakeRunner{fn: func(cmds []string) (string, error) {
		script := strings.Join(cmds, "\n")
		if strings.Contains(script, "search ") {
			searchScript = script // 검색 스크립트 캡처
			// 아무 모듈도 반환하지 않아 검증 단계로 넘어가지 않게 함(빈 CSV)
			return "", nil
		}
		return "", nil
	}}

	// CPE(버전)가 있는 포트
	_, _ = s.Scan(context.Background(),
		[]model.Port{{Target: "1.2.3.4", Number: 80, Service: "http", Product: "Apache httpd", CPE: "cpe:/a:apache:http_server:2.4.49"}})

	if !strings.Contains(searchScript, "cve:CVE-2021-41773") || !strings.Contains(searchScript, "cve:CVE-2021-42013") {
		t.Errorf("버전 기반 cve: 검색이 만들어지지 않음: %q", searchScript)
	}
	if strings.Contains(searchScript, "httpd") {
		t.Errorf("CPE가 있으면 제품명(httpd) 검색이 아니라 cve: 검색이어야 함: %q", searchScript)
	}
}

// fakeCVEResolver는 지정한 CVE 목록을 그대로 돌려주는 CVEResolver 가짜 구현이다.
type fakeCVEResolver struct{ cves []string }

func (f fakeCVEResolver) ResolveCVEs(_ context.Context, _ string) []string { return f.cves }
