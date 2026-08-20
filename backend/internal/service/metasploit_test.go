package service

import (
	"strings"
	"testing"
)

// TestParseMSFOutput은 msfconsole 출력에서 [+] 결과만 취약점으로 추출하는지 검증한다.
func TestParseMSFOutput(t *testing.T) {
	output := strings.Join([]string{
		"[*] Running module against 10.0.0.1",
		"[+] 10.0.0.1:80 - Vulnerable to CVE-2017-5638",
		"[-] 10.0.0.2:80 - Not vulnerable",
		"[+] 10.0.0.3:8080 - Apache Struts detected",
	}, "\n")

	mod := MSFModule{Name: "exploit/multi/http/struts2_content_type_ognl", CVE: "CVE-2017-5638", CVSS: 10.0}
	vulns := parseMSFOutput(strings.NewReader(output), mod)

	if len(vulns) != 2 {
		t.Fatalf("취약점 개수 = %d, want 2 ([+] 줄만)", len(vulns))
	}
	if vulns[0].Target != "10.0.0.1:80" {
		t.Errorf("대상 추출 오류: got %q, want 10.0.0.1:80", vulns[0].Target)
	}
	if vulns[0].ID != "CVE-2017-5638" || vulns[0].CVSS != 10.0 || vulns[0].Severity != "critical" {
		t.Errorf("취약점 메타데이터 오류: %+v", vulns[0])
	}
	if vulns[0].Source != "metasploit" {
		t.Errorf("source = %q, want metasploit", vulns[0].Source)
	}
}

// TestExtractMSFTarget은 다양한 결과 줄 형태에서 대상 추출을 검증한다.
func TestExtractMSFTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.0.1:80 - Vulnerable", "10.0.0.1:80"},
		{"host.example.com:443 detected", "host.example.com:443"},
		{"", ""},
	}
	for _, c := range cases {
		if got := extractMSFTarget(c.in); got != c.want {
			t.Errorf("extractMSFTarget(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestBuildResourceScript는 생성된 msfconsole 리소스 명령이 모듈과 대상을 포함하는지 검증한다.
func TestBuildResourceScript(t *testing.T) {
	got := buildResourceScript("auxiliary/scanner/http/http_version", "1.1.1.1 2.2.2.2")
	for _, want := range []string{"use auxiliary/scanner/http/http_version", "set RHOSTS 1.1.1.1 2.2.2.2", "run", "exit"} {
		if !strings.Contains(got, want) {
			t.Errorf("리소스 스크립트에 %q가 없음: %q", want, got)
		}
	}
}
