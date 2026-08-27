package service

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// TestSearchTerm은 제품/CPE/서비스로부터 검색어를 도출하는 규칙을 검증한다.
func TestSearchTerm(t *testing.T) {
	cases := []struct {
		name string
		port model.Port
		want string
	}{
		{"제품 마지막 토큰", model.Port{Product: "Apache Struts", Service: "http"}, "struts"},
		{"httpd는 마지막 토큰", model.Port{Product: "Apache httpd", Service: "http"}, "httpd"},
		{"CPE 폴백", model.Port{CPE: "cpe:/a:apache:struts:2.5.10", Service: "http"}, "struts"},
		{"서비스 폴백", model.Port{Service: "ssh"}, "ssh"},
		{"unknown 서비스는 제외", model.Port{Service: "unknown"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := searchTerm(c.port); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// TestParseSearchCSV는 search -o CSV에서 모듈 행만 추출하고 자식 행을 제외하는지 검증한다.
func TestParseSearchCSV(t *testing.T) {
	csv := `#,Full Name,Disclosure Date,Rank,Check,Name
"0","exploit/multi/http/struts2_content_type_ognl","2017-03-07","excellent","Yes","Apache Struts OGNL Injection"
"1"," \_ target: Automatic",".",".",".","."
"2","exploit/multi/http/struts_dev_mode","2012-01-06","excellent","Yes","Struts Dev Mode"`

	mods := parseSearchCSV([]byte(csv))
	if len(mods) != 2 {
		t.Fatalf("모듈 2개를 기대했으나 %d개: %+v", len(mods), mods)
	}
	if mods[0].fullName != "exploit/multi/http/struts2_content_type_ognl" || mods[0].rank != "excellent" {
		t.Errorf("첫 모듈 파싱 오류: %+v", mods[0])
	}
	if mods[1].fullName != "exploit/multi/http/struts_dev_mode" {
		t.Errorf("자식 행 제외 실패 또는 두 번째 모듈 오류: %+v", mods[1])
	}
}

// TestParseCheckOutput은 마커로 분할된 검증 출력에서 취약 여부와 CVE를 귀속시키는지 검증한다.
func TestParseCheckOutput(t *testing.T) {
	// ANSI 색상 코드가 섞여 있어도 파싱되어야 한다.
	out := "\x1b[1m===RECON0===\x1b[0m\n" +
		"  References:\n  https://.../CVE-2017-5638\n" +
		"[+] 1.2.3.4:8080 - The target is vulnerable.\n" +
		"===RECON1===\n" +
		"[*] 1.2.3.4:80 - The target appears to be vulnerable.\n" +
		"===RECON2===\n" +
		"[-] 1.2.3.4:22 - The target is not exploitable.\n"

	res := parseCheckOutput([]byte(out))

	if !res[0].vulnerable || res[0].cve != "CVE-2017-5638" {
		t.Errorf("0번: 취약+CVE 기대, got %+v", res[0])
	}
	if res[1].vulnerable || !res[1].appears {
		t.Errorf("1번: appears 기대, got %+v", res[1])
	}
	if res[2].vulnerable || res[2].appears {
		t.Errorf("2번: 취약 아님 기대, got %+v", res[2])
	}
}

// TestMSFSearchScanner_Scan은 가짜 msfconsole 실행기로 발굴→검증→기록의 전체 흐름을 검증한다.
func TestMSFSearchScanner_Scan(t *testing.T) {
	s := NewMSFSearchScanner("")
	s.runner = fakeRunner{fn: func(script string) (string, error) {
		// 발굴 단계: search 스크립트면 -o 경로에 CSV를 쓴다.
		if strings.Contains(script, "search ") {
			csv := `#,Full Name,Disclosure Date,Rank,Check,Name
"0","exploit/multi/http/struts2_content_type_ognl","2017-03-07","excellent","Yes","Apache Struts OGNL Injection"`
			for _, path := range extractOutPaths(script) {
				os.WriteFile(path, []byte(csv), 0o600)
			}
			return "done", nil
		}
		// 검증 단계: 첫 작업을 취약으로 판정하는 출력을 돌려준다.
		return "===RECON0===\n  https://x/CVE-2017-5638\n" +
			"[+] 1.2.3.4:8080 - The target is vulnerable.\n", nil
	}}

	targets := []model.Port{{Target: "1.2.3.4", Number: 8080, Service: "http", Product: "Apache Struts"}}
	vulns, err := s.Scan(context.Background(), targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Fatalf("취약점 1건을 기대했으나 %d건: %+v", len(vulns), vulns)
	}
	v := vulns[0]
	if v.ID != "CVE-2017-5638" || v.Source != "metasploit" || v.Severity != "high" {
		t.Errorf("취약점 필드 오류: %+v", v)
	}
	if v.Target != "1.2.3.4:8080" {
		t.Errorf("대상 표기 오류: %q", v.Target)
	}
}

// extractOutPaths는 테스트에서 search 스크립트의 -o <path> 인자들을 뽑아낸다.
func extractOutPaths(script string) []string {
	re := regexp.MustCompile(`-o ([^\s;]+)`)
	var paths []string
	for _, m := range re.FindAllStringSubmatch(script, -1) {
		paths = append(paths, m[1])
	}
	return paths
}
