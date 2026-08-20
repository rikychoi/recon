package service

import (
	"strings"
	"testing"
)

// TestParseNucleiLines는 nuclei JSONL 출력이 취약점 모델로 올바르게 파싱되는지 검증한다.
func TestParseNucleiLines(t *testing.T) {
	input := strings.Join([]string{
		`{"template-id":"tls-version","host":"example.com","info":{"name":"TLS Version","severity":"info","classification":{"cvss-score":0}}}`,
		`{"template-id":"cve-2021-1234","host":"www.example.com","info":{"name":"RCE","severity":"critical","classification":{"cvss-score":9.8}}}`,
		`이것은 JSON이 아닌 진행 로그 줄이다`, // 파싱 불가 줄은 무시되어야 한다.
		`{"template-id":"missing-sev","host":"api.example.com","info":{"name":"No Severity","classification":{"cvss-score":7.5}}}`,
	}, "\n")

	vulns := parseNucleiLines(strings.NewReader(input))
	if len(vulns) != 3 {
		t.Fatalf("취약점 개수 = %d, want 3", len(vulns))
	}
	if vulns[1].ID != "cve-2021-1234" || vulns[1].CVSS != 9.8 || vulns[1].Severity != "critical" {
		t.Errorf("두 번째 취약점 파싱 오류: %+v", vulns[1])
	}
	// severity가 비면 CVSS로부터 추론되어야 한다 (7.5 -> high).
	if vulns[2].Severity != "high" {
		t.Errorf("severity 추론 오류: got %q, want high", vulns[2].Severity)
	}
	if vulns[0].Source != "nuclei" {
		t.Errorf("source = %q, want nuclei", vulns[0].Source)
	}
}
