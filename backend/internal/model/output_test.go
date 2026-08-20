package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestSeverityFromCVSS는 CVSS 점수 경계값이 올바른 심각도로 매핑되는지 검증한다.
func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.8, "critical"},
		{9.0, "critical"},
		{7.5, "high"},
		{4.0, "medium"},
		{0.1, "low"},
		{0.0, "info"},
	}
	for _, c := range cases {
		if got := SeverityFromCVSS(c.score); got != c.want {
			t.Errorf("SeverityFromCVSS(%.1f) = %q, want %q", c.score, got, c.want)
		}
	}
}

// sampleResult는 테스트에 사용할 예시 점검 결과를 만든다.
func sampleResult() ScanResult {
	start := time.Now()
	return ScanResult{
		Target:     "example.com",
		StartedAt:  start,
		FinishedAt: start.Add(1500 * time.Millisecond),
		Asset: Asset{
			Domain:      "example.com",
			Subdomains:  []Subdomain{{Name: "www.example.com", IPs: []string{"93.184.216.34"}}},
			MailServers: []MailServer{{Host: "mx.example.com", Preference: 10}},
			DNSRecords:  []DNSRecord{{Type: "A", Name: "example.com", Value: "93.184.216.34"}},
		},
		Vulnerabilities: []Vulnerability{{ID: "cve-test", Name: "테스트 취약점", Target: "example.com", CVSS: 7.5, Severity: "high", Source: "nuclei"}},
	}
}

// TestNewFormatter는 형식 이름에 따른 Formatter 선택과 오류 처리를 검증한다.
func TestNewFormatter(t *testing.T) {
	if _, err := NewFormatter("json"); err != nil {
		t.Fatalf("json 형식이 오류를 반환함: %v", err)
	}
	if _, err := NewFormatter(""); err != nil {
		t.Fatalf("빈 형식(기본 text)이 오류를 반환함: %v", err)
	}
	if _, err := NewFormatter("xml"); err == nil {
		t.Fatal("지원하지 않는 형식이 오류를 반환하지 않음")
	}
}

// TestTextFormatter는 텍스트 출력에 주요 섹션과 값이 포함되는지 검증한다.
func TestTextFormatter(t *testing.T) {
	var buf bytes.Buffer
	if err := (TextFormatter{}).Format(&buf, sampleResult()); err != nil {
		t.Fatalf("Format 실패: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"서브도메인", "www.example.com", "메일 서버", "mx.example.com", "취약점", "7.5"} {
		if !strings.Contains(out, want) {
			t.Errorf("텍스트 출력에 %q가 포함되지 않음\n출력:\n%s", want, out)
		}
	}
}

// TestJSONFormatter는 JSON 출력이 다시 파싱 가능하고 대상이 유지되는지 검증한다.
func TestJSONFormatter(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSONFormatter{}).Format(&buf, sampleResult()); err != nil {
		t.Fatalf("Format 실패: %v", err)
	}
	var decoded ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON 재파싱 실패: %v", err)
	}
	if decoded.Target != "example.com" {
		t.Errorf("target = %q, want example.com", decoded.Target)
	}
}
