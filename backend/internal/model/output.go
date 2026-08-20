package model

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// Formatter는 점검 결과(ScanResult)를 특정 형식으로 직렬화하는 인터페이스이다.
// 새로운 출력 형식을 추가하려면 이 인터페이스를 구현하면 된다.
type Formatter interface {
	// Format은 결과를 w에 기록한다.
	Format(w io.Writer, r ScanResult) error
}

// NewFormatter는 형식 이름(text/json)에 해당하는 Formatter를 반환한다.
func NewFormatter(name string) (Formatter, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "text":
		return TextFormatter{}, nil
	case "json":
		return JSONFormatter{}, nil
	default:
		return nil, fmt.Errorf("지원하지 않는 출력 형식: %s", name)
	}
}

// JSONFormatter는 결과를 들여쓰기된 JSON으로 출력한다.
type JSONFormatter struct{}

// Format은 ScanResult를 JSON으로 직렬화하여 w에 기록한다.
func (JSONFormatter) Format(w io.Writer, r ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// TextFormatter는 결과를 사람이 읽기 쉬운 텍스트 형태로 출력한다.
type TextFormatter struct{}

// Format은 ScanResult를 섹션별 텍스트로 w에 기록한다.
func (TextFormatter) Format(w io.Writer, r ScanResult) error {
	fmt.Fprintf(w, "== 점검 결과: %s ==\n", r.Target)
	fmt.Fprintf(w, "소요 시간: %s\n\n", r.Duration().Round(time.Millisecond))

	// 서브도메인 (이름순 정렬)
	subs := append([]Subdomain(nil), r.Asset.Subdomains...)
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
	fmt.Fprintf(w, "[서브도메인] (%d개)\n", len(subs))
	for _, s := range subs {
		fmt.Fprintf(w, "  - %s -> %s\n", s.Name, strings.Join(s.IPs, ", "))
	}
	fmt.Fprintln(w)

	// 메일 서버
	fmt.Fprintf(w, "[메일 서버] (%d개)\n", len(r.Asset.MailServers))
	for _, m := range r.Asset.MailServers {
		fmt.Fprintf(w, "  - %s (우선순위 %d)\n", m.Host, m.Preference)
	}
	fmt.Fprintln(w)

	// DNS 레코드
	fmt.Fprintf(w, "[DNS 레코드] (%d개)\n", len(r.Asset.DNSRecords))
	for _, d := range r.Asset.DNSRecords {
		fmt.Fprintf(w, "  - %-6s %s\n", d.Type, d.Value)
	}
	fmt.Fprintln(w)

	// 취약점 (CVSS 높은 순 정렬)
	vulns := append([]Vulnerability(nil), r.Vulnerabilities...)
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].CVSS > vulns[j].CVSS })
	fmt.Fprintf(w, "[취약점] (%d개)\n", len(vulns))
	for _, v := range vulns {
		fmt.Fprintf(w, "  - [%.1f %s] %s (%s) @ %s\n", v.CVSS, v.Severity, v.Name, v.ID, v.Target)
	}
	return nil
}
