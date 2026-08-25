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

	// 포트
	fmt.Fprintf(w, "[포트] (%d개)\n", len(r.Asset.Ports))
	for _, p := range r.Asset.Ports {
		fmt.Fprintf(w, "  - %s/%s %d %s %s\n", p.Target, p.Protocol, p.Number, p.State, p.Service)
	}
	fmt.Fprintln(w)

	// 취약점 (위험 우선순위 정렬: 실제 악용(KEV) → CVSS → 악용 확률(EPSS))
	vulns := append([]Vulnerability(nil), r.Vulnerabilities...)
	sort.Slice(vulns, func(i, j int) bool {
		if vulns[i].KEV != vulns[j].KEV {
			return vulns[i].KEV // KEV(실제 악용 중)를 최상단으로.
		}
		if vulns[i].CVSS != vulns[j].CVSS {
			return vulns[i].CVSS > vulns[j].CVSS
		}
		return vulns[i].EPSS > vulns[j].EPSS
	})
	fmt.Fprintf(w, "[취약점] (%d개)\n", len(vulns))
	for _, v := range vulns {
		fmt.Fprintf(w, "  - [%.1f %s] %s (%s) @ %s\n", v.CVSS, v.Severity, v.Name, v.ID, v.Target)
		// 보강 정보(CVE/EPSS/KEV)가 있으면 부가 라인으로 함께 표시한다.
		var tags []string
		if len(v.CVEs) > 0 {
			tags = append(tags, strings.Join(v.CVEs, ","))
		}
		if v.EPSS > 0 {
			tags = append(tags, fmt.Sprintf("EPSS %.1f%%", v.EPSS*100))
		}
		if v.KEV {
			tags = append(tags, "KEV(실제 악용 중)")
		}
		if len(tags) > 0 {
			fmt.Fprintf(w, "      %s\n", strings.Join(tags, " | "))
		}
	}
	return nil
}
