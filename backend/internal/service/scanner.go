// Package service는 자산 식별과 취약점 점검 기능을 제공한다.
// 각 기능은 인터페이스로 정의하여 구현 교체와 테스트를 용이하게 한다.
package service

import (
	"context"

	"github.com/rikychoi/recon/internal/model"
)

// DNSResolver는 도메인의 DNS 레코드(메일 서버, CNAME 등)를 조회한다.
type DNSResolver interface {
	// Resolve는 도메인의 A/CNAME/MX/TXT 등 레코드와 메일 서버 목록을 반환한다.
	Resolve(ctx context.Context, domain string) ([]model.DNSRecord, []model.MailServer, error)
}

// SubdomainScanner는 대상 도메인의 서브도메인을 열거한다.
type SubdomainScanner interface {
	// Enumerate는 대상 도메인의 서브도메인 목록을 반환한다.
	Enumerate(ctx context.Context, domain string) ([]model.Subdomain, error)
}

// PortScanner는 대상 목록을 포트 스캔하여 열린 포트를 식별한다.
type PortScanner interface {
	// Scan은 대상 목록에 대해 포트 스캔을 수행하고 결과를 반환한다.
	Scan(ctx context.Context, targets []string) ([]model.Port, error)
}

// VulnerabilityScanner는 열린 포트(서비스 포함) 목록에 대해 취약점을 점검한다.
type VulnerabilityScanner interface {
	// Scan은 열린 포트 목록(대상·포트·서비스)에 대해 취약점을 점검하여 결과를 반환한다.
	// 포트 정보가 없는 대상은 Number 0인 Port로 전달하며, 스캐너는 기본 포트로 점검한다.
	// 서비스 정보를 통해 각 점검 도구가 적합한 서비스(예: http)에만 실행할 수 있다.
	Scan(ctx context.Context, targets []model.Port) ([]model.Vulnerability, error)
}

// Enricher는 발견된 취약점에 외부 위협 인텔리전스(NVD/EPSS/KEV)를 보강한다.
// 네트워크 조회 실패는 치명적이지 않으므로 최선노력(best-effort)으로 동작하며,
// 오류를 반환하지 않고 보강 가능한 정보만 채워 원본 순서 그대로 돌려준다.
type Enricher interface {
	// Enrich는 각 취약점의 연관 CVE를 식별하고 EPSS(악용 확률)·KEV(실제 악용) 정보와
	// (CVSS가 비어 있으면) NVD의 권위 있는 CVSS 점수를 채워 반환한다.
	Enrich(ctx context.Context, vulns []model.Vulnerability) []model.Vulnerability
}

// TakeoverDetector는 댕글링 CNAME(가리키는 대상이 사라진 CNAME)을 근거로
// 서브도메인 탈취 가능성을 탐지한다. 탐지 결과는 취약점(Vulnerability)으로 표현한다.
type TakeoverDetector interface {
	// Detect는 루트 도메인과 서브도메인들의 CNAME을 검사하여 탈취 가능 후보를 취약점으로 반환한다.
	Detect(ctx context.Context, domain string, subs []model.Subdomain) []model.Vulnerability
}
