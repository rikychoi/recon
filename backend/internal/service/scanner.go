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
