package service

import (
	"context"

	"github.com/rikychoi/recon/internal/model"
)

// MultiScanner는 여러 VulnerabilityScanner를 순차 실행하고 결과를 하나로 합친다.
// nuclei와 metasploit 등 서로 다른 도구를 한 번에 적용할 때 사용한다.
type MultiScanner struct {
	scanners []VulnerabilityScanner
}

// NewMultiScanner는 주어진 스캐너들을 묶은 MultiScanner를 생성한다.
func NewMultiScanner(scanners ...VulnerabilityScanner) *MultiScanner {
	return &MultiScanner{scanners: scanners}
}

// Scan은 구성된 모든 스캐너를 실행하고 각 결과를 합쳐 반환한다.
// 개별 스캐너의 오류는 전체를 중단시키지 않고 건너뛴다.
func (m *MultiScanner) Scan(ctx context.Context, targets []string) ([]model.Vulnerability, error) {
	var all []model.Vulnerability
	for _, s := range m.scanners {
		if s == nil {
			continue
		}
		vulns, err := s.Scan(ctx, targets)
		if err != nil {
			continue
		}
		all = append(all, vulns...)
	}
	return all, nil
}
