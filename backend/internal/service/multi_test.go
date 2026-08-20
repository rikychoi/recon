package service

import (
	"context"
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// stubVuln은 고정 취약점을 반환하는 VulnerabilityScanner 스텁이다.
type stubVuln struct {
	vulns []model.Vulnerability
	err   error
}

func (s stubVuln) Scan(ctx context.Context, targets []string) ([]model.Vulnerability, error) {
	return s.vulns, s.err
}

// TestMultiScannerMerges는 여러 스캐너의 결과가 하나로 합쳐지는지 검증한다.
func TestMultiScannerMerges(t *testing.T) {
	a := stubVuln{vulns: []model.Vulnerability{{ID: "a", Source: "nuclei"}}}
	b := stubVuln{vulns: []model.Vulnerability{{ID: "b", Source: "metasploit"}, {ID: "c", Source: "metasploit"}}}

	multi := NewMultiScanner(a, nil, b) // nil 스캐너는 건너뛰어야 한다.
	vulns, err := multi.Scan(context.Background(), []string{"example.com"})
	if err != nil {
		t.Fatalf("Scan 오류: %v", err)
	}
	if len(vulns) != 3 {
		t.Fatalf("합쳐진 취약점 개수 = %d, want 3", len(vulns))
	}
}

// TestMultiScannerToleratesError는 한 스캐너의 오류가 나머지 결과를 막지 않는지 검증한다.
func TestMultiScannerToleratesError(t *testing.T) {
	good := stubVuln{vulns: []model.Vulnerability{{ID: "ok"}}}
	bad := stubVuln{err: context.DeadlineExceeded}

	multi := NewMultiScanner(bad, good)
	vulns, err := multi.Scan(context.Background(), []string{"example.com"})
	if err != nil {
		t.Fatalf("Scan 오류: %v", err)
	}
	if len(vulns) != 1 || vulns[0].ID != "ok" {
		t.Errorf("오류 스캐너 이후 결과 집계 실패: %+v", vulns)
	}
}
