package service

import (
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// TestFilterOutInfo는 info 심각도는 제거하되, CVSS가 0이어도 확인된 취약점(high/medium)은 유지하는지 검증한다.
func TestFilterOutInfo(t *testing.T) {
	in := []model.Vulnerability{
		{ID: "ftp-detect", Severity: "info", CVSS: 0},          // 제거 대상(탐지)
		{ID: "CVE-2021-42013", Severity: "high", CVSS: 0},      // 유지(보강 전 CVSS 0인 확인 취약점)
		{ID: "CVE-2017-5638", Severity: "critical", CVSS: 9.8}, // 유지
		{ID: "takeover", Severity: "high", CVSS: 8.1},          // 유지
		{ID: "info-upper", Severity: "INFO", CVSS: 0},          // 대소문자 무관 제거
	}
	out := filterOutInfo(in)
	if len(out) != 3 {
		t.Fatalf("유지 3건 기대, got %d: %+v", len(out), out)
	}
	for _, v := range out {
		if v.Severity == "info" || v.Severity == "INFO" {
			t.Errorf("info가 남았음: %+v", v)
		}
	}
}
