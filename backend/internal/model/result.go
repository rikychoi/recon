package model

import "time"

// ScanResult는 한 번의 점검 실행 전체 결과를 담는 최상위 모델이다.
type ScanResult struct {
	Target          string          `json:"target"`          // 점검 대상 도메인
	StartedAt       time.Time       `json:"started_at"`      // 점검 시작 시각
	FinishedAt      time.Time       `json:"finished_at"`     // 점검 종료 시각
	Asset           Asset           `json:"asset"`           // 자산 식별 결과
	Vulnerabilities []Vulnerability `json:"vulnerabilities"` // 발견된 취약점 목록
}

// Duration은 점검에 소요된 시간을 반환한다.
func (r ScanResult) Duration() time.Duration {
	return r.FinishedAt.Sub(r.StartedAt)
}
