package service

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// fakeDoer는 요청 URL에 따라 미리 지정한 JSON 본문을 돌려주는 httpDoer 가짜 구현이다.
type fakeDoer struct {
	// respond는 요청 URL을 받아 (본문, 상태코드)를 반환한다.
	respond func(url string) (string, int)
	calls   []string // 호출된 URL 기록(호출 횟수 검증용)
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.calls = append(f.calls, req.URL.String())
	body, code := f.respond(req.URL.String())
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}

// TestCVEEnricher_EPSSandKEV는 EPSS 점수와 KEV 등재 여부가 취약점에 반영되는지 검증한다.
func TestCVEEnricher_EPSSandKEV(t *testing.T) {
	doer := &fakeDoer{respond: func(url string) (string, int) {
		switch {
		case strings.Contains(url, "epss"):
			// CVE-2021-44228은 높은 EPSS, CVE-2020-0001은 낮은 EPSS
			return `{"data":[{"cve":"CVE-2021-44228","epss":"0.97430"},{"cve":"CVE-2020-0001","epss":"0.00042"}]}`, 200
		case strings.Contains(url, "known_exploited"):
			// KEV에는 CVE-2021-44228만 등재
			return `{"vulnerabilities":[{"cveID":"CVE-2021-44228"}]}`, 200
		default:
			return "{}", 200
		}
	}}
	en := NewCVEEnricher(doer, false)

	vulns := []model.Vulnerability{
		{ID: "CVE-2021-44228", Name: "Log4Shell", Target: "a", CVSS: 10.0},
		{ID: "generic", Name: "관련 CVE-2020-0001 존재", Target: "b", CVSS: 5.0},
		{ID: "no-cve", Name: "CVE 없음", Target: "c", CVSS: 3.0},
	}
	out := en.Enrich(context.Background(), vulns)

	// 첫 취약점: EPSS 반영 + KEV true + CVE 추출
	if len(out[0].CVEs) != 1 || out[0].CVEs[0] != "CVE-2021-44228" {
		t.Errorf("CVE 추출 실패: %v", out[0].CVEs)
	}
	if out[0].EPSS < 0.97 {
		t.Errorf("EPSS 미반영: %v", out[0].EPSS)
	}
	if !out[0].KEV {
		t.Error("KEV 미반영: true 여야 함")
	}
	// 두 번째: 이름에서 CVE 추출, EPSS 낮음, KEV 아님
	if len(out[1].CVEs) != 1 || out[1].CVEs[0] != "CVE-2020-0001" {
		t.Errorf("이름에서 CVE 추출 실패: %v", out[1].CVEs)
	}
	if out[1].KEV {
		t.Error("두 번째 취약점은 KEV가 아니어야 함")
	}
	// 세 번째: CVE 없으므로 보강 없음
	if len(out[2].CVEs) != 0 || out[2].EPSS != 0 || out[2].KEV {
		t.Errorf("CVE 없는 취약점이 보강됨: %+v", out[2])
	}
}

// TestCVEEnricher_NVDFillsCVSS는 CVSS가 비어 있을 때 NVD 보강으로 점수가 채워지는지 검증한다.
func TestCVEEnricher_NVDFillsCVSS(t *testing.T) {
	doer := &fakeDoer{respond: func(url string) (string, int) {
		switch {
		case strings.Contains(url, "epss"):
			return `{"data":[]}`, 200
		case strings.Contains(url, "known_exploited"):
			return `{"vulnerabilities":[]}`, 200
		case strings.Contains(url, "nvd") || strings.Contains(url, "cveId"):
			return `{"vulnerabilities":[{"cve":{"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]}}}]}`, 200
		default:
			return "{}", 200
		}
	}}
	en := NewCVEEnricher(doer, true) // NVD 보강 켜기

	vulns := []model.Vulnerability{{ID: "CVE-2021-44228", Name: "x", Target: "a", CVSS: 0}}
	out := en.Enrich(context.Background(), vulns)

	if out[0].CVSS != 9.8 {
		t.Errorf("NVD CVSS 미반영: got %v", out[0].CVSS)
	}
	if out[0].Severity != "critical" {
		t.Errorf("CVSS 보강 후 심각도 재계산 실패: %v", out[0].Severity)
	}
}

// TestCVEEnricher_NetworkFailureIsBestEffort는 조회 실패 시 원본을 그대로 돌려주는지 검증한다.
func TestCVEEnricher_NetworkFailureIsBestEffort(t *testing.T) {
	doer := &fakeDoer{respond: func(url string) (string, int) {
		return "", 500 // 모든 조회 실패
	}}
	en := NewCVEEnricher(doer, true)

	vulns := []model.Vulnerability{{ID: "CVE-2021-44228", Name: "x", Target: "a", CVSS: 7.5}}
	out := en.Enrich(context.Background(), vulns)

	if len(out) != 1 || out[0].CVSS != 7.5 {
		t.Errorf("조회 실패 시 원본 보존 실패: %+v", out)
	}
	// CVE 추출은 네트워크와 무관하므로 여전히 채워져야 한다.
	if len(out[0].CVEs) != 1 {
		t.Errorf("CVE 추출은 실패와 무관하게 수행되어야 함: %v", out[0].CVEs)
	}
}

// TestCVEEnricher_KEVFetchedOnce는 KEV 피드가 한 번만 조회(캐시)되는지 검증한다.
func TestCVEEnricher_KEVFetchedOnce(t *testing.T) {
	doer := &fakeDoer{respond: func(url string) (string, int) {
		if strings.Contains(url, "epss") {
			return `{"data":[]}`, 200
		}
		return `{"vulnerabilities":[]}`, 200
	}}
	en := NewCVEEnricher(doer, false)

	en.Enrich(context.Background(), []model.Vulnerability{{ID: "CVE-2021-44228"}})
	en.Enrich(context.Background(), []model.Vulnerability{{ID: "CVE-2020-0001"}})

	kevCalls := 0
	for _, c := range doer.calls {
		if strings.Contains(c, "known_exploited") {
			kevCalls++
		}
	}
	if kevCalls != 1 {
		t.Errorf("KEV 피드는 한 번만 조회되어야 함: got %d", kevCalls)
	}
}
