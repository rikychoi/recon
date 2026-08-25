package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rikychoi/recon/internal/model"
)

// defaultHTTPClient는 외부 위협 인텔리전스 조회에 쓰는 기본 HTTP 클라이언트이다.
// 전체 점검 컨텍스트 타임아웃과 별개로, 개별 요청이 오래 매달리지 않도록 상한을 둔다.
func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second}
}

// httpDoer는 HTTP 요청을 수행하는 최소 인터페이스이다.
// 실제 실행에는 *http.Client를, 테스트에는 가짜 구현을 주입해 네트워크 없이 검증한다.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// 외부 위협 인텔리전스 소스의 기본 엔드포인트.
const (
	defaultEPSSURL = "https://api.first.org/data/v1/epss"                                                  // FIRST.org EPSS API
	defaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" // CISA KEV 피드
	defaultNVDURL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"                                    // NVD CVE API
)

// CVEEnricher는 발견된 취약점을 EPSS·CISA KEV·(선택적)NVD로 보강하는 Enricher 구현이다.
// - EPSS: 각 CVE의 악용 확률(0~1)을 조회해 위험 우선순위화를 돕는다.
// - KEV : CISA가 "실제 악용 중"으로 지정한 CVE 목록과 대조한다.
// - NVD : CVSS가 비어 있는 취약점에 한해 권위 있는 CVSS 점수를 채운다.
type CVEEnricher struct {
	client   httpDoer  // HTTP 실행기(주입 가능)
	epssURL  string    // EPSS 엔드포인트
	kevURL   string    // KEV 피드 URL
	nvdURL   string    // NVD 엔드포인트
	useNVD   bool      // NVD 보강 사용 여부(레이트 제한이 있어 선택적)
	progress io.Writer // 진행 상황 출력 대상(nil이면 미출력)

	kevOnce sync.Once       // KEV 피드는 한 번만 내려받는다.
	kevSet  map[string]bool // KEV에 등재된 CVE 집합(대문자)
}

// NewCVEEnricher는 CVEEnricher를 생성한다. client가 nil이면 기본 HTTP 클라이언트를 사용한다.
// useNVD가 true이면 CVSS가 비어 있는 취약점에 대해 NVD 조회로 CVSS를 보강한다.
func NewCVEEnricher(client httpDoer, useNVD bool) *CVEEnricher {
	if client == nil {
		client = defaultHTTPClient()
	}
	return &CVEEnricher{
		client:  client,
		epssURL: defaultEPSSURL,
		kevURL:  defaultKEVURL,
		nvdURL:  defaultNVDURL,
		useNVD:  useNVD,
	}
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (e *CVEEnricher) SetProgress(w io.Writer) { e.progress = w }

// Enrich는 각 취약점의 연관 CVE를 식별하고 EPSS·KEV·(선택)NVD 정보를 채워 반환한다.
// 네트워크 실패는 무시하고 채울 수 있는 값만 채운다(최선노력).
func (e *CVEEnricher) Enrich(ctx context.Context, vulns []model.Vulnerability) []model.Vulnerability {
	if len(vulns) == 0 {
		return vulns
	}

	// 1) 각 취약점에서 CVE를 추출하고(비어 있으면 ID/이름에서), 전체 CVE 집합을 만든다.
	cveSet := make(map[string]struct{})
	for i := range vulns {
		if len(vulns[i].CVEs) == 0 {
			vulns[i].CVEs = model.ExtractCVEs(vulns[i].ID, vulns[i].Name)
		}
		for _, cve := range vulns[i].CVEs {
			cveSet[cve] = struct{}{}
		}
	}
	if len(cveSet) == 0 {
		return vulns // CVE가 하나도 없으면 보강할 것이 없다.
	}
	cves := make([]string, 0, len(cveSet))
	for c := range cveSet {
		cves = append(cves, c)
	}

	progressf(e.progress, "    - CVE 보강: %d개 CVE에 EPSS/KEV%s 조회 중...\n",
		len(cves), map[bool]string{true: "/NVD", false: ""}[e.useNVD])

	// 2) EPSS 점수와 KEV 집합을 조회한다(실패해도 계속 진행).
	epss := e.fetchEPSS(ctx, cves)
	kev := e.fetchKEV(ctx)

	// 3) 각 취약점에 보강 정보를 반영한다.
	for i := range vulns {
		for _, cve := range vulns[i].CVEs {
			if score, ok := epss[cve]; ok && score > vulns[i].EPSS {
				vulns[i].EPSS = score // 여러 CVE 중 가장 높은 악용 확률을 대표값으로.
			}
			if kev[cve] {
				vulns[i].KEV = true
			}
		}
		// CVSS가 비어 있고 NVD 보강이 켜져 있으면 NVD에서 점수를 채운다.
		if e.useNVD && vulns[i].CVSS == 0 {
			for _, cve := range vulns[i].CVEs {
				if s, ok := e.fetchNVDScore(ctx, cve); ok {
					vulns[i].CVSS = s
					vulns[i].Severity = model.SeverityFromCVSS(s)
					break
				}
			}
		}
	}
	return vulns
}

// epssResponse는 EPSS API 응답 중 필요한 필드만 담는다.
type epssResponse struct {
	Data []struct {
		CVE  string `json:"cve"`
		EPSS string `json:"epss"` // 문자열로 내려오는 확률 값
	} `json:"data"`
}

// fetchEPSS는 CVE 목록을 한 번의 요청으로 EPSS API에 조회해 CVE→점수 맵을 반환한다.
// 실패 시 빈 맵을 반환한다(보강 생략).
func (e *CVEEnricher) fetchEPSS(ctx context.Context, cves []string) map[string]float64 {
	result := make(map[string]float64)
	if len(cves) == 0 {
		return result
	}
	q := url.Values{}
	q.Set("cve", strings.Join(cves, ","))
	var resp epssResponse
	if err := e.getJSON(ctx, e.epssURL+"?"+q.Encode(), &resp); err != nil {
		progressf(e.progress, "    - EPSS 조회 실패(건너뜀): %v\n", err)
		return result
	}
	for _, d := range resp.Data {
		if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
			result[strings.ToUpper(d.CVE)] = f
		}
	}
	return result
}

// kevResponse는 CISA KEV 피드 중 필요한 필드만 담는다.
type kevResponse struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// fetchKEV는 CISA KEV 피드를 한 번만 내려받아 CVE 집합으로 캐시하고 반환한다.
func (e *CVEEnricher) fetchKEV(ctx context.Context) map[string]bool {
	e.kevOnce.Do(func() {
		e.kevSet = make(map[string]bool)
		var resp kevResponse
		if err := e.getJSON(ctx, e.kevURL, &resp); err != nil {
			progressf(e.progress, "    - KEV 조회 실패(건너뜀): %v\n", err)
			return
		}
		for _, v := range resp.Vulnerabilities {
			e.kevSet[strings.ToUpper(v.CVEID)] = true
		}
	})
	return e.kevSet
}

// nvdResponse는 NVD CVE API 응답 중 CVSS 점수 추출에 필요한 필드만 담는다.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			Metrics struct {
				V31 []nvdMetric `json:"cvssMetricV31"`
				V30 []nvdMetric `json:"cvssMetricV30"`
				V2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdMetric은 NVD의 CVSS 메트릭 한 항목이다.
type nvdMetric struct {
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// fetchNVDScore는 단일 CVE의 CVSS 기본 점수를 NVD에서 조회한다.
// v3.1 → v3.0 → v2 순으로 가장 상위 버전의 점수를 사용한다. 실패 시 (0,false).
func (e *CVEEnricher) fetchNVDScore(ctx context.Context, cve string) (float64, bool) {
	var resp nvdResponse
	if err := e.getJSON(ctx, e.nvdURL+"?cveId="+url.QueryEscape(cve), &resp); err != nil {
		return 0, false
	}
	for _, v := range resp.Vulnerabilities {
		for _, m := range [][]nvdMetric{v.CVE.Metrics.V31, v.CVE.Metrics.V30, v.CVE.Metrics.V2} {
			if len(m) > 0 && m[0].CVSSData.BaseScore > 0 {
				return m[0].CVSSData.BaseScore, true
			}
		}
	}
	return 0, false
}

// getJSON은 GET 요청을 보내 JSON 응답을 out에 디코딩한다. 2xx가 아니면 오류를 반환한다.
func (e *CVEEnricher) getJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
