package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// CVEResolver는 서비스의 CPE(제품+버전)를 근거로 해당 버전에 영향을 주는 CVE 목록을 조회한다.
// 이를 통해 "제품명 검색"보다 정밀한 "버전 → CVE → 모듈" 연결이 가능해진다.
type CVEResolver interface {
	// ResolveCVEs는 CPE(버전 포함)에 해당하는 CVE 식별자 목록을 반환한다(없으면 nil).
	ResolveCVEs(ctx context.Context, cpe string) []string
}

// NVDResolver는 NVD의 CVE API(virtualMatchString)로 CPE에 해당하는 CVE를 조회하는 CVEResolver 구현이다.
type NVDResolver struct {
	client   httpDoer  // HTTP 실행기(주입 가능)
	url      string    // NVD CVE API 엔드포인트
	maxCVEs  int       // 조회 CVE 수 상한(과도한 search 인자 방지)
	progress io.Writer // 진행 상황 출력 대상(nil이면 미출력)
}

// defaultNVDMaxCVEs는 한 CPE에 대해 가져올 CVE 수 상한이다.
const defaultNVDMaxCVEs = 40

// NewNVDResolver는 NVDResolver를 생성한다. client가 nil이면 기본 HTTP 클라이언트를 사용한다.
func NewNVDResolver(client httpDoer) *NVDResolver {
	if client == nil {
		client = defaultHTTPClient()
	}
	return &NVDResolver{client: client, url: defaultNVDURL, maxCVEs: defaultNVDMaxCVEs}
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (r *NVDResolver) SetProgress(w io.Writer) { r.progress = w }

// nvdCVEListResponse는 NVD CVE API 응답에서 CVE ID 추출에 필요한 필드만 담는다.
type nvdCVEListResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID string `json:"id"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// ResolveCVEs는 CPE를 NVD virtualMatchString으로 질의하여 해당 버전의 CVE 목록을 반환한다.
// 버전이 없는 CPE(전 버전 매칭)는 결과가 지나치게 넓어 무의미하므로 조회하지 않는다.
func (r *NVDResolver) ResolveCVEs(ctx context.Context, cpe string) []string {
	match := cpeToVirtualMatch(cpe)
	if match == "" {
		return nil // 버전을 포함한 유효한 CPE가 아니면 조회하지 않는다.
	}
	q := url.Values{}
	q.Set("virtualMatchString", match)
	q.Set("resultsPerPage", strconv.Itoa(r.maxCVEs))

	var resp nvdCVEListResponse
	if err := getJSONInto(ctx, r.client, r.url+"?"+q.Encode(), &resp); err != nil {
		progressf(r.progress, "    - NVD CVE 조회 실패(건너뜀): %v\n", err)
		return nil
	}

	seen := make(map[string]struct{})
	var cves []string
	for _, v := range resp.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVE.ID))
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		cves = append(cves, id)
	}
	sort.Strings(cves)
	return cves
}

// cpeToVirtualMatch는 nmap CPE(2.2 형식 등)를 NVD virtualMatchString용 2.3 형식으로 변환한다.
// 버전 필드가 있어야만 변환하며(예: cpe:/a:apache:http_server:2.4.49 → cpe:2.3:a:apache:http_server:2.4.49),
// 버전이 없거나 형식이 맞지 않으면 빈 문자열을 반환한다.
func cpeToVirtualMatch(cpe string) string {
	c := strings.ToLower(strings.TrimSpace(cpe))
	switch {
	case strings.HasPrefix(c, "cpe:2.3:"):
		// 이미 2.3 형식: cpe:2.3:part:vendor:product:version:...
		parts := strings.Split(c, ":")
		if len(parts) >= 6 && parts[5] != "" && parts[5] != "*" && parts[5] != "-" {
			return strings.Join(parts[:6], ":")
		}
		return ""
	case strings.HasPrefix(c, "cpe:/"):
		// 2.2 형식: cpe:/part:vendor:product:version:...
		parts := strings.Split(strings.TrimPrefix(c, "cpe:/"), ":")
		if len(parts) < 4 { // part, vendor, product, version 최소 4개 필요
			return ""
		}
		part, vendor, product, version := parts[0], parts[1], parts[2], parts[3]
		if product == "" || version == "" || version == "*" || version == "-" {
			return ""
		}
		return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s", part, vendor, product, version)
	default:
		return ""
	}
}

// getJSONInto는 httpDoer로 GET 요청을 보내 JSON 응답을 out에 디코딩한다(2xx가 아니면 오류).
func getJSONInto(ctx context.Context, client httpDoer, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
