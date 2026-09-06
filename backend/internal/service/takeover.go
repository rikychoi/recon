package service

import (
	"context"
	"io"
	"strings"

	"github.com/rikychoi/recon/internal/model"
)

// defaultResolver는 탈취 탐지용 DNS 리졸버를 반환한다.
// 표준 net.LookupCNAME은 댕글링(대상 NXDOMAIN) 시 CNAME을 얻지 못하므로,
// TYPE=CNAME 직접 질의를 하는 rawResolver를 사용한다.
func defaultResolver() cnameLookuper {
	return newRawResolver()
}

// cnameLookuper는 탈취 탐지에 필요한 DNS 조회 최소 인터페이스이다.
// 실제로는 rawResolver를, 테스트에는 가짜 구현을 주입한다.
type cnameLookuper interface {
	// LookupCNAME은 호스트의 CNAME 대상을 반환한다(대상이 해석 불가여도 CNAME이 있으면 반환).
	LookupCNAME(ctx context.Context, host string) (string, error)
	// LookupHost는 호스트를 IP로 해석한다. 대상이 사라지면 오류(NXDOMAIN)를 반환한다.
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// takeoverFingerprint는 특정 서비스(플랫폼)를 가리키는 CNAME 접미사와 서비스명을 짝지은 것이다.
type takeoverFingerprint struct {
	suffix  string // CNAME이 이 접미사로 끝나면 해당 서비스로 판단한다.
	service string // 사람이 읽을 서비스 이름
}

// defaultTakeoverFingerprints는 서브도메인 탈취가 자주 발생하는 서드파티 호스팅 서비스 목록이다.
// CNAME이 이들 중 하나를 가리키는데 최종 대상이 해석되지 않으면(댕글링) 탈취 후보로 본다.
var defaultTakeoverFingerprints = []takeoverFingerprint{
	{".github.io", "GitHub Pages"},
	{".herokuapp.com", "Heroku"},
	{".herokudns.com", "Heroku"},
	{".s3.amazonaws.com", "AWS S3"},
	{".cloudfront.net", "AWS CloudFront"},
	{".azurewebsites.net", "Azure App Service"},
	{".cloudapp.net", "Azure"},
	{".trafficmanager.net", "Azure Traffic Manager"},
	{".blob.core.windows.net", "Azure Blob Storage"},
	{".netlify.app", "Netlify"},
	{".netlify.com", "Netlify"},
	{".pages.dev", "Cloudflare Pages"},
	{".ghost.io", "Ghost"},
	{".wpengine.com", "WP Engine"},
	{".pantheonsite.io", "Pantheon"},
	{".readthedocs.io", "Read the Docs"},
	{".surge.sh", "Surge"},
	{".bitbucket.io", "Bitbucket"},
	{".fastly.net", "Fastly"},
	{".zendesk.com", "Zendesk"},
	{".statuspage.io", "Statuspage"},
	{".firebaseapp.com", "Firebase"},
}

// TakeoverScanner는 댕글링 CNAME을 근거로 서브도메인 탈취 가능성을 탐지하는 TakeoverDetector 구현이다.
// HTTP 요청 없이 DNS만으로 판정하여 부작용을 최소화한다:
// 대상 호스트의 CNAME이 알려진 서드파티 서비스를 가리키는데 그 대상이 해석되지 않으면 탈취 후보로 본다.
type TakeoverScanner struct {
	resolver     cnameLookuper         // DNS 조회기(주입 가능)
	fingerprints []takeoverFingerprint // 탐지 대상 서비스 지문
	progress     io.Writer             // 진행 상황 출력 대상(nil이면 미출력)
}

// NewTakeoverScanner는 TakeoverScanner를 생성한다.
// resolver가 nil이면 시스템 기본 리졸버를, fingerprints가 비면 기본 목록을 사용한다.
func NewTakeoverScanner(resolver cnameLookuper, fingerprints []takeoverFingerprint) *TakeoverScanner {
	if resolver == nil {
		resolver = defaultResolver()
	}
	if len(fingerprints) == 0 {
		fingerprints = defaultTakeoverFingerprints
	}
	return &TakeoverScanner{resolver: resolver, fingerprints: fingerprints}
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (t *TakeoverScanner) SetProgress(w io.Writer) { t.progress = w }

// Detect는 루트 도메인과 서브도메인들을 검사하여 탈취 가능 후보를 취약점으로 반환한다.
func (t *TakeoverScanner) Detect(ctx context.Context, domain string, subs []model.Subdomain) []model.Vulnerability {
	// 검사 대상 호스트 집합을 만든다(루트 도메인 + 서브도메인, 중복 제거).
	hosts := make([]string, 0, len(subs)+1)
	seen := make(map[string]bool)
	addHost := func(h string) {
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	addHost(domain)
	for _, s := range subs {
		addHost(s.Name)
	}

	var vulns []model.Vulnerability
	for _, host := range hosts {
		if v, ok := t.check(ctx, host); ok {
			vulns = append(vulns, v)
		}
	}
	return vulns
}

// check는 단일 호스트가 탈취 후보인지 판정한다.
// CNAME이 알려진 서비스를 가리키면서 그 최종 대상이 해석되지 않으면(NXDOMAIN/빈 응답) 후보로 본다.
func (t *TakeoverScanner) check(ctx context.Context, host string) (model.Vulnerability, bool) {
	cname, err := t.resolver.LookupCNAME(ctx, host)
	if err != nil {
		return model.Vulnerability{}, false
	}
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	if cname == "" || cname == strings.ToLower(host) {
		return model.Vulnerability{}, false // 외부를 가리키는 CNAME이 없다.
	}

	service := t.matchFingerprint(cname)
	if service == "" {
		return model.Vulnerability{}, false // 알려진 탈취 대상 서비스가 아니다.
	}

	// CNAME 대상(서드파티 리소스)이 해석되지 않으면 댕글링(탈취 후보)이다.
	// 호스트가 아니라 CNAME 대상을 확인해야, 호스트 A레코드 캐시에 영향받지 않고 정확히 판정한다.
	if addrs, err := t.resolver.LookupHost(ctx, cname); err == nil && len(addrs) > 0 {
		return model.Vulnerability{}, false // 대상이 살아있으므로 탈취 후보 아님.
	}

	const cvss = 8.1 // 서브도메인 탈취는 고위험(하이재킹→피싱/쿠키 탈취 등)으로 평가한다.
	return model.Vulnerability{
		ID:       "TAKEOVER-" + strings.ToUpper(strings.ReplaceAll(service, " ", "-")),
		Name:     "서브도메인 탈취 가능(댕글링 CNAME → " + service + "): " + cname,
		Target:   host,
		CVSS:     cvss,
		Severity: model.SeverityFromCVSS(cvss),
		Source:   "takeover",
	}, true
}

// matchFingerprint는 CNAME이 어떤 서비스 지문에 해당하는지 찾아 서비스명을 반환한다(없으면 빈 문자열).
func (t *TakeoverScanner) matchFingerprint(cname string) string {
	for _, fp := range t.fingerprints {
		if strings.HasSuffix(cname, fp.suffix) {
			return fp.service
		}
	}
	return ""
}
