package service

import (
	"context"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rikychoi/recon/internal/model"
)

// Recon은 자산 식별부터 취약점 점검까지의 전체 흐름을 조율하는 인터페이스이다.
type Recon interface {
	// Run은 대상 도메인에 대해 점검을 수행하고 결과를 반환한다.
	Run(ctx context.Context, domain string) (model.ScanResult, error)
}

// defaultAssetConcurrency는 자산별 파이프라인(포트스캔→취약점점검)을 동시에 실행하는 기본 상한이다.
const defaultAssetConcurrency = 8

// Orchestrator는 각 스캐너를 조합하여 점검을 수행하는 Recon 구현이다.
// 각 스캐너는 nil일 수 있으며, nil인 단계는 건너뛴다.
type Orchestrator struct {
	dns              DNSResolver          // DNS/메일 서버 조회
	subs             SubdomainScanner     // 서브도메인 열거
	port             PortScanner          // 포트 스캔
	vuln             VulnerabilityScanner // 취약점 점검
	progress         io.Writer            // 진행 상황 출력 대상(nil이면 미출력)
	progressMu       sync.Mutex           // 병렬 구간에서 진행 로그 출력을 직렬화한다.
	assetConcurrency int                  // 자산별 파이프라인 동시 실행 상한
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(보통 os.Stderr).
// nil을 넘기면 진행 로그를 출력하지 않는다.
func (o *Orchestrator) SetProgress(w io.Writer) {
	o.progress = w
}

// SetAssetConcurrency는 자산별 파이프라인을 동시에 실행할 최대 개수를 지정한다(0 이하이면 무시).
func (o *Orchestrator) SetAssetConcurrency(n int) {
	if n > 0 {
		o.assetConcurrency = n
	}
}

// NewOrchestrator는 주어진 스캐너들로 Orchestrator를 생성한다.
func NewOrchestrator(dns DNSResolver, subs SubdomainScanner, vuln VulnerabilityScanner) *Orchestrator {
	return NewOrchestratorWithPortScan(dns, subs, nil, vuln)
}

// NewOrchestratorWithPortScan은 포트 스캔 단계가 포함된 Orchestrator를 생성한다.
func NewOrchestratorWithPortScan(dns DNSResolver, subs SubdomainScanner, port PortScanner, vuln VulnerabilityScanner) *Orchestrator {
	return &Orchestrator{
		dns:              dns,
		subs:             subs,
		port:             port,
		vuln:             vuln,
		assetConcurrency: defaultAssetConcurrency,
	}
}

// logf는 병렬 구간에서 여러 고루틴이 진행 로그를 섞어 쓰지 않도록 출력을 직렬화한다.
func (o *Orchestrator) logf(format string, a ...any) {
	o.progressMu.Lock()
	defer o.progressMu.Unlock()
	progressf(o.progress, format, a...)
}

// scanAsset은 포트 스캔·취약점 점검을 진행할 하나의 자산(IP)을 나타낸다.
// key는 중복 제거 기준이자 포트 스캔·취약점 점검 대상(식별된 IP, 없으면 호스트명)이며,
// hostnames는 이 IP를 가리키는 도메인 목록으로 결과 추적·로그 표시에만 쓰인다(스캔 대상 아님).
type scanAsset struct {
	key       string   // 스캔 대상: 식별된 IP(없으면 호스트명)
	hostnames []string // 이 IP를 가리키는 도메인 목록(참고용)
}

// Run은 자산 식별(DNS→서브도메인) 후, 식별된 자산을 IP 기준으로 중복 제거하고
// 자산별 (포트스캔→취약점점검) 파이프라인을 고루틴으로 병렬 실행하여 하나의 보고서로 취합한다.
func (o *Orchestrator) Run(ctx context.Context, domain string) (model.ScanResult, error) {
	result := model.ScanResult{Target: domain, StartedAt: time.Now()}
	result.Asset.Domain = domain

	progressf(o.progress, "[*] %s 점검 시작\n", domain)

	// 1) DNS/메일 서버 조회 (자산 식별)
	if o.dns != nil {
		progressf(o.progress, "[*] DNS/메일 서버 조회 중...\n")
		if records, mails, err := o.dns.Resolve(ctx, domain); err == nil {
			result.Asset.DNSRecords = records
			result.Asset.MailServers = mails
			progressf(o.progress, "[+] DNS 레코드 %d개, 메일 서버 %d개\n", len(records), len(mails))
		} else {
			progressf(o.progress, "[!] DNS 조회 실패: %v\n", err)
		}
	}

	// 2) 서브도메인 열거 (자산 식별)
	if o.subs != nil {
		progressf(o.progress, "[*] 서브도메인 열거 중...\n")
		if subs, err := o.subs.Enumerate(ctx, domain); err == nil {
			result.Asset.Subdomains = subs
			progressf(o.progress, "[+] 서브도메인 %d개 발견\n", len(subs))
		} else {
			progressf(o.progress, "[!] 서브도메인 열거 실패: %v\n", err)
		}
	}

	// 3) 식별된 자산을 IP 기준으로 중복 제거한다.
	//    같은 IP를 가리키는 호스트명은 하나의 자산으로 묶어 포트 스캔이 한 번만 수행되게 한다.
	rootIPs := extractHostIPs(result.Asset.DNSRecords)
	assets := buildAssets(domain, rootIPs, result.Asset.Subdomains)

	if o.port == nil && o.vuln == nil {
		// 포트 스캔·취약점 점검이 모두 비활성이면 자산 식별 결과만 반환한다.
		result.FinishedAt = time.Now()
		progressf(o.progress, "[*] 점검 완료 (소요 %s)\n", result.Duration().Round(time.Millisecond))
		return result, nil
	}

	progressf(o.progress, "[*] 자산 %d개에 대해 포트스캔→취약점점검 병렬 실행 (동시 %d개)...\n",
		len(assets), o.assetConcurrency)

	// 4) 자산별 (포트스캔 → 취약점점검) 파이프라인을 고루틴으로 병렬 실행하고 결과를 취합한다.
	var (
		mu       sync.Mutex            // allPorts/allVulns 취합 보호
		allPorts []model.Port          // 모든 자산의 포트 스캔 결과
		allVulns []model.Vulnerability // 모든 자산의 취약점 점검 결과
		wg       sync.WaitGroup
	)
	sem := make(chan struct{}, o.assetConcurrency) // 동시 실행 자산 수 제한

	for _, a := range assets {
		wg.Add(1)
		go func(a *scanAsset) {
			defer wg.Done()

			// 세마포어로 동시 실행 자산 수를 제한한다. 취소 시 즉시 빠져나간다.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			ports, vulns := o.scanOne(ctx, a)

			mu.Lock()
			allPorts = append(allPorts, ports...)
			allVulns = append(allVulns, vulns...)
			mu.Unlock()
		}(a)
	}
	wg.Wait()

	// 병렬 수집이라 순서가 비결정적이므로 정렬하여 보고서 출력을 안정화한다.
	sortPorts(allPorts)
	sortVulns(allVulns)
	result.Asset.Ports = allPorts
	result.Vulnerabilities = allVulns

	progressf(o.progress, "[+] 취합 결과: 열린 포트 %d개, 취약점 %d건\n", len(allPorts), len(allVulns))

	result.FinishedAt = time.Now()
	progressf(o.progress, "[*] 점검 완료 (소요 %s)\n", result.Duration().Round(time.Millisecond))
	return result, nil
}

// scanOne은 하나의 자산(IP)에 대해 포트 스캔과 취약점 점검을 순차 실행한다.
// 포트 스캔·취약점 점검 모두 자산의 대표 대상(IP)에 대해 1회만 수행한다.
// 같은 IP를 가리키는 여러 도메인이어도 스캔은 IP 단위로 중복 없이 이뤄진다.
func (o *Orchestrator) scanOne(ctx context.Context, a *scanAsset) ([]model.Port, []model.Vulnerability) {
	// 이 IP를 가리키는 도메인들을 함께 남겨 결과 추적을 돕는다.
	if len(a.hostnames) > 0 {
		o.logf("    - [자산] %s (%s)\n", a.key, strings.Join(a.hostnames, ", "))
	} else {
		o.logf("    - [자산] %s\n", a.key)
	}

	var ports []model.Port
	if o.port != nil {
		o.logf("    - [포트] %s 스캔...\n", a.key)
		if p, err := o.port.Scan(ctx, []string{a.key}); err == nil {
			ports = p
		} else {
			o.logf("    - [포트] %s 실패: %v\n", a.key, err)
		}
	}

	var vulns []model.Vulnerability
	if o.vuln != nil {
		o.logf("    - [취약점] %s 점검...\n", a.key)
		if v, err := o.vuln.Scan(ctx, []string{a.key}); err == nil {
			vulns = v
		} else {
			o.logf("    - [취약점] %s 실패: %v\n", a.key, err)
		}
	}
	return ports, vulns
}

// extractHostIPs는 DNS 레코드에서 A/AAAA 레코드의 IP 값만 추출한다(루트 도메인의 IP).
func extractHostIPs(records []model.DNSRecord) []string {
	var ips []string
	for _, r := range records {
		if r.Type == "A" || r.Type == "AAAA" {
			ips = append(ips, r.Value)
		}
	}
	return ips
}

// buildAssets는 루트 도메인과 서브도메인을 IP 기준으로 묶어 중복 없는 자산 목록을 만든다.
// 같은 IP를 가리키는 여러 호스트명은 하나의 자산으로 합쳐 포트 스캔 중복을 방지하고,
// IP를 해석하지 못한 호스트명은 호스트명 자체를 대상으로 삼는다.
// 반환 순서는 최초 등장 순으로 안정적이다.
func buildAssets(domain string, rootIPs []string, subs []model.Subdomain) []*scanAsset {
	order := make([]string, 0)
	byKey := make(map[string]*scanAsset)

	// add는 (key, hostname)을 자산 맵에 등록한다. 같은 key면 호스트명만 추가(중복 제외)한다.
	add := func(key, hostname string) {
		a, ok := byKey[key]
		if !ok {
			a = &scanAsset{key: key}
			byKey[key] = a
			order = append(order, key)
		}
		for _, h := range a.hostnames {
			if h == hostname {
				return
			}
		}
		a.hostnames = append(a.hostnames, hostname)
	}

	// 루트 도메인: 해석된 IP가 있으면 IP별로, 없으면 도메인명 자체로 등록한다.
	if len(rootIPs) == 0 {
		add(domain, domain)
	} else {
		for _, ip := range rootIPs {
			add(ip, domain)
		}
	}

	// 서브도메인: 각 IP별로 등록하되, IP가 없으면 서브도메인명 자체로 등록한다.
	for _, s := range subs {
		if len(s.IPs) == 0 {
			add(s.Name, s.Name)
			continue
		}
		for _, ip := range s.IPs {
			add(ip, s.Name)
		}
	}

	assets := make([]*scanAsset, 0, len(order))
	for _, k := range order {
		assets = append(assets, byKey[k])
	}
	return assets
}

// sortPorts는 포트 결과를 대상·포트 번호 순으로 정렬한다.
func sortPorts(ports []model.Port) {
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Target != ports[j].Target {
			return ports[i].Target < ports[j].Target
		}
		return ports[i].Number < ports[j].Number
	})
}

// sortVulns는 취약점 결과를 대상·식별자·탐지도구 순으로 정렬한다.
func sortVulns(vulns []model.Vulnerability) {
	sort.Slice(vulns, func(i, j int) bool {
		if vulns[i].Target != vulns[j].Target {
			return vulns[i].Target < vulns[j].Target
		}
		if vulns[i].ID != vulns[j].ID {
			return vulns[i].ID < vulns[j].ID
		}
		return vulns[i].Source < vulns[j].Source
	})
}
