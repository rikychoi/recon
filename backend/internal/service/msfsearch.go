package service

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/rikychoi/recon/internal/model"
)

// MSFSearchScanner는 nmap이 인식한 서비스 제품을 근거로 Metasploit 모듈을 "동적으로 검색"하여
// 적용 가능한 취약점 점검을 수행하는 VulnerabilityScanner 구현이다.
//
// 고정 카탈로그(DefaultMSFModules) 방식과 달리, 대상 제품에 해당하는 모듈을 msfconsole의
// `search`로 실시간 발굴하므로 커버리지가 Metasploit 전체로 확장된다. 발굴한 모듈은 실제
// 익스플로잇(run) 대신 `check`(비침투 검증)로만 확인하여, 잘 모르는 사용자도 안전하게 쓸 수 있다.
//
// 실행 흐름(“서비스 인식 → 적용 취약점 검색 → 안전 검증”):
//  1. 각 포트의 제품에서 검색어를 도출한다(예: "Apache httpd" → "httpd", "Apache Struts" → "struts").
//  2. 한 번의 msfconsole 부팅으로 모든 검색을 실행해 후보 모듈을 CSV로 받는다(발굴).
//  3. 한 번의 msfconsole 부팅으로 후보 모듈들을 대상에 `check` 실행하여 취약 여부를 검증한다.
//  4. 검증에서 취약으로 판정된 모듈만 취약점으로 기록한다(가능하면 info에서 CVE도 추출).
type MSFSearchScanner struct {
	binary        string    // msfconsole 경로 (기본 "msfconsole")
	runner        msfRunner // msfconsole 실행기(기본 oneShotMSF, 공유 세션 주입 가능)
	progress      io.Writer // 진행 상황 출력 대상(nil이면 미출력)
	maxPerService int       // 서비스(검색어)당 검증할 모듈 상한
	rankFilter    string    // search rank 필터(예: "gte300" = normal 이상)
}

const (
	defaultMSFSearchMaxPerService = 10       // 검색어당 검증 모듈 상한(과도한 check 실행 방지)
	defaultMSFSearchRank          = "gte300" // normal 이상 랭크만 후보로(저품질 모듈 제외)
)

// NewMSFSearchScanner는 MSFSearchScanner를 생성한다. binary가 비면 "msfconsole"을 사용한다.
func NewMSFSearchScanner(binary string) *MSFSearchScanner {
	if binary == "" {
		binary = "msfconsole"
	}
	s := &MSFSearchScanner{
		binary:        binary,
		maxPerService: defaultMSFSearchMaxPerService,
		rankFilter:    defaultMSFSearchRank,
	}
	s.runner = oneShotMSF{binary: binary} // 기본: 호출마다 부팅(폴백). 공유 세션은 SetSession으로 주입.
	return s
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (s *MSFSearchScanner) SetProgress(w io.Writer) { s.progress = w }

// SetMaxPerService는 검색어당 검증할 모듈 상한을 지정한다(0 이하이면 무시).
func (s *MSFSearchScanner) SetMaxPerService(n int) {
	if n > 0 {
		s.maxPerService = n
	}
}

// SetSession은 프로그램 수명 동안 유지되는 공유 msfconsole 세션을 실행기로 지정한다.
// 이를 통해 발굴·검증의 모든 명령이 매번 새로 부팅하지 않고 하나의 msfconsole에서 실행된다.
func (s *MSFSearchScanner) SetSession(sess msfRunner) {
	if sess != nil {
		s.runner = sess
	}
}

// ansiPattern은 msfconsole 출력의 ANSI 색상 escape 코드를 제거하기 위한 정규식이다.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// wordPattern은 제품 문자열에서 영숫자 토큰을 추출하는 정규식이다.
var wordPattern = regexp.MustCompile(`[A-Za-z0-9]+`)

// searchTerm은 포트의 제품 정보로부터 Metasploit 검색어를 도출한다.
// 제품명의 마지막 토큰이 모듈 검색에 가장 효과적이다(예: "Apache httpd"→"httpd", "Apache Struts"→"struts").
// CPE만 있으면 CPE의 제품 필드를, 둘 다 없으면 서비스명을 사용한다. 도출 실패 시 빈 문자열.
func searchTerm(p model.Port) string {
	if p.Product != "" {
		if words := wordPattern.FindAllString(p.Product, -1); len(words) > 0 {
			return strings.ToLower(words[len(words)-1])
		}
	}
	if prod := cpeProduct(p.CPE); prod != "" {
		return prod
	}
	if p.Service != "" && p.Service != "unknown" {
		return strings.ToLower(p.Service)
	}
	return ""
}

// cpeProduct는 CPE 문자열에서 제품 필드를 추출한다.
// 예: "cpe:/a:apache:struts:2.5.10" → "struts". 형식이 맞지 않으면 빈 문자열.
func cpeProduct(cpe string) string {
	cpe = strings.TrimPrefix(strings.ToLower(cpe), "cpe:/")
	cpe = strings.TrimPrefix(cpe, "cpe:2.3:")
	parts := strings.Split(cpe, ":")
	// cpe:/a:vendor:product:... → [a, vendor, product, ...]
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// discoveredModule은 search로 발굴한 후보 모듈 하나이다.
type discoveredModule struct {
	fullName string // 모듈 전체 경로(예: exploit/multi/http/struts2_content_type_ognl)
	rank     string // 랭크(excellent/great/good 등)
	desc     string // 서술적 이름(예: Apache Struts Jakarta Multipart Parser OGNL Injection)
}

// parseSearchCSV는 `search -o` CSV 출력을 파싱하여 후보 모듈 목록을 만든다.
// CSV 컬럼: #, Full Name, Disclosure Date, Rank, Check, Name.
// 타깃/액션 등 자식 행(Full Name이 공백/"\_"로 시작)은 제외하고 모듈 행만 취한다.
func parseSearchCSV(data []byte) []discoveredModule {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1 // 열 수가 달라도 허용
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return nil
	}
	var mods []discoveredModule
	for _, row := range rows[1:] { // 첫 행은 헤더
		if len(row) < 6 {
			continue
		}
		full := strings.TrimSpace(row[1])
		// 자식 행(타깃 등)은 "\_"를 포함하거나 모듈 경로 형태가 아니므로 제외한다.
		if full == "" || strings.Contains(full, `\_`) || !strings.Contains(full, "/") {
			continue
		}
		mods = append(mods, discoveredModule{fullName: full, rank: row[3], desc: row[5]})
	}
	return mods
}

// checkOutcome은 한 모듈 검증(check)의 결과이다.
type checkOutcome struct {
	vulnerable bool   // 취약 판정 여부
	appears    bool   // "appears to be vulnerable"(추정) 여부
	cve        string // info에서 추출한 대표 CVE(있으면)
}

var (
	cveInText      = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)
	vulnerableLine = regexp.MustCompile(`(?i)the target is vulnerable`)
	appearsLine    = regexp.MustCompile(`(?i)appears to be vulnerable`)
)

// parseCheckOutput은 검증 스크립트의 출력을 마커(===RECON<i>===)로 분할하여
// 작업 인덱스별 검증 결과(취약 여부, CVE)를 파싱한다.
func parseCheckOutput(data []byte) map[int]checkOutcome {
	clean := ansiPattern.ReplaceAllString(string(data), "")
	out := make(map[int]checkOutcome)
	marker := regexp.MustCompile(`===RECON(\d+)===`)

	cur := -1
	var oc checkOutcome
	flush := func() {
		if cur >= 0 {
			out[cur] = oc
		}
	}
	for _, line := range strings.Split(clean, "\n") {
		if m := marker.FindStringSubmatch(line); m != nil {
			flush() // 이전 블록 저장
			cur, _ = strconv.Atoi(m[1])
			oc = checkOutcome{}
			continue
		}
		if cur < 0 {
			continue
		}
		if oc.cve == "" {
			if c := cveInText.FindString(line); c != "" {
				oc.cve = strings.ToUpper(c)
			}
		}
		if vulnerableLine.MatchString(line) {
			oc.vulnerable = true
		}
		if appearsLine.MatchString(line) {
			oc.appears = true
		}
	}
	flush()
	return out
}

// verifyTask는 하나의 (모듈, 대상 호스트, 포트) 검증 작업이다.
type verifyTask struct {
	mod   discoveredModule
	host  string
	rport int
}

// Scan은 대상 포트의 제품을 근거로 모듈을 검색·검증하여 확인된 취약점을 반환한다.
func (s *MSFSearchScanner) Scan(ctx context.Context, targets []model.Port) ([]model.Vulnerability, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// 1) 검색어별로 대상 포트를 묶는다(같은 제품이면 한 번만 검색).
	termPorts := make(map[string][]model.Port)
	var terms []string
	for _, p := range targets {
		term := searchTerm(p)
		if term == "" {
			continue
		}
		if _, ok := termPorts[term]; !ok {
			terms = append(terms, term)
		}
		termPorts[term] = append(termPorts[term], p)
	}
	if len(terms) == 0 {
		return nil, nil
	}

	// 2) 발굴: 한 번의 msfconsole 부팅으로 모든 검색어를 실행한다.
	progressf(s.progress, "    - msf-search: 제품 %d종에 대해 적용 모듈 검색 중...\n", len(terms))
	candidates := s.discover(ctx, terms)

	// 3) 검증 작업 구성: 검색어별 후보 모듈(상한) × 해당 제품 포트.
	var tasks []verifyTask
	for _, term := range terms {
		mods := candidates[term]
		if len(mods) > s.maxPerService {
			mods = mods[:s.maxPerService]
		}
		for _, m := range mods {
			for _, p := range termPorts[term] {
				tasks = append(tasks, verifyTask{mod: m, host: p.Target, rport: p.Number})
			}
		}
	}
	if len(tasks) == 0 {
		progressf(s.progress, "    - msf-search: 적용 가능한 모듈을 찾지 못했습니다.\n")
		return nil, nil
	}

	// 4) 검증: 한 번의 부팅으로 모든 후보를 check 실행하고 결과를 파싱한다.
	progressf(s.progress, "    - msf-search: 후보 모듈 %d건을 check(비침투 검증)로 확인 중...\n", len(tasks))
	outcomes := s.verify(ctx, tasks)

	// 5) 취약 판정된 작업만 취약점으로 기록한다.
	var vulns []model.Vulnerability
	for i, t := range tasks {
		oc := outcomes[i]
		if !oc.vulnerable && !oc.appears {
			continue
		}
		severity := "high" // check가 취약을 확정한 경우
		if !oc.vulnerable && oc.appears {
			severity = "medium" // "appears"는 추정
		}
		id := oc.cve
		if id == "" {
			id = t.mod.fullName
		}
		var cves []string
		if oc.cve != "" {
			cves = []string{oc.cve}
		}
		vulns = append(vulns, model.Vulnerability{
			ID:       id,
			Name:     t.mod.desc + " [" + t.mod.fullName + "]",
			Target:   net.JoinHostPort(t.host, strconv.Itoa(t.rport)),
			CVSS:     0, // msf check는 CVSS를 주지 않는다. CVE가 있으면 이후 보강(NVD/EPSS/KEV)에서 채운다.
			Severity: severity,
			Source:   "metasploit",
			CVEs:     cves,
		})
	}
	return vulns, nil
}

// discover는 검색어별로 후보 모듈을 발굴한다. 모든 검색을 한 msfconsole 부팅에서 실행하고,
// 각 검색 결과는 임시 CSV 파일로 받아 파싱한다. 실패한 검색은 빈 결과로 처리한다.
func (s *MSFSearchScanner) discover(ctx context.Context, terms []string) map[string][]discoveredModule {
	result := make(map[string][]discoveredModule)

	// 검색어별 임시 CSV 경로를 만들고, 하나의 리소스 스크립트로 모든 search를 실행한다.
	files := make(map[string]string, len(terms))
	var cmds []string
	for _, term := range terms {
		f, err := os.CreateTemp("", "recon-msf-*.csv")
		if err != nil {
			continue
		}
		path := f.Name()
		f.Close()
		files[term] = path
		// type:exploit + check:Yes로 "check로 안전 검증 가능한 익스플로잇"만 후보로 좁힌다.
		cmds = append(cmds, fmt.Sprintf("search %s type:exploit check:Yes rank:%s -c -o %s",
			sanitizeTerm(term), s.rankFilter, path))
	}
	if len(cmds) == 0 {
		return result
	}
	defer func() {
		for _, p := range files {
			os.Remove(p)
		}
	}()

	script := strings.Join(cmds, "; ") // exit는 실행기가 관리하므로 넣지 않는다.
	if _, err := s.runner.RunMSF(ctx, script); err != nil {
		progressf(s.progress, "    - msf-search: 검색 실행 실패(건너뜀): %v\n", err)
		// 일부 CSV는 생성됐을 수 있으므로 계속 진행하여 읽어 본다.
	}
	for term, path := range files {
		if data, err := os.ReadFile(path); err == nil {
			result[term] = parseSearchCSV(data)
		}
	}
	return result
}

// verify는 검증 작업들을 하나의 msfconsole 부팅에서 순차 실행한다.
// 각 작업 앞에 고유 마커(echo)를 찍어 출력에서 결과를 작업 인덱스에 귀속시킨다.
func (s *MSFSearchScanner) verify(ctx context.Context, tasks []verifyTask) map[int]checkOutcome {
	var b strings.Builder
	for i, t := range tasks {
		// 마커 → info(CVE 추출용) → 모듈 로드 → 대상 설정 → check(비침투 검증)
		fmt.Fprintf(&b, "echo ===RECON%d===; info %s; use %s; set RHOSTS %s; set RPORT %d; check; ",
			i, t.mod.fullName, t.mod.fullName, t.host, t.rport)
	}
	// exit는 실행기가 관리하므로 넣지 않는다(공유 세션을 닫지 않기 위해).

	out, err := s.runner.RunMSF(ctx, strings.TrimRight(b.String(), "; "))
	if err != nil {
		progressf(s.progress, "    - msf-search: 검증 실행 경고: %v\n", err)
	}
	return parseCheckOutput([]byte(out))
}

// sanitizeTerm은 검색어에서 명령 주입 위험 문자를 제거해 리소스 스크립트에 안전히 넣는다.
// 검색어는 nmap이 식별한 제품명에서 오지만, 방어적으로 영숫자·일부 기호만 허용한다.
func sanitizeTerm(term string) string {
	var b strings.Builder
	for _, r := range term {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
