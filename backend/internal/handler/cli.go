// Package handler는 CLI 입력을 처리하고 점검 실행을 조율한다.
package handler

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rikychoi/recon/internal/model"
	"github.com/rikychoi/recon/internal/service"
)

// Options는 CLI 실행 옵션을 담는다.
type Options struct {
	Domain      string        // 점검 대상 도메인
	Format      string        // 출력 형식 (text|json)
	Timeout     time.Duration // 전체 점검 제한 시간
	Nmap        bool          // nmap 포트 스캔 활성화(외부 nmap 사용)
	Portscan    bool          // 내장 고루틴 TCP 포트 스캔 활성화(외부 도구 불필요)
	Nuclei      bool          // nuclei 취약점 점검 활성화
	MSF         bool          // metasploit 취약점 점검 활성화(고정 카탈로그 + 실제 익스플로잇)
	MSFSearch   bool          // metasploit 동적 모듈 검색 점검 활성화(제품→모듈 search + check 검증)
	Full        bool          // 자산 식별 → 포트 스캔 → 취약점 점검 전체 파이프라인 실행
	AllowPublic bool          // 공인(외부) IP 대상 스캔 허용(기본 false=차단)
	Enrich      bool          // 발견된 취약점에 CVE 보강(EPSS/KEV) 적용(기본 true)
	NVD         bool          // CVSS가 비어 있는 취약점을 NVD로 보강(기본 false, 레이트 제한)
	Takeover    bool          // 서브도메인 탈취(댕글링 CNAME) 탐지(기본 true)
}

// Run은 명령행 인자를 파싱하여 점검을 실행하고 결과를 출력한다.
// 반환값은 프로세스 종료 코드이다(0=성공, 1=실행 오류, 2=사용법 오류).
func Run(args []string) int {
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	var opts Options
	fs.StringVar(&opts.Domain, "domain", "", "점검 대상 도메인 (필수)")
	fs.StringVar(&opts.Format, "format", "text", "출력 형식 (text|json)")
	fs.DurationVar(&opts.Timeout, "timeout", 5*time.Minute, "전체 점검 제한 시간")
	fs.BoolVar(&opts.Nmap, "nmap", false, "nmap 포트 스캔 활성화(외부 nmap 사용)")
	fs.BoolVar(&opts.Portscan, "portscan", false, "내장 고루틴 TCP 포트 스캔 활성화(외부 도구 불필요)")
	fs.BoolVar(&opts.Nuclei, "nuclei", false, "nuclei 취약점 점검 활성화")
	fs.BoolVar(&opts.MSF, "msf", false, "metasploit 고정 카탈로그 점검(실제 익스플로잇 시도, 격리 환경 전용)")
	fs.BoolVar(&opts.MSFSearch, "msf-search", false, "metasploit 동적 모듈 검색 점검(감지된 제품 → search로 모듈 발굴 → check로 안전 검증). -nmap과 함께 쓰면 정밀. -full에 포함됨")
	fs.BoolVar(&opts.Full, "full", false, "자산 식별부터 포트 스캔까지 포함한 전체 파이프라인 실행 (내장 포트 스캔 + nuclei + metasploit)")
	fs.BoolVar(&opts.AllowPublic, "allow-public", false, "공인(외부) IP 대상 스캔 허용 (기본: 사설/로컬 IP만 스캔, 공인 IP는 경고 후 제외)")
	fs.BoolVar(&opts.Enrich, "enrich", true, "발견된 취약점에 CVE 보강(EPSS 악용확률/CISA KEV) 적용 (외부 API 조회)")
	fs.BoolVar(&opts.NVD, "nvd", false, "NVD 연동: msf-search에서 CPE(버전)→CVE 목록으로 모듈을 정밀 검색하고, CVSS 없는 취약점을 NVD로 보강 (레이트 제한이 있어 기본 비활성)")
	fs.BoolVar(&opts.Takeover, "takeover", true, "서브도메인 탈취(댕글링 CNAME) 탐지 (DNS 조회만 수행)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if opts.Domain == "" {
		fmt.Fprintln(os.Stderr, "오류: -domain 옵션은 필수입니다.")
		fs.Usage()
		return 2
	}

	formatter, err := model.NewFormatter(opts.Format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	// 활성화된 외부 도구가 설치되어 있는지 점검하고, 없으면 설치를 안내/시도한다.
	ensureTools(ctx, opts, os.Stdin, os.Stderr)

	// 진행 상황은 결과(stdout)와 분리하여 stderr로 실시간 출력한다.
	// cleanup은 공유 msfconsole 세션 등 프로그램 수명 자원을 종료 시 함께 정리한다.
	orch, cleanup := buildOrchestrator(ctx, opts, os.Stderr)
	defer cleanup()

	// 자산 식별 → 취약점 점검으로 이어지는 전체 흐름을 한 번의 호출로 실행한다.
	result, err := orch.Run(ctx, opts.Domain)
	if err != nil {
		fmt.Fprintln(os.Stderr, "점검 실패:", err)
		return 1
	}

	if err := formatter.Format(os.Stdout, result); err != nil {
		fmt.Fprintln(os.Stderr, "출력 실패:", err)
		return 1
	}
	return 0
}

// buildOrchestrator는 옵션에 따라 자산 식별 스캐너와 취약점 스캐너를 조립한다.
// -full은 사용 가능한 모든 취약점 스캐너(nuclei + metasploit)를 활성화한다.
// progress는 진행 상황 출력 대상이다(보통 os.Stderr). 각 스캐너와 오케스트레이터에 주입한다.
// 반환하는 cleanup 함수는 공유 msfconsole 세션 등 프로그램 수명 동안 유지되는 자원을 종료한다(없으면 no-op).
func buildOrchestrator(ctx context.Context, opts Options, progress io.Writer) (*service.Orchestrator, func()) {
	useNmap := opts.Nmap // -full은 외부 도구가 필요 없는 내장 TCP 스캐너를 사용한다
	useNuclei := opts.Nuclei || opts.Full
	useMSF := opts.MSF                          // 고정 카탈로그(실제 익스플로잇)는 명시적 -msf에서만
	useMSFSearch := opts.MSFSearch || opts.Full // 동적 검색(안전 검증)은 -full의 기본 msf 방식

	// PATH에 없어도 go install 위치(GOPATH/bin) 등에서 실행 파일을 찾아 전체 경로로 실행한다.
	var scanners []service.VulnerabilityScanner
	if useNuclei {
		s := service.NewNucleiScanner(service.ToolPath("nuclei"))
		s.SetProgress(progress)
		scanners = append(scanners, s)
	}
	var catalogScanner *service.MetasploitScanner
	if useMSF {
		catalogScanner = service.NewMetasploitScanner(service.ToolPath("msfconsole"))
		catalogScanner.SetProgress(progress)
		scanners = append(scanners, catalogScanner)
	}
	var searchScanner *service.MSFSearchScanner
	if useMSFSearch {
		// 감지된 제품으로 msf 모듈을 동적 검색하고 check로 안전 검증한다("서비스 인식 → 적용 취약점 검색").
		searchScanner = service.NewMSFSearchScanner(service.ToolPath("msfconsole"))
		searchScanner.SetProgress(progress)
		// -nvd 지정 시: CPE(버전) → NVD로 CVE 목록 조회 → 그 CVE로 모듈 검색(버전 정밀). 없으면 제품명 검색.
		if opts.NVD {
			res := service.NewNVDResolver(nil)
			res.SetProgress(progress)
			searchScanner.SetCVEResolver(res)
		}
		scanners = append(scanners, searchScanner)
	}

	// 취약점 스캐너가 하나 이상이면 MultiScanner로 묶어 순차 적용한다.
	var vulnScanner service.VulnerabilityScanner
	if len(scanners) > 0 {
		vulnScanner = service.NewMultiScanner(scanners...)
	}

	// 포트 스캔 엔진 선택: -nmap이 지정되면 외부 nmap을,
	// 그 외 -portscan/-full이면 외부 도구가 필요 없는 내장 고루틴 TCP 스캐너를 사용한다.
	var portScanner service.PortScanner
	switch {
	case useNmap:
		ns := service.NewNmapScanner(service.ToolPath("nmap"))
		ns.SetProgress(progress)
		portScanner = ns
	case opts.Portscan || opts.Full:
		ts := service.NewTCPPortScanner(nil, 100)
		ts.SetProgress(progress)
		portScanner = ts
	}

	orch := service.NewOrchestratorWithPortScan(
		service.NewNetDNSResolver(),
		service.NewBruteSubdomainScanner(nil, 20),
		portScanner,
		vulnScanner,
	)
	orch.SetProgress(progress)
	orch.SetAllowPublic(opts.AllowPublic)

	// 서브도메인 탈취 탐지: HTTP 없이 DNS만으로 판정하므로 기본 활성이며 비용이 낮다.
	if opts.Takeover {
		td := service.NewTakeoverScanner(nil, nil)
		td.SetProgress(progress)
		orch.SetTakeover(td)
	}

	// CVE 보강: 발견된 취약점에 EPSS(악용 확률)·CISA KEV(실제 악용)와 선택적으로 NVD CVSS를 채운다.
	if opts.Enrich {
		en := service.NewCVEEnricher(nil, opts.NVD)
		en.SetProgress(progress)
		orch.SetEnricher(en)
	}

	// 공유 msfconsole 세션: msf 기반 스캐너(카탈로그/동적검색)가 하나라도 활성이면
	// msfconsole을 프로그램당 1회만 부팅해 유지하고 모든 msf 스캐너가 이 세션을 공유한다.
	// (매 명령·모듈마다 새로 부팅하던 낭비를 없앤다.) 시작 실패 시 개별 부팅(폴백)으로 동작한다.
	cleanup := func() {}
	if catalogScanner != nil || searchScanner != nil {
		sess := service.NewMSFSession(service.ToolPath("msfconsole"))
		sess.SetProgress(progress)
		if err := sess.Start(ctx); err == nil {
			if catalogScanner != nil {
				catalogScanner.SetSession(sess)
			}
			if searchScanner != nil {
				searchScanner.SetSession(sess)
			}
			cleanup = func() { sess.Close() } // 프로그램 종료 시 세션도 함께 종료한다.
		} else {
			fmt.Fprintf(progress, "[!] msfconsole 세션 시작 실패(개별 실행으로 대체): %v\n", err)
		}
	}
	return orch, cleanup
}

// requiredTool은 활성화된 옵션과 그에 필요한 외부 도구(실행 파일)를 짝지은 것이다.
type requiredTool struct {
	enabled bool
	binary  string
}

// ensureTools는 활성화된 단계에 필요한 외부 도구의 설치 여부를 확인한다.
// 설치되어 있지 않으면 경고를 출력하고, 자동 설치가 가능한 도구는 사용자에게 물어본 뒤 설치한다.
// out은 안내/프롬프트 출력 대상, in은 사용자 응답 입력 대상이다(테스트 주입용).
func ensureTools(ctx context.Context, opts Options, in io.Reader, out io.Writer) {
	tools := []requiredTool{
		{opts.Nmap, "nmap"},
		{opts.Nuclei || opts.Full, "nuclei"},
		{opts.MSF || opts.MSFSearch || opts.Full, "msfconsole"},
	}

	for _, t := range tools {
		if !t.enabled || service.ToolAvailable(t.binary) {
			continue // 사용하지 않거나 이미 설치된 도구는 건너뛴다.
		}

		fmt.Fprintf(out, "경고: %s 가 설치되어 있지 않아 해당 단계를 건너뜁니다.\n", t.binary)

		// 자동 설치가 가능하고 대화형 입력이 가능하면 설치 여부를 물어본다.
		if service.CanAutoInstall(t.binary) && isInteractive() {
			if promptYesNo(in, out, fmt.Sprintf("%s 를 지금 설치할까요? [y/N]: ", t.binary)) {
				if err := service.InstallTool(ctx, t.binary); err != nil {
					fmt.Fprintf(out, "설치 실패: %v\n", err)
				} else {
					fmt.Fprintf(out, "%s 설치 완료.\n", t.binary)
				}
				continue
			}
		}
		// 설치하지 않았거나 자동 설치가 불가능한 경우 수동 설치 방법을 안내한다.
		fmt.Fprintf(out, "설치 방법: %s\n", service.InstallHint(t.binary))
	}
}

// isInteractive는 표준 입력이 터미널(문자 장치)인지 확인한다.
// 파이프/리다이렉트 등 비대화형 실행에서는 설치 프롬프트로 멈추지 않도록 한다.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// promptYesNo는 사용자에게 예/아니오를 물어 y 또는 yes 응답일 때만 true를 반환한다.
func promptYesNo(in io.Reader, out io.Writer, question string) bool {
	fmt.Fprint(out, question)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
