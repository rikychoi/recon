// Package handler는 CLI 입력을 처리하고 점검 실행을 조율한다.
package handler

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rikychoi/recon/internal/model"
	"github.com/rikychoi/recon/internal/service"
)

// Options는 CLI 실행 옵션을 담는다.
type Options struct {
	Domain  string        // 점검 대상 도메인
	Format  string        // 출력 형식 (text|json)
	Timeout time.Duration // 전체 점검 제한 시간
	Nmap    bool          // nmap 포트 스캔 활성화
	Nuclei  bool          // nuclei 취약점 점검 활성화
	MSF     bool          // metasploit 취약점 점검 활성화
	Full    bool          // 자산 식별 → 포트 스캔 → 취약점 점검 전체 파이프라인 실행
}

// Run은 명령행 인자를 파싱하여 점검을 실행하고 결과를 출력한다.
// 반환값은 프로세스 종료 코드이다(0=성공, 1=실행 오류, 2=사용법 오류).
func Run(args []string) int {
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	var opts Options
	fs.StringVar(&opts.Domain, "domain", "", "점검 대상 도메인 (필수)")
	fs.StringVar(&opts.Format, "format", "text", "출력 형식 (text|json)")
	fs.DurationVar(&opts.Timeout, "timeout", 5*time.Minute, "전체 점검 제한 시간")
	fs.BoolVar(&opts.Nmap, "nmap", false, "nmap 포트 스캔 활성화")
	fs.BoolVar(&opts.Nuclei, "nuclei", false, "nuclei 취약점 점검 활성화")
	fs.BoolVar(&opts.MSF, "msf", false, "metasploit 취약점 점검 활성화")
	fs.BoolVar(&opts.Full, "full", false, "자산 식별부터 포트 스캔까지 포함한 전체 파이프라인 실행 (nmap + nuclei + metasploit)")
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

	orch := buildOrchestrator(opts)

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

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
func buildOrchestrator(opts Options) *service.Orchestrator {
	useNmap := opts.Nmap || opts.Full
	useNuclei := opts.Nuclei || opts.Full
	useMSF := opts.MSF || opts.Full

	var scanners []service.VulnerabilityScanner
	if useNuclei {
		scanners = append(scanners, service.NewNucleiScanner(""))
	}
	if useMSF {
		scanners = append(scanners, service.NewMetasploitScanner(""))
	}

	// 취약점 스캐너가 하나 이상이면 MultiScanner로 묶어 순차 적용한다.
	var vulnScanner service.VulnerabilityScanner
	if len(scanners) > 0 {
		vulnScanner = service.NewMultiScanner(scanners...)
	}

	var portScanner service.PortScanner
	if useNmap {
		portScanner = service.NewNmapScanner("")
	}

	return service.NewOrchestratorWithPortScan(
		service.NewNetDNSResolver(),
		service.NewBruteSubdomainScanner(nil, 20),
		portScanner,
		vulnScanner,
	)
}
