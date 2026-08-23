package service

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"

	"github.com/rikychoi/recon/internal/model"
)

// MSFModule은 실행할 Metasploit 모듈과 그에 연관된 취약점 메타데이터를 정의한다.
type MSFModule struct {
	Name     string  // 모듈 경로 (예: auxiliary/scanner/http/http_version)
	CVE      string  // 연관 CVE 식별자 (있으면)
	CVSS     float64 // 연관 CVSS 점수 (알 수 없으면 0)
	Severity string  // 심각도 등급 (비면 CVSS로부터 추론)
}

// DefaultMSFModules는 기본으로 실행할 안전한 정보 수집용 모듈 집합이다.
// 실제 취약점 검증 모듈은 대상 특성에 맞게 호출 측에서 추가한다.
var DefaultMSFModules = []MSFModule{
	{Name: "auxiliary/scanner/http/http_version", CVSS: 0},
}

// MetasploitScanner는 msfconsole을 실행하여 취약점을 점검하는 VulnerabilityScanner 구현이다.
// 각 모듈을 개별 msfconsole 세션으로 실행하여 결과 귀속을 단순화한다.
type MetasploitScanner struct {
	binary  string      // msfconsole 경로 (기본 "msfconsole")
	modules []MSFModule // 실행할 모듈 목록
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
	return &MetasploitScanner{binary: binary, modules: modules}
}

// buildResourceScript는 지정한 모듈을 대상(rhosts)에 대해 실행하는 msfconsole 리소스 명령을 만든다.
func buildResourceScript(module, rhosts string) string {
	return "use " + module + "; set RHOSTS " + rhosts + "; run; exit"
}

// Scan은 설정된 각 모듈을 대상 목록에 대해 실행하고 긍정 결과([+])를 취약점으로 수집한다.
func (m *MetasploitScanner) Scan(ctx context.Context, targets []string) ([]model.Vulnerability, error) {
	if len(targets) == 0 || len(m.modules) == 0 {
		return nil, nil
	}

	rhosts := strings.Join(targets, " ")
	var vulns []model.Vulnerability
	for _, mod := range m.modules {
		script := buildResourceScript(mod.Name, rhosts)
		cmd := exec.CommandContext(ctx, m.binary, "-q", "-x", script)
		// msfconsole이 부모 터미널을 raw 모드로 바꿔 입력이 먹통이 되는 것을 막기 위해
		// 자식 프로세스를 제어 터미널에서 분리한다.
		cmd.SysProcAttr = detachedProcAttr()
		out, err := cmd.Output()
		if err != nil {
			continue // 개별 모듈 실행 실패는 건너뛰고 다음 모듈을 진행한다.
		}
		vulns = append(vulns, parseMSFOutput(bytes.NewReader(out), mod)...)
	}
	return vulns, nil
}

// parseMSFOutput은 msfconsole 출력에서 [+] 긍정 결과 줄을 취약점으로 변환한다.
// 실행 로직과 분리하여 단위 테스트가 가능하도록 별도 함수로 둔다.
func parseMSFOutput(r io.Reader, mod MSFModule) []model.Vulnerability {
	var vulns []model.Vulnerability
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "[+]") {
			continue // 긍정 결과([+]) 줄만 취약점으로 취급한다.
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
