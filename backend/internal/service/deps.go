package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// installMethod는 도구를 자동 설치하는 방식을 정의한다.
type installMethod struct {
	// apt가 비어 있지 않으면 apt 패키지명으로 apt-get 설치를 시도한다.
	apt string
	// goPkg가 비어 있지 않으면 `go install goPkg`로 설치를 시도한다.
	goPkg string
}

// installMethods는 각 도구의 자동 설치 방식을 정의한다.
// 설치 절차가 복잡한 도구(msfconsole)는 여기에 두지 않고 InstallHint로만 안내한다.
var installMethods = map[string]installMethod{
	"nmap":   {apt: "nmap"},
	"nuclei": {goPkg: "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
}

// aptAvailable은 apt-get을 사용할 수 있는 환경(리눅스 + apt-get 존재)인지 확인한다.
func aptAvailable() bool {
	return runtime.GOOS == "linux" && ToolAvailable("apt-get")
}

// ToolAvailable은 지정한 실행 파일이 PATH에 존재하는지 확인한다.
func ToolAvailable(binary string) bool {
	_, err := exec.LookPath(binary)
	return err == nil
}

// CanAutoInstall은 해당 도구를 이 환경에서 자동 설치할 수 있는지 반환한다.
func CanAutoInstall(tool string) bool {
	m, ok := installMethods[tool]
	if !ok {
		return false
	}
	if m.apt != "" && aptAvailable() {
		return true
	}
	if m.goPkg != "" && ToolAvailable("go") {
		return true
	}
	return false
}

// InstallHint는 도구가 없을 때 사용자에게 안내할 수동 설치 방법을 반환한다.
func InstallHint(tool string) string {
	switch tool {
	case "nmap":
		return "sudo apt-get install -y nmap  (또는 brew install nmap / sudo dnf install -y nmap)"
	case "nuclei":
		return "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
	case "msfconsole":
		return "https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html 참고"
	default:
		return tool + " 설치가 필요합니다."
	}
}

// InstallTool은 지원되는 방식(apt 우선, 없으면 go install)으로 도구를 설치한다.
// sudo가 필요할 수 있어 대화형 셸에서 비밀번호를 물을 수 있으며,
// 지원되지 않는 환경/도구는 InstallHint를 포함한 오류를 반환한다.
func InstallTool(ctx context.Context, tool string) error {
	m, ok := installMethods[tool]
	if !ok {
		return fmt.Errorf("%s 자동 설치는 지원되지 않습니다: %s", tool, InstallHint(tool))
	}

	switch {
	case m.apt != "" && aptAvailable():
		if err := aptInstall(ctx, m.apt); err != nil {
			return fmt.Errorf("%s 설치 실패: %w", tool, err)
		}
	case m.goPkg != "" && ToolAvailable("go"):
		if err := goInstall(ctx, m.goPkg); err != nil {
			return fmt.Errorf("%s 설치 실패: %w", tool, err)
		}
	default:
		return fmt.Errorf("이 환경에서는 %s 자동 설치가 불가능합니다: %s", tool, InstallHint(tool))
	}

	if !ToolAvailable(tool) {
		return fmt.Errorf("%s 설치를 마쳤으나 PATH에서 찾을 수 없습니다(go install의 경우 $(go env GOPATH)/bin 을 PATH에 추가하세요)", tool)
	}
	return nil
}

// aptInstall은 apt-get으로 패키지를 설치한다. 목록 갱신 실패는 무시하고 설치를 시도한다.
func aptInstall(ctx context.Context, pkg string) error {
	update := exec.CommandContext(ctx, "sudo", "apt-get", "update")
	update.Stdout, update.Stderr = os.Stderr, os.Stderr
	_ = update.Run()

	install := exec.CommandContext(ctx, "sudo", "apt-get", "install", "-y", pkg)
	install.Stdin, install.Stdout, install.Stderr = os.Stdin, os.Stderr, os.Stderr
	return install.Run()
}

// goInstall은 `go install`로 Go 기반 도구를 설치한다.
func goInstall(ctx context.Context, pkg string) error {
	install := exec.CommandContext(ctx, "go", "install", pkg)
	install.Stdout, install.Stderr = os.Stderr, os.Stderr
	return install.Run()
}
