package service

import (
	"context"
	"testing"
)

// TestToolAvailable은 존재하는/존재하지 않는 실행 파일 판별을 검증한다.
func TestToolAvailable(t *testing.T) {
	// go 테스트 환경에는 "go" 바이너리가 항상 존재한다.
	if !ToolAvailable("go") {
		t.Fatalf("go 바이너리를 찾지 못했다")
	}
	if ToolAvailable("definitely-not-a-real-binary-xyz") {
		t.Fatalf("존재하지 않는 바이너리를 존재한다고 판별했다")
	}
}

// TestInstallHint는 알려진 도구와 미지의 도구에 대한 안내 문구를 검증한다.
func TestInstallHint(t *testing.T) {
	if InstallHint("nmap") == "" {
		t.Fatalf("nmap 설치 안내가 비어 있다")
	}
	if got := InstallHint("unknown-tool"); got == "" {
		t.Fatalf("미지 도구에 대한 기본 안내가 비어 있다")
	}
}

// TestInstallToolUnsupported는 자동 설치가 지원되지 않는 도구에 오류를 반환하는지 검증한다.
func TestInstallToolUnsupported(t *testing.T) {
	// msfconsole은 설치 절차가 복잡하여 자동 설치 대상이 아니다.
	if err := InstallTool(context.Background(), "msfconsole"); err == nil {
		t.Fatalf("msfconsole 자동 설치는 지원되지 않아야 하는데 오류가 없다")
	}
}

// TestToolPath는 PATH에 있는 도구의 전체 경로를 반환하고, 없는 도구는 빈 문자열을 반환하는지 검증한다.
func TestToolPath(t *testing.T) {
	if p := ToolPath("go"); p == "" {
		t.Fatalf("go 실행 파일의 경로를 찾지 못했다")
	}
	if p := ToolPath("definitely-not-a-real-binary-xyz"); p != "" {
		t.Fatalf("존재하지 않는 도구인데 경로 %q 를 반환했다", p)
	}
}
