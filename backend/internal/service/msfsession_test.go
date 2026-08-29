package service

import (
	"bufio"
	"context"
	"strings"
	"testing"
)

// fakeRunner는 스크립트를 받아 미리 지정한 출력을 돌려주는 msfRunner 가짜 구현이다.
type fakeRunner struct {
	fn func(cmds []string) (string, error)
}

func (f fakeRunner) RunMSF(_ context.Context, cmds []string) (string, error) { return f.fn(cmds) }

// TestReadUntilMarker는 마커 줄 전까지의 출력을 반환하고, ANSI 코드가 섞인 마커도 인식하는지 검증한다.
func TestReadUntilMarker(t *testing.T) {
	input := "line1\n" +
		"[*] exec: echo ===RECONMARK1===\n" + // 마커의 echo 실행 줄(마커 자체 아님)
		"line2\n" +
		"\x1b[0m===RECONMARK1===\x1b[0m\n" + // 색상 코드가 붙은 실제 마커 줄
		"after\n"
	r := bufio.NewReader(strings.NewReader(input))

	out, err := readUntilMarker(r, "===RECONMARK1===")
	if err != nil {
		t.Fatalf("예상치 못한 오류: %v", err)
	}
	if !strings.Contains(out, "line1") || !strings.Contains(out, "line2") {
		t.Errorf("마커 이전 출력이 누락됨: %q", out)
	}
	if strings.Contains(out, "after") {
		t.Errorf("마커 이후 출력이 포함됨: %q", out)
	}
	// "exec: echo" 줄은 마커 자체가 아니므로 종료 트리거가 되면 안 되고, 출력에 남아야 한다.
	if !strings.Contains(out, "exec: echo") {
		t.Errorf("echo 실행 줄이 마커로 오인됨: %q", out)
	}
}

// TestReadUntilMarker_EOF는 마커 없이 스트림이 끝나면 지금까지의 출력과 함께 오류를 반환하는지 검증한다.
func TestReadUntilMarker_EOF(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("partial output\nno marker here\n"))
	out, err := readUntilMarker(r, "===NOPE===")
	if err == nil {
		t.Error("EOF에서 오류를 기대했으나 nil")
	}
	if !strings.Contains(out, "partial output") {
		t.Errorf("EOF까지의 출력이 반환되어야 함: %q", out)
	}
}
