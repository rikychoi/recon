package handler

import (
	"bytes"
	"strings"
	"testing"
)

// TestPromptYesNo는 다양한 사용자 응답에 대한 예/아니오 판별을 검증한다.
func TestPromptYesNo(t *testing.T) {
	cases := map[string]bool{
		"y\n":   true,
		"Y\n":   true,
		"yes\n": true,
		"n\n":   false,
		"\n":    false,
		"":      false, // EOF(빈 입력)는 아니오로 처리한다.
	}
	for input, want := range cases {
		var out bytes.Buffer
		got := promptYesNo(strings.NewReader(input), &out, "질문: ")
		if got != want {
			t.Errorf("입력 %q: got %v, want %v", input, got, want)
		}
		if !strings.Contains(out.String(), "질문: ") {
			t.Errorf("입력 %q: 프롬프트 문구가 출력되지 않았다", input)
		}
	}
}

// TestEnsureToolsSkipsDisabled은 비활성 도구에 대해 아무 경고도 내지 않는지 검증한다.
func TestEnsureToolsSkipsDisabled(t *testing.T) {
	var out bytes.Buffer
	// 모든 옵션이 꺼져 있으면 어떤 도구도 확인하지 않는다.
	ensureTools(nil, Options{}, strings.NewReader(""), &out)
	if out.Len() != 0 {
		t.Fatalf("비활성 옵션인데 출력이 발생했다: %q", out.String())
	}
}
