package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// TestProgressfNilWriter는 Writer가 nil일 때 아무 출력/패닉이 없는지 검증한다.
func TestProgressfNilWriter(t *testing.T) {
	// nil Writer로 호출해도 패닉하지 않아야 한다.
	progressf(nil, "무시되는 메시지 %d\n", 1)
}

// TestProgressfWritesFormatted는 Writer가 주어지면 서식화된 문자열을 출력하는지 검증한다.
func TestProgressfWritesFormatted(t *testing.T) {
	var buf bytes.Buffer
	progressf(&buf, "값=%d\n", 42)
	if got := buf.String(); got != "값=42\n" {
		t.Fatalf("예상과 다른 출력: %q", got)
	}
}

// TestOrchestratorProgress는 SetProgress 지정 시 각 단계의 진행 로그가 출력되는지 검증한다.
func TestOrchestratorProgress(t *testing.T) {
	dns := fakeDNS{records: []model.DNSRecord{{Type: "A", Name: "x", Value: "1.1.1.1"}}}
	subs := fakeSubs{subs: []model.Subdomain{{Name: "www.x"}}}
	ports := &recordingPorts{}
	vuln := &recordingVuln{}

	orch := NewOrchestratorWithPortScan(dns, subs, ports, vuln)
	var buf bytes.Buffer
	orch.SetProgress(&buf)

	if _, err := orch.Run(context.Background(), "x"); err != nil {
		t.Fatalf("Run 실패: %v", err)
	}

	out := buf.String()
	// 시작/완료 및 각 단계 로그가 포함되어야 한다.
	for _, want := range []string{"점검 시작", "DNS", "서브도메인", "[포트]", "[취약점]", "점검 완료"} {
		if !strings.Contains(out, want) {
			t.Errorf("진행 로그에 %q 가 없다:\n%s", want, out)
		}
	}
}

// TestOrchestratorProgressDisabled는 SetProgress 미지정 시 진행 로그가 출력되지 않는지 검증한다.
func TestOrchestratorProgressDisabled(t *testing.T) {
	orch := NewOrchestrator(fakeDNS{}, fakeSubs{}, &recordingVuln{})
	// progress 미지정 상태에서 실행해도 패닉 없이 정상 동작해야 한다.
	if _, err := orch.Run(context.Background(), "x"); err != nil {
		t.Fatalf("Run 실패: %v", err)
	}
}
