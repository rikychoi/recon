package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"

	"github.com/rikychoi/recon/internal/model"
)

// NucleiScanner는 Nuclei CLI를 실행하여 취약점을 점검하는 VulnerabilityScanner 구현이다.
// binary를 "docker"로 지정하고 extra에 실행 인자를 넘기면 Docker 컨테이너로도 실행할 수 있다.
type NucleiScanner struct {
	binary   string    // 실행할 바이너리 경로 (기본 "nuclei")
	extra    []string  // 추가 CLI 인자 (템플릿 경로, 레이트 제한 등)
	progress io.Writer // 진행 상황 출력 대상(nil이면 미출력)
}

// NewNucleiScanner는 NucleiScanner를 생성한다. binary가 비면 "nuclei"를 사용한다.
func NewNucleiScanner(binary string, extra ...string) *NucleiScanner {
	if binary == "" {
		binary = "nuclei"
	}
	return &NucleiScanner{binary: binary, extra: extra}
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (n *NucleiScanner) SetProgress(w io.Writer) {
	n.progress = w
}

// nucleiResult는 nuclei의 -jsonl 출력 중 필요한 필드만 담는 구조체이다.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	Info       struct {
		Name           string `json:"name"`
		Severity       string `json:"severity"`
		Classification struct {
			CVSSScore float64 `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
}

// Scan은 열린 포트 목록에 대해 nuclei를 실행하고 JSONL 출력을 파싱하여 취약점을 수집한다.
// 각 포트를 host:port 대상으로 넘기며(Number 0이면 host만), nuclei가 http/https를 자동 판별한다.
func (n *NucleiScanner) Scan(ctx context.Context, targets []model.Port) ([]model.Vulnerability, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-jsonl", "-silent"}
	for _, p := range targets {
		target := p.Target
		if p.Number > 0 {
			target = net.JoinHostPort(p.Target, strconv.Itoa(p.Number))
		}
		args = append(args, "-target", target)
	}
	args = append(args, n.extra...)

	progressf(n.progress, "    - nuclei 실행 (대상 %d개, 템플릿 스캔 중)...\n", len(targets))
	cmd := exec.CommandContext(ctx, n.binary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("nuclei 실행 실패(설치 여부를 확인하세요): %w", err)
	}

	vulns := parseNucleiLines(stdout)
	// nuclei는 취약점 발견 시 비정상 종료 코드를 반환할 수 있으므로 Wait 오류는 무시한다.
	_ = cmd.Wait()
	return vulns, nil
}

// parseNucleiLines는 nuclei의 JSONL 출력(줄 단위 JSON)을 취약점 목록으로 변환한다.
// 실행 로직과 분리하여 단위 테스트가 가능하도록 별도 함수로 둔다.
func parseNucleiLines(r io.Reader) []model.Vulnerability {
	var vulns []model.Vulnerability
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var nr nucleiResult
		if err := json.Unmarshal(scanner.Bytes(), &nr); err != nil {
			continue // 파싱 불가한 줄(진행 로그 등)은 건너뛴다.
		}
		cvss := nr.Info.Classification.CVSSScore
		severity := nr.Info.Severity
		if severity == "" {
			severity = model.SeverityFromCVSS(cvss)
		}
		vulns = append(vulns, model.Vulnerability{
			ID:       nr.TemplateID,
			Name:     nr.Info.Name,
			Target:   nr.Host,
			CVSS:     cvss,
			Severity: severity,
			Source:   "nuclei",
		})
	}
	return vulns
}
