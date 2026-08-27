package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// msfRunner는 msfconsole 명령 스크립트를 실행하고 출력을 반환하는 실행기이다.
// 구현으로는 프로그램 수명 동안 하나의 msfconsole을 유지하는 MSFSession(권장)과,
// 호출마다 새로 부팅하는 oneShotMSF(폴백)가 있다.
type msfRunner interface {
	// RunMSF는 스크립트(세미콜론으로 구분된 msf 명령들)를 실행하고 출력 텍스트를 반환한다.
	// 스크립트에 `exit`를 포함해서는 안 된다(세션 종료는 실행기가 관리한다).
	RunMSF(ctx context.Context, script string) (string, error)
}

// oneShotMSF는 호출마다 msfconsole을 새로 부팅해 명령을 실행하는 실행기이다.
// 공유 세션(MSFSession)을 시작하지 못했을 때의 폴백이며, 실행 후 `exit`으로 종료된다.
type oneShotMSF struct{ binary string }

// RunMSF는 msfconsole을 `-q -x <script>; exit`로 한 번 실행하고 출력을 반환한다.
func (o oneShotMSF) RunMSF(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, o.binary, "-q", "-x", script+"; exit")
	cmd.SysProcAttr = detachedProcAttr()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// MSFSession은 프로그램 수명 동안 하나의 msfconsole 프로세스를 유지하는 영속 세션이다.
// msfconsole은 부팅에 수십 초가 걸리므로, 매 명령마다 새로 켜는 대신 한 번만 켜서
// stdin으로 명령을 순차 전송하고 stdout에서 결과를 읽는다. 프로그램 종료 시 Close로 함께 종료한다.
//
// 명령 완료는 각 명령 뒤에 고유 마커(echo)를 붙여 그 마커가 출력에 나타날 때까지 읽어 감지한다.
// 세션은 단일 프로세스이므로 명령 실행은 뮤텍스로 직렬화된다.
type MSFSession struct {
	binary   string
	progress io.Writer

	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	outReader *bufio.Reader
	seq       int
	started   bool
}

// NewMSFSession은 MSFSession을 생성한다. binary가 비면 "msfconsole"을 사용한다.
func NewMSFSession(binary string) *MSFSession {
	if binary == "" {
		binary = "msfconsole"
	}
	return &MSFSession{binary: binary}
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (s *MSFSession) SetProgress(w io.Writer) { s.progress = w }

// Start는 msfconsole을 1회 부팅하고 준비될 때까지 기다린다(부팅에 수십 초 소요).
// ctx가 취소/만료되면 프로세스도 함께 종료되므로 세션 수명은 ctx에 묶인다.
func (s *MSFSession) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	cmd := exec.CommandContext(ctx, s.binary, "-q")
	cmd.SysProcAttr = detachedProcAttr()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.mu.Unlock()
		return err
	}
	cmd.Stderr = cmd.Stdout // 표준오류도 같은 파이프로 모아 함께 읽는다.
	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		return err
	}
	s.cmd = cmd
	s.stdin = stdin
	s.outReader = bufio.NewReader(stdout)
	s.started = true
	s.mu.Unlock()

	progressf(s.progress, "    - msfconsole 세션 시작(최초 1회 부팅, 수십 초 소요)...\n")
	// 빈 명령을 보내 마커까지 읽어 부팅 배너를 소진하고 준비 완료를 확인한다.
	if _, err := s.RunMSF(ctx, ""); err != nil {
		return fmt.Errorf("msfconsole 세션 준비 실패: %w", err)
	}
	progressf(s.progress, "    - msfconsole 세션 준비 완료\n")
	return nil
}

// RunMSF는 스크립트를 실행하고 고유 마커가 나타날 때까지의 출력을 반환한다.
// 명령 실행은 직렬화되며, 스크립트에 exit를 넣어서는 안 된다.
func (s *MSFSession) RunMSF(ctx context.Context, script string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return "", errors.New("msf 세션이 시작되지 않았습니다")
	}
	s.seq++
	marker := fmt.Sprintf("===RECONMARK%d===", s.seq)

	var b strings.Builder
	if strings.TrimSpace(script) != "" {
		b.WriteString(script)
		b.WriteString("\n")
	}
	b.WriteString("echo ")
	b.WriteString(marker)
	b.WriteString("\n")
	if _, err := io.WriteString(s.stdin, b.String()); err != nil {
		return "", err
	}
	return readUntilMarker(s.outReader, marker)
}

// Close는 세션에 exit를 보내 msfconsole을 정상 종료하고, 지연되면 강제 종료한다.
func (s *MSFSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return nil
	}
	s.started = false
	io.WriteString(s.stdin, "exit\n") // 정상 종료 요청
	s.stdin.Close()

	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-time.After(5 * time.Second):
		_ = s.cmd.Process.Kill() // 종료가 지연되면 강제 종료한다.
		<-done
	case <-done:
	}
	return nil
}

// readUntilMarker는 리더에서 마커 줄이 나올 때까지 읽어 그 이전까지의 출력을 반환한다.
// ANSI 색상 코드와 공백을 제거한 줄이 marker와 정확히 일치하면 종료로 판단한다.
// 실행 로직과 분리해 단위 테스트가 가능하도록 별도 함수로 둔다.
func readUntilMarker(r *bufio.Reader, marker string) (string, error) {
	var out strings.Builder
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			clean := strings.TrimSpace(ansiPattern.ReplaceAllString(line, ""))
			if clean == marker {
				return out.String(), nil
			}
			out.WriteString(line)
		}
		if err != nil {
			return out.String(), err // EOF 또는 파이프 종료(프로세스 종료)
		}
	}
}
