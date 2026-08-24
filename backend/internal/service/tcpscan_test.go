package service

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rikychoi/recon/internal/model"
)

// fakeConn은 테스트에서 성공한 연결을 흉내 내는 최소 net.Conn 구현이다.
type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

// newFakeDial은 openPorts에 포함된 포트만 연결에 성공하는 dialFunc를 만든다.
// calls에는 시도 횟수를 누적하여 병렬 실행/전수 점검 여부를 검증한다.
func newFakeDial(openPorts map[int]bool, calls *int64) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		atomic.AddInt64(calls, 1)
		_, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port := 0
		for _, c := range portStr {
			port = port*10 + int(c-'0')
		}
		if openPorts[port] {
			return fakeConn{}, nil
		}
		return nil, errors.New("connection refused")
	}
}

// TestTCPPortScanner_OpenPorts는 열린 포트만 결과에 포함되고,
// 모든 대상×포트 조합을 빠짐없이 시도하는지 확인한다.
func TestTCPPortScanner_OpenPorts(t *testing.T) {
	var calls int64
	openPorts := map[int]bool{80: true, 443: true}

	s := NewTCPPortScanner([]int{22, 80, 443, 8080}, 10)
	s.dial = newFakeDial(openPorts, &calls)

	targets := []string{"a.example.com", "b.example.com"}
	ports, err := s.Scan(context.Background(), targets)
	if err != nil {
		t.Fatalf("Scan 오류: %v", err)
	}

	// 대상 2개 × 열린 포트 2개 = 4건이 열린 포트로 나와야 한다.
	if len(ports) != 4 {
		t.Fatalf("열린 포트 수 = %d, 기대값 4 (%+v)", len(ports), ports)
	}

	// 전체 조합(2×4=8)을 모두 시도했는지 확인한다.
	if calls != 8 {
		t.Fatalf("연결 시도 횟수 = %d, 기대값 8", calls)
	}

	// 결과가 대상·포트 순으로 정렬되어 있는지 확인한다.
	for i := 1; i < len(ports); i++ {
		prev, cur := ports[i-1], ports[i]
		if prev.Target > cur.Target || (prev.Target == cur.Target && prev.Number > cur.Number) {
			t.Fatalf("정렬되지 않음: %+v", ports)
		}
	}

	// 열린 포트는 상태/프로토콜/서비스명이 채워져야 한다.
	for _, p := range ports {
		if p.State != "open" || p.Protocol != "tcp" {
			t.Errorf("예상치 못한 포트 필드: %+v", p)
		}
		if p.Number == 80 && p.Service != "http" {
			t.Errorf("80 포트 서비스명 = %q, 기대값 http", p.Service)
		}
	}
}

// TestTCPPortScanner_Empty는 대상이 없으면 nil을 반환하는지 확인한다.
func TestTCPPortScanner_Empty(t *testing.T) {
	s := NewTCPPortScanner(nil, 10)
	ports, err := s.Scan(context.Background(), nil)
	if err != nil || ports != nil {
		t.Fatalf("빈 대상 결과 = (%v, %v), 기대값 (nil, nil)", ports, err)
	}
}

// TestTCPPortScanner_ContextCancel은 취소된 컨텍스트에서 즉시 중단하는지 확인한다.
func TestTCPPortScanner_ContextCancel(t *testing.T) {
	var calls int64
	s := NewTCPPortScanner(defaultTCPPorts, 5)
	s.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		atomic.AddInt64(&calls, 1)
		return nil, errors.New("refused")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 즉시 취소

	done := make(chan []model.Port, 1)
	go func() {
		ports, _ := s.Scan(ctx, []string{"x.example.com", "y.example.com"})
		done <- ports
	}()

	select {
	case <-done:
		// 취소 시 결과 없이 신속히 반환되어야 한다.
	case <-time.After(2 * time.Second):
		t.Fatal("취소된 컨텍스트에서 Scan이 제때 종료되지 않음")
	}
}

// TestTCPPortScanner_ConcurrencyCap는 워커 수가 전체 작업 수를 넘지 않도록
// 제한되는 경우에도 정상 동작하는지 확인한다.
func TestTCPPortScanner_ConcurrencyCap(t *testing.T) {
	var calls int64
	s := NewTCPPortScanner([]int{80}, 1000) // concurrency > 작업 수(1)
	s.dial = newFakeDial(map[int]bool{80: true}, &calls)

	ports, err := s.Scan(context.Background(), []string{"only.example.com"})
	if err != nil {
		t.Fatalf("Scan 오류: %v", err)
	}
	if len(ports) != 1 || calls != 1 {
		t.Fatalf("결과=%d, 시도=%d, 기대값 1/1", len(ports), calls)
	}
}
