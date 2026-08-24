package service

import (
	"context"
	"io"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rikychoi/recon/internal/model"
)

// defaultTCPPorts는 별도 지정이 없을 때 스캔하는 대표적인 서비스 포트 목록이다.
var defaultTCPPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080,
	8443, 8888, 9000, 9200, 11211, 27017,
}

// commonServiceNames는 포트 번호를 대표 서비스명으로 매핑한다(간이 식별용).
var commonServiceNames = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
	139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
	993: "imaps", 995: "pop3s", 1723: "pptp", 3306: "mysql",
	3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
	6379: "redis", 8000: "http-alt", 8080: "http-proxy",
	8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
	9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

// dialFunc는 TCP 연결 시도 함수 시그니처이다. 테스트에서 주입해 교체할 수 있다.
type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// TCPPortScanner는 표준 라이브러리만으로 TCP connect 스캔을 수행하는 PortScanner 구현이다.
// 외부 도구(nmap) 없이 동작하며, 대상×포트 조합을 고루틴으로 병렬 점검한다.
type TCPPortScanner struct {
	ports       []int         // 스캔할 포트 목록
	concurrency int           // 동시에 진행할 연결 시도 수(워커 상한)
	timeout     time.Duration // 포트 하나당 연결 제한 시간
	progress    io.Writer     // 진행 상황 출력 대상(nil이면 미출력)
	dial        dialFunc      // 연결 시도 함수(테스트 주입용, nil이면 기본 net.Dialer)
}

// NewTCPPortScanner는 TCPPortScanner를 생성한다.
// ports가 비어 있으면 대표 포트 목록(defaultTCPPorts)을, concurrency가 0 이하이면 100을 사용한다.
func NewTCPPortScanner(ports []int, concurrency int) *TCPPortScanner {
	if len(ports) == 0 {
		ports = defaultTCPPorts
	}
	if concurrency <= 0 {
		concurrency = 100
	}
	return &TCPPortScanner{
		ports:       ports,
		concurrency: concurrency,
		timeout:     2 * time.Second,
	}
}

// SetProgress는 진행 상황을 출력할 Writer를 지정한다(nil이면 미출력).
func (s *TCPPortScanner) SetProgress(w io.Writer) {
	s.progress = w
}

// SetTimeout은 포트 하나당 연결 제한 시간을 지정한다.
func (s *TCPPortScanner) SetTimeout(d time.Duration) {
	if d > 0 {
		s.timeout = d
	}
}

// scanJob은 스캔할 (대상, 포트) 조합 하나를 나타낸다.
type scanJob struct {
	target string
	port   int
}

// Scan은 대상×포트 조합을 고루틴 워커 풀로 병렬 점검하여 열린 포트를 반환한다.
// 각 워커는 job 채널에서 작업을 받아 연결을 시도하며, 동시 실행 수는 concurrency로 제한된다.
// ctx가 취소되면 남은 작업을 중단하고 그때까지 수집한 결과를 반환한다.
func (s *TCPPortScanner) Scan(ctx context.Context, targets []string) ([]model.Port, error) {
	if len(targets) == 0 || len(s.ports) == 0 {
		return nil, nil
	}

	total := len(targets) * len(s.ports)
	jobs := make(chan scanJob)
	results := make(chan model.Port)

	// 워커 수는 전체 작업 수를 넘지 않도록 제한한다.
	workers := s.concurrency
	if workers > total {
		workers = total
	}

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		// 각 워커는 job 채널이 닫힐 때까지 작업을 처리한다.
		go func() {
			defer wg.Done()
			for job := range jobs {
				if p, ok := s.probe(ctx, job.target, job.port); ok {
					select {
					case results <- p:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// 생산자: 모든 (대상, 포트) 작업을 job 채널로 흘려보낸다.
	go func() {
		defer close(jobs)
		for _, target := range targets {
			for _, port := range s.ports {
				select {
				case jobs <- scanJob{target: target, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// 모든 워커가 끝나면 결과 채널을 닫아 아래 수집 루프를 종료시킨다.
	go func() {
		wg.Wait()
		close(results)
	}()

	// 소비자: 열린 포트를 모은다.
	var ports []model.Port
	for p := range results {
		ports = append(ports, p)
	}

	// 대상·포트 순으로 정렬해 출력 순서를 안정화한다(병렬 수집이라 순서가 비결정적).
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Target != ports[j].Target {
			return ports[i].Target < ports[j].Target
		}
		return ports[i].Number < ports[j].Number
	})

	progressf(s.progress, "    - TCP 스캔 완료: 대상 %d개 × 포트 %d개, 열린 포트 %d개\n",
		len(targets), len(s.ports), len(ports))
	return ports, nil
}

// probe는 대상의 특정 포트에 TCP 연결을 시도하여 열려 있으면 model.Port를 반환한다.
func (s *TCPPortScanner) probe(ctx context.Context, target string, port int) (model.Port, bool) {
	dctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	conn, err := s.dialer()(dctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err != nil {
		return model.Port{}, false
	}
	_ = conn.Close()

	service := commonServiceNames[port]
	if service == "" {
		service = "unknown"
	}
	return model.Port{
		Target:   target,
		Number:   port,
		Protocol: "tcp",
		State:    "open",
		Service:  service,
	}, true
}

// dialer는 주입된 연결 함수가 있으면 그것을, 없으면 기본 net.Dialer를 사용한다.
func (s *TCPPortScanner) dialer() dialFunc {
	if s.dial != nil {
		return s.dial
	}
	var d net.Dialer
	return d.DialContext
}
