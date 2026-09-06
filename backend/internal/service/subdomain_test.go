package service

import (
	"context"
	"strings"
	"testing"
)

// fakeHostResolver는 호스트별 IP를 지정하고, 그 외에는 와일드카드 IP(설정 시)로 응답하는 가짜 리졸버다.
type fakeHostResolver struct {
	hosts      map[string][]string // 명시적으로 존재하는 호스트
	wildcardIP string              // 비어있지 않으면 미지정 호스트를 이 IP로 응답(하이재킹 흉내)
}

func (f *fakeHostResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if ips, ok := f.hosts[host]; ok {
		return ips, nil
	}
	if f.wildcardIP != "" {
		return []string{f.wildcardIP}, nil // 존재하지 않아도 하이재킹 IP 반환
	}
	return nil, &fakeHostErr{host}
}

type fakeHostErr struct{ h string }

func (e *fakeHostErr) Error() string { return "no such host: " + e.h }

// TestEnumerate_NoWildcard는 정상 DNS에서 실제 존재하는 서브도메인만 반환하는지 검증한다.
func TestEnumerate_NoWildcard(t *testing.T) {
	res := &fakeHostResolver{hosts: map[string][]string{
		"www.example.com": {"1.2.3.4"},
		"api.example.com": {"1.2.3.5"},
	}}
	s := NewBruteSubdomainScanner([]string{"www", "api", "nope"}, 5)
	s.resolver = res

	out, _ := s.Enumerate(context.Background(), "example.com")
	if len(out) != 2 {
		t.Fatalf("실존 2개 기대, got %d: %+v", len(out), out)
	}
}

// TestEnumerate_WildcardHijack는 하이재킹(모든 이름이 특정 IP로 해석) 시 가짜 후보를 제외하는지 검증한다.
func TestEnumerate_WildcardHijack(t *testing.T) {
	// 218.38.137.27로 모든 미지정 호스트가 해석되는 하이재킹 환경.
	// 단, real.example.com만 진짜 다른 IP를 가진 실제 서브도메인.
	res := &fakeHostResolver{
		hosts:      map[string][]string{"real.example.com": {"10.0.0.9"}},
		wildcardIP: "218.38.137.27",
	}
	// 워드리스트에 real 포함 + 하이재킹으로 다 잡힐 이름들
	s := NewBruteSubdomainScanner([]string{"real", "www", "admin", "vpn", "ftp"}, 5)
	s.resolver = res

	out, _ := s.Enumerate(context.Background(), "example.com")
	if len(out) != 1 || out[0].Name != "real.example.com" {
		t.Fatalf("하이재킹 제외 후 real 1개만 기대, got %d: %+v", len(out), out)
	}
}

// TestIsAllWildcard는 IP 집합이 전부 와일드카드일 때만 true인지 검증한다.
func TestIsAllWildcard(t *testing.T) {
	wc := map[string]bool{"218.38.137.27": true}
	if !isAllWildcard([]string{"218.38.137.27"}, wc) {
		t.Error("와일드카드 IP만 있으면 true여야 함")
	}
	if isAllWildcard([]string{"218.38.137.27", "10.0.0.1"}, wc) {
		t.Error("진짜 IP가 섞이면 false여야 함")
	}
	if isAllWildcard([]string{"1.2.3.4"}, map[string]bool{}) {
		t.Error("와일드카드 집합이 비면 false여야 함")
	}
}

// TestRandomLabel은 무작위 라벨이 매번 달라지고 recon 접두어를 갖는지 확인한다.
func TestRandomLabel(t *testing.T) {
	a, b := randomLabel(), randomLabel()
	if a == b {
		t.Error("무작위 라벨이 매번 달라야 함")
	}
	if !strings.HasPrefix(a, "recon-") {
		t.Errorf("라벨 접두어 오류: %s", a)
	}
}
