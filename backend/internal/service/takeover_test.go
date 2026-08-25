package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// fakeResolver는 호스트별 CNAME과 해석 결과를 미리 지정하는 cnameLookuper 가짜 구현이다.
type fakeResolver struct {
	cnames map[string]string   // host -> CNAME(빈 값이면 CNAME 없음=자기 자신)
	hosts  map[string][]string // host -> 해석된 IP(없으면 NXDOMAIN 처리)
}

func (f *fakeResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	if c, ok := f.cnames[host]; ok && c != "" {
		return c + ".", nil // 실제 리졸버처럼 후행 점을 붙여 반환
	}
	return host + ".", nil // CNAME 없으면 자기 자신을 반환
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if addrs, ok := f.hosts[host]; ok && len(addrs) > 0 {
		return addrs, nil
	}
	return nil, fmt.Errorf("no such host: %s", host) // NXDOMAIN
}

// TestTakeoverScanner_DanglingCNAME은 알려진 서비스를 가리키는 댕글링 CNAME을 탈취 후보로 잡는지 검증한다.
func TestTakeoverScanner_DanglingCNAME(t *testing.T) {
	res := &fakeResolver{
		cnames: map[string]string{
			"gone.example.com": "myapp.herokuapp.com", // 서드파티 서비스를 가리킴
		},
		hosts: map[string][]string{}, // gone.example.com은 해석 안 됨(댕글링)
	}
	ts := NewTakeoverScanner(res, nil)

	subs := []model.Subdomain{{Name: "gone.example.com"}}
	vulns := ts.Detect(context.Background(), "example.com", subs)

	if len(vulns) != 1 {
		t.Fatalf("탈취 후보 1건을 기대했으나 %d건", len(vulns))
	}
	v := vulns[0]
	if v.Target != "gone.example.com" || v.Source != "takeover" {
		t.Errorf("탈취 취약점 필드 오류: %+v", v)
	}
	if v.CVSS < 7.0 || v.Severity != "high" {
		t.Errorf("탈취는 고위험이어야 함: cvss=%v sev=%s", v.CVSS, v.Severity)
	}
}

// TestTakeoverScanner_LiveCNAMEnotFlagged는 정상 해석되는 CNAME은 후보로 잡지 않는지 검증한다.
func TestTakeoverScanner_LiveCNAMEnotFlagged(t *testing.T) {
	res := &fakeResolver{
		cnames: map[string]string{
			"live.example.com": "myapp.herokuapp.com",
		},
		hosts: map[string][]string{
			"live.example.com": {"1.2.3.4"}, // 정상 해석됨
		},
	}
	ts := NewTakeoverScanner(res, nil)

	vulns := ts.Detect(context.Background(), "example.com",
		[]model.Subdomain{{Name: "live.example.com"}})

	if len(vulns) != 0 {
		t.Errorf("정상 해석 CNAME은 후보가 아니어야 함: %+v", vulns)
	}
}

// TestTakeoverScanner_UnknownServiceIgnored는 지문에 없는 대상을 가리키는 CNAME은 무시하는지 검증한다.
func TestTakeoverScanner_UnknownServiceIgnored(t *testing.T) {
	res := &fakeResolver{
		cnames: map[string]string{
			"x.example.com": "internal.corp.local", // 알려진 탈취 대상 서비스 아님
		},
		hosts: map[string][]string{}, // 해석 안 되더라도
	}
	ts := NewTakeoverScanner(res, nil)

	vulns := ts.Detect(context.Background(), "example.com",
		[]model.Subdomain{{Name: "x.example.com"}})

	if len(vulns) != 0 {
		t.Errorf("알려지지 않은 서비스는 후보가 아니어야 함: %+v", vulns)
	}
}

// TestTakeoverScanner_NoExternalCNAME은 외부를 가리키는 CNAME이 없으면 무시하는지 검증한다.
func TestTakeoverScanner_NoExternalCNAME(t *testing.T) {
	res := &fakeResolver{cnames: map[string]string{}, hosts: map[string][]string{}}
	ts := NewTakeoverScanner(res, nil)

	vulns := ts.Detect(context.Background(), "example.com",
		[]model.Subdomain{{Name: "www.example.com"}})

	if len(vulns) != 0 {
		t.Errorf("CNAME이 없으면 후보가 아니어야 함: %+v", vulns)
	}
}
