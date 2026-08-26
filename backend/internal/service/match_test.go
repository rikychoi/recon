package service

import (
	"testing"

	"github.com/rikychoi/recon/internal/model"
)

// TestModuleMatchesPort는 "서비스 제품 인식 → 적용 취약점 매핑"의 핵심 로직을 검증한다.
func TestModuleMatchesPort(t *testing.T) {
	struts := MSFModule{Name: "exploit/x/struts", Service: "http", Product: "struts"}
	httpd := MSFModule{Name: "exploit/x/httpd", Service: "http", Product: "httpd"}
	anyHTTP := MSFModule{Name: "aux/x/log4shell", Service: "http"} // 제품 조건 없음

	strutsPort := model.Port{Number: 8080, Service: "http", Product: "Apache Struts", CPE: "cpe:/a:apache:struts:2.5.10"}
	apachePort := model.Port{Number: 80, Service: "http", Product: "Apache httpd", CPE: "cpe:/a:apache:http_server:2.4.49"}
	noProductHTTP := model.Port{Number: 80, Service: "http"} // 내장 스캐너: 제품 미상
	sshPort := model.Port{Number: 22, Service: "ssh"}

	cases := []struct {
		name string
		mod  MSFModule
		port model.Port
		want bool
	}{
		{"struts 모듈 → Struts 포트 = 적합", struts, strutsPort, true},
		{"struts 모듈 → Apache httpd 포트 = 부적합", struts, apachePort, false},
		{"httpd 모듈 → Apache httpd 포트 = 적합", httpd, apachePort, true},
		{"httpd 모듈 → Struts 포트 = 부적합", httpd, strutsPort, false},
		{"제품미상 http 포트 → 제품모듈은 서비스 폴백으로 적합", struts, noProductHTTP, true},
		{"제품조건 없는 모듈 → http 포트 적합", anyHTTP, apachePort, true},
		{"제품조건 없는 모듈 → ssh 포트 부적합", anyHTTP, sshPort, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := moduleMatchesPort(c.mod, c.port); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
