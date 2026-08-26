package service

import "testing"

// TestParseNmapXML_ProductVersionCPE는 -sV가 식별한 제품/버전/CPE를 파싱하는지 검증한다.
// 이 정보가 이후 "제품 → 적용 취약점(모듈)" 매핑의 근거가 된다.
func TestParseNmapXML_ProductVersionCPE(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49">
          <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>`

	ports := parseNmapXML("10.0.0.5", []byte(xml))
	if len(ports) != 1 {
		t.Fatalf("open 포트 1개를 기대했으나 %d개", len(ports))
	}
	p := ports[0]
	if p.Number != 80 || p.Service != "http" {
		t.Errorf("포트/서비스 파싱 오류: %+v", p)
	}
	if p.Product != "Apache httpd" || p.Version != "2.4.49" {
		t.Errorf("제품/버전 파싱 실패: product=%q version=%q", p.Product, p.Version)
	}
	if p.CPE != "cpe:/a:apache:http_server:2.4.49" {
		t.Errorf("CPE 파싱 실패: %q", p.CPE)
	}
}
