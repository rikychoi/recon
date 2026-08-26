// Package model은 recon 도구의 도메인 모델과 결과 출력 포맷을 정의한다.
package model

// Subdomain은 대상 도메인에서 발견된 서브도메인 하나를 표현한다.
type Subdomain struct {
	Name string   `json:"name"` // 발견된 FQDN (예: mail.example.com)
	IPs  []string `json:"ips"`  // 해당 서브도메인이 가리키는 IP 주소 목록
}

// MailServer는 대상 도메인의 메일 서버(MX 레코드) 정보를 표현한다.
type MailServer struct {
	Host       string `json:"host"`       // 메일 서버 호스트명
	Preference uint16 `json:"preference"` // MX 우선순위 값 (낮을수록 우선)
}

// DNSRecord는 자산 식별 과정에서 수집한 DNS 레코드를 표현한다.
type DNSRecord struct {
	Type  string `json:"type"`  // 레코드 유형 (A, AAAA, CNAME, MX, TXT 등)
	Name  string `json:"name"`  // 레코드 대상 이름
	Value string `json:"value"` // 레코드 값
}

// Port는 포트 스캔으로 식별된 열린 포트를 표현한다.
type Port struct {
	Target   string `json:"target"`            // 포트를 스캔한 대상(hostname 또는 IP)
	Number   int    `json:"number"`            // 포트 번호
	Protocol string `json:"protocol"`          // 프로토콜 (tcp/udp)
	State    string `json:"state"`             // 포트 상태 (open|filtered 등)
	Service  string `json:"service"`           // 서비스 명 (예: http, ssh)
	Product  string `json:"product,omitempty"` // 서비스 제품명 (예: Apache httpd) — nmap -sV로 식별
	Version  string `json:"version,omitempty"` // 서비스 버전 (예: 2.4.49) — nmap -sV로 식별
	CPE      string `json:"cpe,omitempty"`     // CPE 식별자 (예: cpe:/a:apache:http_server:2.4.49)
}

// Asset는 대상 도메인에 대해 식별된 자산 정보를 한데 모은다.
type Asset struct {
	Domain      string       `json:"domain"`       // 점검 대상 루트 도메인
	Subdomains  []Subdomain  `json:"subdomains"`   // 발견된 서브도메인 목록
	MailServers []MailServer `json:"mail_servers"` // 메일 서버(MX) 목록
	DNSRecords  []DNSRecord  `json:"dns_records"`  // 수집된 DNS 레코드 목록
	Ports       []Port       `json:"ports"`        // 포트 스캔 결과
}
