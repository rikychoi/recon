# recon

`recon`은 대상 웹서버의 **자산을 식별**하고, 노출된 **포트를 스캔**한 뒤, 스캔된
포트/서비스에 대해 **취약점을 식별**하는 Go 기반 CLI 도구입니다.

DNS 조회부터 취약점 점검까지를 하나의 파이프라인으로 연결하여, 대상 하나에
대한 정찰(recon)과 취약점 점검을 단일 명령으로 수행하는 것을 목표로 합니다.

## 무엇을 하는가

`recon`은 대상 도메인 하나를 입력받아 다음 순서로 정찰을 진행합니다.

```text
DNS / 메일 서버 조회
      ↓
서브도메인 열거
      ↓
포트 스캔 (nmap)          ← 대상 + 발견된 서브도메인
      ↓
취약점 식별 (nuclei / metasploit)
      ↓
결과 출력 (text / json)
```

1. **자산 식별** — DNS 레코드(A/AAAA/CNAME/TXT), 메일 서버(MX)를 조회하고
   서브도메인을 열거하여 대상의 공격 표면(attack surface)을 그려냅니다.
2. **포트 스캔** — `nmap`으로 대상 및 발견된 서브도메인의 열린 포트와 서비스
   버전을 식별합니다.
3. **취약점 식별** — 식별된 대상에 대해 `nuclei`(템플릿 기반)와
   `metasploit`(검증)으로 취약점을 점검하고 CVSS 점수와 심각도를 산출합니다.

각 단계는 인터페이스로 분리되어 있어, 외부 도구가 설치되어 있지 않으면 해당
단계만 건너뛰고 나머지 파이프라인은 계속 진행합니다.

## 요구 사항

| 도구          | 용도                | 필수 여부              |
| ------------- | ------------------- | ---------------------- |
| Go 1.25+      | 빌드 및 실행        | 필수                   |
| `nmap`        | 포트 스캔           | `-nmap`/`-full` 시     |
| `nuclei`      | 템플릿 취약점 스캔  | `-nuclei`/`-full` 시   |
| `msfconsole`  | 취약점 검증         | `-msf`/`-full` 시      |

DNS 조회와 서브도메인 열거는 외부 도구 없이 동작합니다.

Linux 설치 예시:

```bash
sudo apt-get update
sudo apt-get install -y nmap
# nuclei:      https://github.com/projectdiscovery/nuclei
# metasploit:  sudo apt-get install -y metasploit-framework
```

## 빌드 및 실행

```bash
cd backend
go mod tidy
```

### 명령어

```bash
# 자산 식별만 (DNS + 서브도메인)
go run ./cmd/recon -domain example.com

# 포트 스캔 포함
go run ./cmd/recon -domain example.com -nmap

# 포트 스캔 + nuclei 취약점 식별
go run ./cmd/recon -domain example.com -nmap -nuclei

# 포트 스캔 + metasploit 검증
go run ./cmd/recon -domain example.com -nmap -msf

# 전체 파이프라인 (nmap + nuclei + metasploit)
go run ./cmd/recon -domain example.com -full

# JSON 출력
go run ./cmd/recon -domain example.com -full -format json
```

### 옵션

| 플래그      | 기본값   | 설명                                                        |
| ----------- | -------- | ----------------------------------------------------------- |
| `-domain`   | (필수)   | 점검 대상 도메인                                            |
| `-format`   | `text`   | 출력 형식 (`text` \| `json`)                                |
| `-timeout`  | `5m`     | 전체 점검 제한 시간                                         |
| `-nmap`     | `false`  | nmap 포트 스캔 활성화                                       |
| `-nuclei`   | `false`  | nuclei 취약점 식별 활성화                                   |
| `-msf`      | `false`  | metasploit 취약점 검증 활성화                               |
| `-full`     | `false`  | `-nmap -nuclei -msf`를 한 번에 활성화                       |

## 출력 예시

```json
{
  "target": "example.com",
  "asset": {
    "domain": "example.com",
    "dns_records": [
      { "type": "A", "name": "example.com", "value": "93.184.216.34" }
    ],
    "mail_servers": [
      { "host": "mail.example.com", "preference": 10 }
    ],
    "subdomains": [
      { "name": "www.example.com", "ips": ["93.184.216.34"] }
    ],
    "ports": [
      { "target": "example.com", "number": 443, "protocol": "tcp", "state": "open", "service": "https" }
    ]
  },
  "vulnerabilities": [
    {
      "id": "CVE-2021-1234",
      "name": "Example RCE",
      "target": "example.com",
      "cvss": 9.8,
      "severity": "critical",
      "source": "nuclei"
    }
  ]
}
```

## 프로젝트 구조

```text
recon/
├── backend/
│   ├── cmd/recon/            # CLI 진입점
│   ├── internal/
│   │   ├── handler/          # CLI 옵션 파싱 및 오케스트레이터 조립
│   │   ├── model/            # 도메인 모델 및 출력 포맷터
│   │   └── service/          # DNS, 서브도메인, nmap, nuclei, msf, 오케스트레이션
│   └── go.mod
├── deploy/                   # 배포/실행 환경
├── README.md
└── CLAUDE.md
```

## 테스트

```bash
cd backend
go test ./...
```

## 사용 범위 / 주의

- 이 도구는 **권한이 부여된 화이트해킹(승인된 침투 테스트)** 을 목적으로 하며,
  권한이 있는 경우 라이브 서비스 서버까지 대상으로 사용할 수 있도록 설계됩니다.
- 어떤 경우든 본인이 소유하거나 **점검 권한을 명시적으로 부여받은 시스템에
  대해서만** 사용하십시오. 무단 스캔·취약점 점검은 법적 책임을 초래합니다.
- 다만 **개발·테스트 단계에서는 법적 리스크를 피하기 위해 라이브 서버를 대상으로
  하지 않으며**, 격리된 VM/로컬 환경에 직접 구성한 웹앱으로만 검증합니다. 이는
  개발자의 검증 편의를 위한 세팅일 뿐, 도구의 대상 범위를 제한하는 것은 아닙니다.
