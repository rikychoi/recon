# recon

`recon`은 웹사이트/도메인 자산 식별과 취약점 점검을 연계하는 Go 기반 CLI 도구입니다.

주요 기능:

- DNS 조회
- 메일 서버(MX) 식별
- CNAME / DNS 레코드 자산 탐지
- 서브도메인 열거
- 포트 스캔 (`nmap` 기반)
- 취약점 스캔 (`nuclei`, `metasploit`)
- 결과를 텍스트 또는 JSON으로 출력

이 도구는 공개 서비스에 직접 공격을 시도하는 용도가 아니라, 로컬/검증용 환경에서의 보안 점검용으로 사용하도록 설계되었습니다.

## 프로젝트 구조

```text
recon/
├── backend/           # Go 코드
│   ├── cmd/recon      # CLI 진입점
│   ├── internal/
│   │   ├── handler    # CLI 옵션 처리
│   │   ├── model      # 결과 모델 및 포맷터
│   │   ├── service    # DNS, 서브도메인, nmap, nuclei, msf
│   └── go.mod
├── deploy/            # 배포 관련 파일
├── README.md
└── CLAUDE.md
```

## 요구 사항

- Go 1.25 이상 권장
- `nmap` (포트 스캔)
- `nuclei` (선택)
- `msfconsole` (선택)

## 실행 전 준비

### 1) Go 실행

```bash
cd /home/rikychoi/recon/backend
```

### 2) 의존성 정리

```bash
go mod tidy
```

### 3) 외부 도구 설치

Linux 예시:

```bash
sudo apt-get update
sudo apt-get install -y nmap
```

필요 시:

```bash
# nuclei 설치 예시
# https://github.com/projectdiscovery/nuclei

# Metasploit 설치 예시
# sudo apt-get install -y metasploit-framework
```

## 실행 방법

### 기본 자산 식별

```bash
go run ./cmd/recon -domain example.com
```

### 포트 스캔 포함

```bash
go run ./cmd/recon -domain example.com -nmap
```

### Nuclei 취약점 점검 포함

```bash
go run ./cmd/recon -domain example.com -nmap -nuclei
```

### Metasploit 검증 포함

```bash
go run ./cmd/recon -domain example.com -nmap -msf
```

### 전체 파이프라인

```bash
go run ./cmd/recon -domain example.com -full
```

### JSON 출력

```bash
go run ./cmd/recon -domain example.com -full -format json
```

## 사용 예시: 로컬 VM 테스트

테스트 대상이 VM 안에 있는 웹앱이라고 가정하면, Windows 호스트에서 VM 서버를 “외부 서버처럼” 스캔할 수 있습니다.

### 1) VM IP 확인

VM 안에서:

```bash
ip addr
```

예시:

```text
192.168.100.130
```

### 2) Windows hosts 파일 수정

Windows에서 관리자 권한으로 다음 파일을 편집합니다:

```text
C:\Windows\System32\drivers\etc\hosts
```

추가 줄:

```text
192.168.100.130 app.test.local
```

### 3) VM 안에서 웹앱 실행

예: 3000 포트에서 실행 중이라고 가정하면:

```text
http://app.test.local:3000
```

### 4) 도구 실행

호스트 Windows에서, 또는 프로젝트를 실행하는 환경에서:

```bash
cd /home/rikychoi/recon/backend
go run ./cmd/recon -domain app.test.local -full -format json
```

이 흐름은 다음을 수행합니다.

1. DNS 조회
2. 서브도메인 열거
3. `nmap` 포트 스캔
4. `nuclei` 스캔
5. `msfconsole` 스캔 (선택)
6. 결과 JSON/텍스트 출력

## 핵심 동작 흐름

```text
DNS 조회
  ↓
서브도메인 열거
  ↓
포트 스캔 (nmap)
  ↓
취약점 스캔 (nuclei / metasploit)
  ↓
결과 출력
```

## 참고

- `-full` 플래그는 `-nmap -nuclei -msf` 를 한 번에 활성화합니다.
- `nmap`/`nuclei`/`msfconsole`이 설치되어 있지 않으면 해당 단계는 건너뛰고 다른 단계는 계속 진행됩니다.
- 이 도구는 로컬 검증 및 학습용 환경을 전제로 하며, 라이브 서비스를 대상으로 하는 용도는 아닙니다.

## 출력 예시

```json
{
  "target": "app.test.local",
  "asset": {
    "domain": "app.test.local",
    "dns_records": [
      {
        "type": "A",
        "name": "app.test.local",
        "value": "192.168.100.130"
      }
    ],
    "ports": [
      {
        "target": "app.test.local",
        "number": 3000,
        "protocol": "tcp",
        "state": "open",
        "service": "http"
      }
    ]
  }
}
```
