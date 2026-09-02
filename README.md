# recon

도메인 하나를 입력하면 **정찰 → 포트 스캔 → 취약점 점검**을 한 번에 자동 수행하고
결과를 단일 보고서로 취합하는 Go 기반 CLI 취약점 점검 도구입니다.
**핵심은 "알려진 취약점(CVE) 식별의 자동화 — 특히 Metasploit 사용의 자동화"** 로,
nmap이 인식한 서비스 제품·버전에 맞는 점검 모듈을 자동으로 찾아 검증합니다.

<br>

# 프로젝트 정보

## 제작기간
2026.00 ~ 2026.00

## 팀 구성원

| 이름 | 역할 |
| :--- | :--- |
| **rikychoi** | 기획 · 개발 |

## 사용 기술 스택

### 코어 / 오케스트레이션
> * Go 1.25

### 취약점 점검
> * Metasploit (msfconsole)
> * Nuclei
> * Nmap (-sV)

### 위협 인텔리전스
> * NVD (버전 → CVE 조회)
> * FIRST.org EPSS (악용 확률)
> * CISA KEV (실제 악용 목록)

<br>

# 파이프라인

<details>
<summary>전체 흐름</summary>
<br>
<img width="900" alt="recon pipeline" src="이미지_링크" />
</details>

```text
자산 식별(DNS·서브도메인)  →  포트 스캔 + 서비스 인식(nmap -sV)
      →  적용 취약점 검색·검증(Metasploit)  →  위험 우선순위화(CVSS·EPSS·KEV)  →  보고서
```

<br>

# 핵심기능

## 1. 자산 식별
<img width="850" alt="asset identification" src="이미지_링크" />

대상 도메인의 DNS 레코드(A·CNAME·MX·TXT), 메일 서버, 서브도메인을 조회해 공격 표면을 그립니다.
같은 IP를 가리키는 호스트는 하나로 묶어 중복 스캔을 방지합니다.

## 2. 서비스 인식 → 적용 취약점 자동 검색·검증 (Metasploit 자동화)
<img width="850" alt="service to vulnerability" src="이미지_링크" />

nmap `-sV`로 포트의 **제품·버전**(예: `Apache httpd 2.4.49`)을 인식하고, 그 제품에 해당하는
Metasploit 모듈을 `search`로 **실시간 발굴**한 뒤 `check`(비침투 검증)로 실제 취약 여부를 확인합니다.
어떤 모듈을 써야 하는지 몰라도, "감지된 서비스 → 맞는 취약점 점검"을 도구가 알아서 연결합니다.

## 3. 버전(CPE) 기반 CVE 정밀 검색
<img width="850" alt="version based cve lookup" src="이미지_링크" />

`-nvd` 지정 시, 인식한 CPE(제품+버전)로 **NVD에서 해당 버전의 CVE 목록**을 받아
그 CVE를 가진 모듈만 정밀 검색합니다. (예: `Apache httpd 2.4.49` → NVD CVE 수십 개 → 실제 모듈로 압축)

## 4. CVE 위험 우선순위화
<img width="850" alt="risk prioritization" src="이미지_링크" />

발견된 취약점에 **CVSS**(심각도) · **EPSS**(악용 확률) · **CISA KEV**(실제 악용 중) 정보를 보강해
**실제 위험이 높은 순서**(KEV → CVSS → EPSS)로 정렬합니다.

## 5. 서브도메인 탈취 탐지
<img width="850" alt="subdomain takeover" src="이미지_링크" />

서브도메인의 CNAME이 서드파티 서비스를 가리키는데 그 대상이 사라진 경우(댕글링 CNAME)를
DNS 조회만으로 탐지해 고위험 취약점으로 보고합니다.

<br>

# 실행 방법

```bash
cd backend

# 자산 식별만
go run ./cmd/recon -domain example.com

# 전체: 제품 인식 → 버전 기반 CVE 검색·검증 → 위험 우선순위화 → JSON 저장
go run ./cmd/recon -domain example.com -nmap -msf-search -nvd \
  -format json -output report.json -timeout 15m
```

> 상세한 옵션·아키텍처·개발 규칙은 [backend/README.md](backend/README.md)를 참고하세요.

<br>

> ⚠️ 본인이 소유하거나 점검 권한을 받은 대상에만 사용하세요. 개발·테스트는 격리된 VM/로컬 환경에서만 수행합니다.
