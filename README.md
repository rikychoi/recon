# recon

`recon`은 웹사이트(서버) 하나를 정해주면 **그 서버에 대해 알아낼 수 있는 정보를 모으고**,
**열려 있는 문(포트)을 확인한 뒤**, **알려진 보안 약점(취약점)이 있는지 점검**해 주는
Go 기반 명령줄(CLI) 도구입니다.

> 🎯 **주 목표는 "알려진 취약점(CVE) 식별의 자동화 — 특히 Metasploit 사용의 자동화"입니다.**
> 사람이 손으로 하던 정찰 → 포트 스캔 → 취약점 점검을, 도구를 오가며 반복하는 대신
> **명령어 한 번으로 자동 수행**하고 결과를 **하나의 보고서로 취합**합니다.
> 새로운(0-day) 취약점을 발굴하는 도구가 아니라, **이미 공개된 CVE에 취약한 자산을
> 빠르고 반복 가능하게 찾아내는** 자동화 파이프라인입니다.
>
> **핵심 동작:** nmap이 포트에서 **서비스의 제품·버전**(예: `Apache httpd 2.4.49`)을 인식하면,
> `recon`이 **그 제품에 실제로 적용되는 취약점 점검 모듈만 골라 자동 실행**합니다.
> Metasploit을 잘 모르는 사용자도, 어떤 모듈을 써야 하는지 고민할 필요 없이
> "감지된 서비스 → 맞는 취약점 점검"을 도구가 알아서 연결해 줍니다.

---

## 보안 용어 먼저 (이 문서를 읽기 위한 최소 지식)

보안 지식이 없어도 따라올 수 있도록, 이 도구에서 쓰는 용어를 먼저 쉽게 정리합니다.

| 용어 | 쉬운 설명 |
| --- | --- |
| **도메인(domain)** | 웹사이트 주소. 예: `example.com` |
| **서브도메인(subdomain)** | 도메인 앞에 붙는 하위 주소. 예: `mail.example.com`, `blog.example.com` |
| **DNS 레코드** | "이 도메인은 어떤 IP·메일서버를 쓰는가"를 적어둔 전화번호부 같은 정보 |
| **IP 주소** | 서버의 실제 번지수. 예: `93.184.216.34` |
| **포트(port)** | 서버라는 건물의 "출입문 번호". 웹은 보통 80·443번 문을 씁니다 |
| **포트 스캔** | 어떤 문이 열려 있는지 하나씩 두드려 확인하는 작업 |
| **취약점(vulnerability)** | 공격에 악용될 수 있는 보안 약점(버그·설정 실수 등) |
| **CVE** | 공개된 취약점에 붙는 전 세계 공통 번호. 예: `CVE-2017-5638` |
| **CVSS** | 취약점의 위험도 점수(0~10). 높을수록 심각. 9 이상이면 `critical` |
| **exploit(익스플로잇)** | 취약점을 실제로 찔러 보는(악용해 보는) 공격 코드/방법 |
| **payload / LHOST** | 익스플로잇이 성공했을 때 실행되는 코드와, 결과를 되돌려 받을 내 IP(자세히는 뒤에서) |

---

## 무엇을 하는가 (전체 흐름)

대상 도메인 하나를 입력하면 아래 순서로 진행합니다.

```text
1. 자산 식별   DNS/메일서버 조회 → 서브도메인 찾기
        ↓
2. 자산 정리   찾은 주소들을 실제 IP로 묶기 (같은 IP는 하나로 취급)
        ↓
3. 포트 스캔   각 IP의 열린 포트 확인            ┐  IP마다
        ↓                                        ├─ 동시에(병렬)
4. 취약점 점검  nuclei / metasploit 로 약점 확인  ┘  진행
        ↓
5. 결과 출력   하나의 보고서로 취합 (text 또는 json)
```

1. **자산 식별** — 도메인의 DNS 레코드(A/AAAA/CNAME/TXT)와 메일 서버(MX)를 조회하고,
   자주 쓰이는 이름(`www`, `api`, `dev` 등)으로 서브도메인을 찾아 **공격 표면**을 그립니다.
2. **자산 정리(중복 제거)** — 여러 도메인이 **같은 IP**를 가리키는 경우가 많습니다.
   같은 IP는 하나의 자산으로 묶어 **똑같은 서버를 두 번 스캔하지 않도록** 합니다.
3. **포트 스캔 + 서비스 인식** — 각 IP에서 열린 포트와 함께, `nmap -sV`로
   **그 포트에서 돌아가는 제품·버전**(예: `Apache httpd 2.4.49`, `Apache Struts`)을 식별합니다.
4. **취약점 점검(제품 맞춤)** — 식별된 **제품에 적용되는 점검 모듈만 골라** `metasploit`으로
   실제 CVE를 점검하고, `nuclei`(템플릿 기반 점검)를 함께 돌려 CVE·CVSS·심각도를 정리합니다.
   → Struts가 감지되면 Struts 모듈만, Apache httpd가 감지되면 httpd 모듈만 실행됩니다.

> **병렬 처리:** 자산(IP)마다 `포트 스캔 → 취약점 점검`을 **고루틴으로 동시에** 실행하고,
> 결과를 하나의 보고서로 합칩니다. 대상이 많아도 빠르게 끝납니다.

각 단계는 서로 분리되어 있어, 외부 도구가 없으면 **그 단계만 건너뛰고** 나머지는 계속 진행합니다.

---

## 핵심: 서비스 인식 → 적용 취약점 자동 검색·검증 (Metasploit 자동화)

이 도구의 심장부입니다. **"열린 포트에 무슨 제품이 도는지"를 인식하고, 그 제품에
적용되는 Metasploit 모듈을 자동으로 검색해 점검**합니다. Metasploit의 수천 개 모듈 중
무엇을 써야 하는지 사용자가 몰라도 됩니다. — 이것이 `recon`이 자동화하려는 바로 그 작업입니다.

```text
nmap -sV        →   제품/버전 인식     →   msf search로 모듈 발굴      →   check로 안전 검증
──────────────      ────────────────       ──────────────────────────      ────────────────────
8080/tcp open       Apache Struts          search struts type:exploit      각 모듈에 check 실행 →
  80/tcp open       Apache httpd 2.4.49     search httpd type:exploit         "취약함" 확인된 것만 기록
  22/tcp open       OpenSSH 8.2            (해당 없음 → 건너뜀)
```

동작 방식(`-msf-search`, `-full`에 기본 포함):

1. **제품 인식** — `nmap -sV`가 포트의 제품/버전을 식별합니다(예: `Apache Struts`).
2. **모듈 동적 검색** — 그 제품명으로 msfconsole `search`를 실행해 **적용 가능한 익스플로잇 모듈을
   실시간으로 발굴**합니다. 고정 목록이 아니라 **Metasploit이 가진 전체 모듈**이 대상이라 커버리지가 넓습니다.
   - **버전 정밀 모드(`-nvd`)** — nmap이 CPE(제품+버전)를 식별했으면, 그 버전에 해당하는 **CVE 목록을
     NVD에서 조회**한 뒤 `search cve:...`로 **버전에 정확히 해당하는 모듈만** 검색합니다.
     (예: `Apache httpd 2.4.49` → NVD가 CVE 수십 개 → 그 중 msf 모듈이 있는 것만 압축 → check.)
     CPE가 없거나(예: Struts 같은 앱-계층) 조회 결과가 없으면 **제품명 검색으로 자동 폴백**합니다.
3. **안전 검증(check)** — 발굴한 모듈을 실제 공격(exploit) 대신 **`check`(비침투 검증)** 로만 실행해
   "이 대상이 정말 취약한가"를 확인합니다. 셸을 따거나 페이로드를 던지지 않으므로 **부작용이 없습니다.**
4. **결과 기록** — `check`가 취약(또는 취약 추정)으로 판정한 모듈만 취약점으로 남기고,
   가능하면 모듈 정보에서 **CVE**까지 뽑아 이어지는 EPSS/KEV/NVD 보강으로 연결합니다.

> ⚠️ 정밀 검색은 **제품 인식이 전제**입니다. `-msf-search`는 `-nmap`(= `nmap -sV`)과 함께 쓰세요.
> 내장 포트 스캐너만 쓰면 제품을 몰라 서비스 종류(`http` 등)로 폭넓게 검색하게 됩니다.

> ⚙️ **msfconsole 생명주기 — 프로그램당 1회 부팅.** msfconsole은 부팅에 수십 초가 걸리므로,
> `recon`은 점검 시작 시 **msfconsole을 한 번만 켜서 세션을 유지**하고 모든 msf 명령
> (`search`·`check`·exploit `run`)을 그 세션에 흘려보낸 뒤, **프로그램 종료 시 함께 닫습니다.**
> `-msf`(카탈로그)와 `-msf-search`(동적 검색)가 **하나의 세션을 공유**하므로 어떤 조합이든
> msfconsole은 딱 한 번만 부팅됩니다. 명령·모듈마다 새로 켜지 않아 훨씬 빠릅니다.

> 🔒 실제 익스플로잇까지 시도하는 공격적 모드가 필요하면 별도의 `-msf`(고정 카탈로그 + 실제 exploit)를
> 쓸 수 있습니다. **격리 환경 전용**입니다. 기본 자동화 흐름(`-full`)은 안전한 `check` 검증만 씁니다.

> 이렇게 찾은 취약점은 이어서 **EPSS(악용 확률)·CISA KEV(실제 악용 중)** 로 보강되어
> **위험이 높은 순서로 정렬**됩니다. (아래 [CVE 위험 우선순위화](#cve-위험-우선순위화-epss--kev--nvd) 참고)

> 💡 **핵심 가치 = 자동화.** 위 5단계를 사람이 도구를 바꿔가며 수동으로 하면 오래 걸리고
> 실수가 생깁니다. `recon`은 이 과정을 한 번에, **같은 방식으로 반복 실행**할 수 있게 해
> 여러 대상을 일관되게(예: CI·정기 점검) 자동 점검하는 것을 지향합니다.

---

## 요구 사항

| 도구 | 용도 | 필수 여부 |
| --- | --- | --- |
| Go 1.25+ | 빌드 및 실행 | **필수** |
| (내장) | 포트 스캔 (Go로 구현, 설치 불필요) | `-portscan`/`-full` 시 |
| `nmap` | 포트 스캔 (서비스 버전까지 상세) | `-nmap` 시(선택) |
| `nuclei` | 템플릿 기반 취약점 점검 | `-nuclei`/`-full` 시 |
| `msfconsole` | 제품별 모듈 검색·검증(또는 실제 exploit) | `-msf-search`/`-msf`/`-full` 시 |

- **DNS 조회·서브도메인 열거·기본 포트 스캔은 외부 도구 없이** 동작합니다.
  (`-portscan`은 Go로 구현된 내장 스캐너라 아무것도 설치할 필요가 없습니다.)
- `nmap`은 포트 스캔을 더 정밀하게(서비스 버전 탐지 등) 하고 싶을 때 선택적으로 씁니다.

---

## 빠르게 시작하기

```bash
cd backend
go mod tidy

# 1) 아무 설치 없이: 자산 식별 + 내장 포트 스캔
go run ./cmd/recon -domain example.com -portscan

# 2) 전체 파이프라인 (권장: -nmap으로 제품 인식 → 제품 맞춤 msf 모듈 자동 검색·검증)
go run ./cmd/recon -domain example.com -full -nmap -timeout 10m
```

> ⚠️ **반드시 본인이 소유하거나 점검 권한을 받은 대상에만 사용하세요.** 자세한 내용은
> 맨 아래 [사용 범위 / 주의](#사용-범위--주의)를 먼저 읽어 주세요.

---

## 명령어와 옵션

### 명령어 예시

```bash
# 자산 식별만 (DNS + 서브도메인). 포트/취약점 점검 없음
go run ./cmd/recon -domain example.com

# 내장 포트 스캔 (설치 불필요)
go run ./cmd/recon -domain example.com -portscan

# 외부 nmap으로 포트 스캔 (서비스 버전까지)
go run ./cmd/recon -domain example.com -nmap

# 포트 스캔 + nuclei 취약점 점검
go run ./cmd/recon -domain example.com -portscan -nuclei

# nmap으로 제품 인식 + metasploit 동적 모듈 검색·검증 (권장 조합)
go run ./cmd/recon -domain example.com -nmap -msf-search -timeout 10m

# metasploit 고정 카탈로그 + 실제 exploit 시도 (격리 환경 전용)
go run ./cmd/recon -domain example.com -portscan -msf

# 전체 파이프라인 (제품 인식까지: 내장/nmap 포트스캔 + nuclei + msf-search)
go run ./cmd/recon -domain example.com -full -nmap -timeout 10m

# JSON으로 출력
go run ./cmd/recon -domain example.com -full -format json
```

### 옵션

| 플래그 | 기본값 | 설명 |
| --- | --- | --- |
| `-domain` | (필수) | 점검 대상 도메인 |
| `-format` | `text` | 출력 형식 (`text` \| `json`) |
| `-timeout` | `5m` | 전체 점검 제한 시간 (metasploit 사용 시 `10m` 권장) |
| `-portscan` | `false` | **내장** 고루틴 TCP 포트 스캔 (외부 도구 불필요) |
| `-nmap` | `false` | 외부 `nmap -sV`로 포트 스캔 (**제품·버전 인식** — `-msf-search`의 정밀도에 필수) |
| `-nuclei` | `false` | `nuclei` 취약점 점검 |
| `-msf-search` | `false` | **`metasploit` 동적 모듈 검색 점검.** 감지된 제품으로 `search`해 모듈을 발굴하고 `check`(비침투)로 검증. `-nmap`과 함께 권장. `-full`에 기본 포함 |
| `-msf` | `false` | `metasploit` 고정 카탈로그 점검 — **실제 exploit 시도(부작용 가능). 격리 환경 전용** |
| `-full` | `false` | 내장 포트스캔 + `nuclei` + **`-msf-search`(안전 검증)** 를 한 번에 |
| `-allow-public` | `false` | 공인(외부) IP 대상 스캔 허용. **기본은 사설/로컬 IP만** 스캔하고 공인 IP는 경고 후 제외 |
| `-enrich` | `true` | 발견된 취약점에 **EPSS**(악용 확률) · **CISA KEV**(실제 악용 중) 정보를 보강 (외부 API 조회) |
| `-nvd` | `false` | **NVD 연동.** msf-search에서 **CPE(버전)→CVE 목록→모듈**로 정밀 검색하고, CVSS 없는 취약점을 NVD로 보강 (레이트 제한이 있어 기본 비활성) |
| `-takeover` | `true` | **서브도메인 탈취**(댕글링 CNAME) 탐지 (DNS 조회만 수행, 부작용 없음) |

> 포트 스캔 엔진은 `-nmap`이 있으면 nmap을, 없으면(`-portscan`/`-full`) 내장 스캐너를 씁니다.

### CVE 위험 우선순위화 (EPSS · KEV · NVD)

발견된 취약점은 CVSS만으로는 "무엇부터 볼지"를 정하기 어렵습니다. `recon`은 각 취약점의
CVE를 식별한 뒤 외부 위협 인텔리전스로 보강하여 **실제 위험 순서**로 정렬합니다.

- **EPSS** (FIRST.org) — 향후 30일 내 악용될 확률(0~100%). "CVSS는 높지만 실제 악용 가능성은 낮은" CVE를 걸러냅니다.
- **CISA KEV** — 미국 CISA가 **실제 악용을 확인**한 CVE 목록. 등재된 취약점은 보고서 최상단에 표시됩니다.
- **NVD** (`-nvd`) — 탐지 도구가 CVSS를 주지 못한 경우 권위 있는 CVSS 점수를 채웁니다.

정렬 우선순위: **KEV(실제 악용) → CVSS → EPSS(악용 확률)**. 이들은 CVE ID만 외부 조회하며,
대상 서버로는 아무것도 보내지 않습니다. 오프라인이거나 조회에 실패해도 점검은 그대로 완주합니다.

### 서브도메인 탈취 탐지 (댕글링 CNAME)

`-takeover`(기본 켜짐)는 서브도메인의 CNAME이 GitHub Pages·Heroku·S3·Azure 등
**서드파티 서비스를 가리키는데 그 대상이 사라진 경우**(댕글링)를 탐지합니다. 이는 공격자가
해당 리소스를 선점해 서브도메인을 장악할 수 있는 고위험 취약점으로, 결과 보고서의 취약점
목록에 `takeover` 소스로 함께 표시됩니다. **HTTP 요청 없이 DNS 조회만** 수행합니다.

---

## 공인 IP 보호 & DNS 하이재킹 주의 (안전장치)

`recon`은 **기본적으로 사설/로컬 IP만 스캔**하고, 대상이 **공인(외부) IP로 해석되면
경고를 출력한 뒤 그 대상을 스캔에서 제외**합니다. 실수로 남의 서버를 공격하는 사고를
코드 차원에서 막기 위한 안전장치입니다.

```text
[!] 경고: 공인(외부) IP 8.8.8.8 (app.test.local) 는 스캔에서 제외했습니다.
    의도한 대상이면 -allow-public 을 지정하세요. (DNS 하이재킹/오타 여부를 먼저 확인)
```

- 사설/로컬 IP(`10.x`, `172.16~31.x`, `192.168.x`, `127.x`, IPv6 `fd00::/7` 등)만 기본 허용
- 공인 IP를 **정말로 점검할 권한이 있다면** `-allow-public` 을 붙여야 진행됩니다

### ⚠️ 왜 이 기능이 필요한가 — DNS 하이재킹

`app.test.local` 처럼 **공인 DNS에 없는 이름**을 대상으로 하면, 일부 ISP(특히 국내
통신사)는 "없는 도메인"에 대해 **자기네 안내/광고 서버 IP(예: `218.38.x.x`)를 대신
응답**합니다. 이걸 그대로 믿고 스캔하면 **의도치 않게 외부 ISP 서버를 공격**하게 됩니다.

`recon`의 공인 IP 차단이 이 사고를 1차로 막지만, **근본 해결은 이름을 올바른 로컬 IP로
고정**하는 것입니다.

**해결: `/etc/hosts` 에 로컬 IP로 못 박기**

```bash
# 대상이 어디로 해석되는지 먼저 확인
getent hosts app.test.local        # 218.38.x.x 가 나오면 하이재킹된 것

# /etc/hosts 에 실제 VM/도커 IP로 고정 (관리자 권한 필요)
echo "127.0.0.1   app.test.local" | sudo tee -a /etc/hosts

# 다시 확인 후 실행
getent hosts app.test.local        # 이제 127.0.0.1 이어야 정상
go run ./cmd/recon -domain app.test.local -portscan
```

또는 이름 대신 **IP를 직접** 지정하세요: `-domain 127.0.0.1`.

---

## 외부 도구 세팅

`recon`은 실행 시 활성화된 단계에 필요한 도구가 없으면 경고를 출력하고, **자동 설치가
가능한 도구는 설치 여부를 물어본 뒤 설치**합니다. 도구는 `PATH`뿐 아니라 `go install`
설치 위치(`$(go env GOPATH)/bin`)에서도 자동으로 찾습니다.

| 도구 | 설치 방식 | `recon` 자동 설치 |
| --- | --- | --- |
| `nmap` | apt | 지원 (`y` 입력) |
| `nuclei` | `go install` | 지원 (`y` 입력) |
| `msfconsole` | 공식 설치 스크립트 | 미지원 (수동) |

### nmap

```bash
sudo apt-get update && sudo apt-get install -y nmap
nmap --version
```

### nuclei

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -version
```

`go install`은 바이너리를 `$(go env GOPATH)/bin`(기본 `~/go/bin`)에 설치합니다. `recon`은
이 위치를 자동 탐색하므로 `PATH`에 추가하지 않아도 됩니다.

### metasploit (msfconsole)

Metasploit은 설치가 무겁고 복잡해 `recon`이 자동 설치하지 않습니다. 아래 중 하나로 설치하세요.

**방법 A — 공식 설치 스크립트 (Ubuntu/WSL 권장)**

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
chmod 755 /tmp/msfinstall
sudo /tmp/msfinstall
```

**방법 B — 배포판 패키지 (Kali/Debian 계열)**

```bash
sudo apt-get install -y metasploit-framework
```

**설치 확인**

```bash
msfconsole -q -x "version; exit"
```

첫 실행 시 데이터베이스(msfdb) 설정을 묻는데, 이는 **Metasploit 자체의 선택 기능**입니다.
`recon`은 데이터베이스를 사용하지 않으므로 프롬프트에서 `no`를 입력해도 됩니다.

---

## metasploit이 실제로 하는 일 (중요)

`recon`의 metasploit 단계는 **정보 수집이 아니라, 알려진 CVE에 대해 실제로 exploit을
실행**해 취약 여부를 판정합니다. 기본 탑재 모듈은 다음과 같습니다.

| CVE | 대상 | 위험도(CVSS) |
| --- | --- | --- |
| `CVE-2017-5638` | Apache Struts2 원격코드실행(RCE) | 9.8 |
| `CVE-2021-41773` | Apache HTTP 경로 우회 RCE | 7.5 |
| `CVE-2021-44228` | Log4Shell (Log4j) | 10.0 |

동작 방식:

- 포트 스캔에서 찾은 **열린 포트를 모듈의 RPORT로 연결**해 실제 서비스에 정확히 시도합니다.
- **서비스가 일치하는 포트에만** 모듈을 실행합니다. 예: HTTP 전용 CVE 모듈은 `http`/`https`
  계열로 식별된 포트에만 시도하고, SSH·SMB·FTP 같은 포트에는 쏘지 않습니다(불필요한 공격·낭비 방지).
- 여러 모듈을 **고루틴으로 병렬 실행**합니다.
- exploit 성공 시 결과를 되돌려 받기 위해 **리버스 페이로드(reverse payload)** 를 사용합니다.
  이때 필요한 값이 아래 두 가지입니다.

### payload와 LHOST란? (직접 코딩할 필요 없음)

- **payload**: exploit이 성공했을 때 대상에서 실행될 코드입니다. **직접 작성하지 않습니다.**
  Metasploit에 이미 들어있는 것(예: `cmd/unix/reverse_bash`)을 **이름으로 고르기만** 하면
  Metasploit이 알아서 만들어 줍니다.
- **LHOST**: 대상이 결과를 **되돌려 보낼 내(공격자) IP 주소**입니다. 셸코드가 아니라 그냥 IP입니다.
  `recon`이 **로컬(사설) IP를 자동으로 감지**해 채워 넣습니다. 필요하면 코드에서 후보 IP를
  여러 개(사설/공인) 지정할 수도 있습니다.
- **LPORT**: 결과를 받을 포트. 모듈마다 **서로 다른 값을 자동 배정**해 충돌을 방지합니다.

> 🧪 **네트워크 조건:** 리버스 페이로드가 성공하려면 **대상이 내 LHOST로 되돌아오는 연결**이
> 가능해야 합니다. 대상과 recon이 **같은 격리 VM 네트워크**에 있으면 보통 문제없습니다.
> 인터넷 너머 대상이라면 공인 IP + 포트 포워딩이 필요합니다.

> ⏱️ Metasploit은 처음 로딩에 수십 초가 걸립니다. `-msf`/`-full` 실행 시 `-timeout 10m`
> 처럼 넉넉히 주세요. 기본 모듈 이름이 설치된 버전에 없으면 그 모듈만 건너뜁니다.

---

## 안전하게 테스트하는 법 (취약 서버 직접 띄우기)

실제 서비스를 공격하면 안 되므로, **내 VM에 일부러 취약한 서버를 띄워** 시험합니다.
[VulHub](https://github.com/vulhub/vulhub)는 CVE별 취약 환경을 docker로 바로 띄워 줍니다.

```bash
# 예: Struts2 CVE-2017-5638 취약 환경
git clone https://github.com/vulhub/vulhub
cd vulhub/struts2/s2-045
docker compose up -d      # http://<VM_IP>:8080 로 취약 서버 기동

# 내가 띄운 그 서버를 대상으로 recon 실행
go run ./cmd/recon -domain <VM_IP> -full -timeout 10m
```

---

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
      { "target": "93.184.216.34", "number": 8080, "protocol": "tcp", "state": "open", "service": "http-proxy" }
    ]
  },
  "vulnerabilities": [
    {
      "id": "CVE-2017-5638",
      "name": "93.184.216.34:8080 - Vulnerable (Apache Struts)",
      "target": "93.184.216.34:8080",
      "cvss": 9.8,
      "severity": "critical",
      "source": "metasploit"
    }
  ]
}
```

텍스트 형식(`-format text`, 기본)은 사람이 읽기 좋게 요약해 출력합니다.

---

## 프로젝트 구조

```text
recon/
├── backend/
│   ├── cmd/recon/            # CLI 진입점
│   ├── internal/
│   │   ├── handler/          # CLI 옵션 파싱 및 오케스트레이터 조립
│   │   ├── model/            # 도메인 모델 및 출력 포맷터
│   │   └── service/          # DNS·서브도메인·포트스캔(내장/nmap)·nuclei·msf·오케스트레이션
│   └── go.mod
├── deploy/                   # 배포/실행 환경
├── README.md
└── CLAUDE.md
```

## 테스트

```bash
cd backend
go test ./...          # 전체 단위 테스트
go test ./... -race    # 병렬 처리 안전성까지 검증
```

외부 도구(nmap/nuclei/msfconsole)가 없어도 테스트는 통과합니다. metasploit 실행 경로는
**가짜 msfconsole 바이너리를 주입**해 실제 설치 없이 검증합니다.

---

## 사용 범위 / 주의

- 이 도구는 **권한이 부여된 화이트해킹(승인된 침투 테스트)** 을 목적으로 하며, 권한이 있는
  경우 라이브 서비스 서버까지 대상으로 사용할 수 있도록 설계됩니다.
- **`-msf`는 실제로 exploit을 실행**합니다(대상에 부작용이 생길 수 있음). `-msf-search`/`-full`은 `check`(비침투 검증)만 수행해 부작용이 없습니다.
  반드시 **본인이 소유하거나 명시적으로 점검 권한을 받은, 격리된 VM/테스트 환경**에서만
  사용하세요. 무단 스캔·취약점 점검은 법적 책임을 초래합니다.
- 개발·테스트 단계에서는 라이브 서버를 대상으로 하지 않고, 격리된 VM/로컬 환경에 직접 구성한
  웹앱으로만 검증합니다. 이는 개발 편의를 위한 제약일 뿐, 도구의 대상 범위를 제한하지 않습니다.
