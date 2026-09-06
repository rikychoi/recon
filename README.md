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
<img width="798" height="21" alt="image" src="https://github.com/user-attachments/assets/468e4af4-e647-4e7c-adb9-52cbda8c0bd2" />

명령어
<img width="1102" height="122" alt="image" src="https://github.com/user-attachments/assets/178caeda-5e0f-4940-9ea0-0fe7134d046f" />

결과 1 - 서브도메인

<img width="374" height="138" alt="image" src="https://github.com/user-attachments/assets/2ee3a579-9525-4ddf-94e1-9161a46a3a4d" />

결과 2 - DNS 레코드, 메일 서버

대상 도메인의 DNS 레코드(A·CNAME·MX·TXT), 메일 서버, 서브도메인을 조회해 공격 표면을 그립니다.
같은 IP를 가리키는 호스트는 하나로 묶어 중복 스캔을 방지합니다.

## 2. 서비스 인식 → 적용 취약점 자동 검색 및 검증 (Metasploit 자동화)
**2, 3번 기능의 이미지는 오픈소스 취약점 실습 플랫폼 vulhub를 대상으로 테스트한 결과입니다.**

<img width="1151" height="23" alt="image" src="https://github.com/user-attachments/assets/6db366ff-d32c-4b95-b46a-4b67a0cd33aa" />

명령어

<img width="677" height="195" alt="image" src="https://github.com/user-attachments/assets/8fafefaf-1a01-4b72-814f-5593bcd9b1b9" />

포트스캔 및 식별된 포트에 대한 취약점점검 실행

<img width="1375" height="172" alt="image" src="https://github.com/user-attachments/assets/fb80b74c-ef60-4946-b922-1a2bf43f7136" />

스캔된 포트 및 식별된 취약점

nmap `-sV`로 포트의 **제품·버전**(예: `Apache httpd 2.4.49`)을 인식하고, 그 제품에 해당하는
Metasploit 모듈을 `search`로 **실시간 발굴**한 뒤 `check`(비침투 검증)로 실제 취약 여부를 확인합니다.
어떤 모듈을 써야 하는지 몰라도, "감지된 서비스 → 맞는 취약점 점검"을 도구가 알아서 연결합니다.

## 3. 버전(CPE) 기반 CVE 정밀 검색

<img width="785" height="22" alt="image" src="https://github.com/user-attachments/assets/94d3a00d-deb3-40cf-8654-4ea10fe8ad9e" />

명령어

<img width="858" height="213" alt="image" src="https://github.com/user-attachments/assets/aec0ed6e-2177-457d-a5ef-0551eefa101f" />

포트스캐닝/취약점 점검 실행

<img width="626" height="108" alt="image" src="https://github.com/user-attachments/assets/97788cde-80a3-4a88-8108-17f32a66a915" />

포트스캐닝 결과

<img width="1408" height="62" alt="image" src="https://github.com/user-attachments/assets/b3b14cc8-fdb6-4972-8781-cd97e8fcef87" />

취약점 진단 결과

`-nvd` 지정 시, 인식한 CPE(제품+버전)로 **NVD에서 해당 버전의 CVE 목록**을 받아
그 CVE를 가진 모듈만 정밀 검색합니다. (예: `Apache httpd 2.4.49` → NVD CVE 수십 개 → 실제 모듈로 압축)

## 4. 서브도메인 취약점 (Dangling CNAME) 탐지
<img width="491" height="437" alt="image" src="https://github.com/user-attachments/assets/86441ec9-5500-4ea1-9f47-10c6af176274" />

desec.io를 이용해 의도적으로 dangling CNAME 생성

<img width="649" height="27" alt="image" src="https://github.com/user-attachments/assets/185e8424-26b1-4ea0-b06a-a6cf587b5fc0" />

1번의 자산식별 명령어 실행

<img width="1437" height="48" alt="image" src="https://github.com/user-attachments/assets/d8db22cb-a852-48de-815b-e33bb7770b12" />

댕글링 cname 탐지 시 취약점으로 출력


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


