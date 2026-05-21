# 취약점 분류 표준 (Vulnerability Taxonomy)

> **적용 범위**: palantir 모든 skill — LLM-Check 단계에서 findings[] 작성 시 이 표를 기준으로
> `category` / `cwe_id` / `owasp_category` / 기본 `severity` / `scope.type` 을 결정한다.
> 이 표에 없는 취약점 유형은 `finding_writing_guide.md` → `severity_criteria.md` 순으로 참조하고,
> 신규 유형이 필요하면 이 파일을 업데이트한다.

---

## 1. Injection 취약점 (sec-scan-injection)

| 취약점 유형 | `category` (정확한 표준값) | `cwe_id` | `owasp_category` | 기본 `severity` | `scope.type` |
|---|---|---|---|---|---|
| SQL 인젝션 확정 (`${}+String`, JDBC concat) | `SQL인젝션` | `CWE-89` | `A03:2021 Injection` | `Critical` | `endpoint` |
| SQL 인젝션 잠재 (수동 확인 필요) | `SQL인젝션` | `CWE-89` | `A03:2021 Injection` | `High` | `endpoint` |
| OS Command 인젝션 (사용자 입력 도달 확정) | `OS Command Injection` | `CWE-78` | `A03:2021 Injection` | `Critical` | `endpoint` |
| OS Command 인젝션 (내부값·설정값·Dead Code) | `OS Command Injection` | `CWE-78` | `A03:2021 Injection` | `Medium` | `file` |
| SSI 인젝션 (`<!--#exec`, `<!--#include`) | `SSI Injection` | `CWE-97` | `A03:2021 Injection` | `Critical` | `file` |
| 서버사이드 템플릿 인젝션 (SSTI — SpEL/FreeMarker/Thymeleaf) | `SSTI` | `CWE-94` | `A03:2021 Injection` | `Critical` | `endpoint` |

### category 표준값 결정 규칙

- `SQL인젝션` — SQL 직접 조작 가능한 모든 경우. 확정/잠재 여부는 severity로 구분하며 category는 동일.
- `OS Command Injection` — `Runtime.exec`, `ProcessBuilder`, `child_process.exec/spawn`, `os.system` 등 OS 명령 실행 패턴 전체.
- `SSI Injection` — SSI 디렉티브(`<!--#exec`, `<!--#include`, `<!--#echo`) 직접 삽입.
- `SSTI` — SpEL parseExpression(), FreeMarker/Thymeleaf에 사용자 입력 문자열이 템플릿 변수로 전달되는 경우.

> **❌ 금지 category 값 예시**: `Injection / OS Command (Stored RCE Pattern)`, `SQL Injection` (영문),
> `injection`, `SQL인젝션(잠재)`, `OS 명령 실행`, `Command Injection` — 위 표준값 이외 사용 금지

---

## 2. XSS 취약점 (sec-scan-xss)

| 취약점 유형 | `category` (정확한 표준값) | `cwe_id` | `owasp_category` | 기본 `severity` | `scope.type` |
|---|---|---|---|---|---|
| 저장형 XSS (Persistent/Stored XSS) | `Persistent XSS` | `CWE-79` | `A03:2021 Injection` | `High` | `endpoint` |
| 반사형 XSS (Reflected XSS) | `Reflected XSS` | `CWE-79` | `A03:2021 Injection` | `High` | `endpoint` |
| DOM 기반 XSS (DOM XSS) | `DOM XSS` | `CWE-79` | `A03:2021 Injection` | `High` | `file` |
| 뷰 단 XSS (View XSS — 서버 템플릿 직접 출력) | `View XSS` | `CWE-79` | `A03:2021 Injection` | `High` | `file` |
| Open Redirect (리다이렉트 피싱) | `Open Redirect` | `CWE-601` | `A01:2021 Broken Access Control` | `High` | `endpoint` |
| XSS 필터 전체 미구현 (`filter_level: none`) | `XSS 필터 미구현` | `CWE-693` | `A05:2021 Security Misconfiguration` | `High` | `config` |
| XSS 필터 불완전 (`@RequestParam` 미보호·multipart 누락 등) | `XSS 필터 불완전` | `CWE-693` | `A05:2021 Security Misconfiguration` | `High` | `config` |

### CWE 매핑 결정 규칙 (CWE-79 vs CWE-693)

- **CWE-79** — XSS 페이로드가 **실행되는 인스턴스** (Persistent/Reflected/DOM/View XSS 각 발생 지점)
- **CWE-693** — **방어 메커니즘 결함** (필터 미구현, 필터 등록 누락, 커버리지 불완전)

> **판단 원칙**: "어느 endpoint에서 XSS가 발생하는가" → **CWE-79** /
> "XSS 방어 계층이 없거나 결함이 있는가" → **CWE-693**
>
> XSS 필터 finding(CWE-693)과 개별 XSS 인스턴스 finding(CWE-79)은 **항상 별개 finding으로 작성**한다.
> 예: 필터 미구현 1건(CWE-693) + Persistent XSS 3건(CWE-79) = 총 4개 finding.

### category 표준값 결정 규칙

- `Persistent XSS` / `Reflected XSS` / `DOM XSS` / `View XSS` — 4종 중 정확히 1종만 선택.
- `Open Redirect` — 사용자 입력을 리다이렉트 URL로 사용하는 모든 경우 (location.href, sendRedirect 포함).
- `XSS 필터 미구현` — filter_level: none, Lucy `FilterRegistrationBean` 등록 없음, AntiSamy 없음.
- `XSS 필터 불완전` — filter_level: jackson_requestbody_only(`@RequestParam` 미보호), multipartFilter 누락, 필수 문자 미차단.

> **❌ 금지 category 값 예시**: `XSS`, `크로스 사이트 스크립팅`, `Persistent/Reflected XSS`,
> `xss_filter`, `XSS필터`, `Stored XSS` — 위 표준값 이외 사용 금지

---

## 3. 공통 필드 열거값 (모든 skill 적용)

### result — findings[] 내 허용값 (엄격 적용)

| 값 | 의미 | 저장 위치 |
|---|---|---|
| `취약` | 취약점 확정 (TP) | `findings[]` |
| `정보` | 잠재 위협 · 수동 확인 필요 · Cross-module Entry Point 등 | `findings[]` |
| *(없음)* | FP 확정 (양호 · 오탐) | `findings[]` 제외 → **`evidence_trail[]`에만** `fp_corrected: true`로 기록 |

> ⚠️ **`findings[]`에 절대 사용 금지**: `양호`, `양호(FP)`, `수동검토필요`, `정보(수동검토필요)`, `안전`, `해당없음`
> FP 확정 항목은 findings[]에서 **완전히 제거**하고 evidence_trail[]에만 기록한다.

### diagnosis_method — 허용값 3종

| 값 | 의미 |
|---|---|
| `자동스캔(SAST)` | 스크립트 자동 탐지, LLM 검토 없음 |
| `교차검증(수동)` | 자동스캔 결과를 LLM이 코드 직접 확인으로 검증·보강 |
| `수동진단(LLM)` | 자동스캔 미탐지(FN), LLM이 직접 발굴한 신규 취약점 |

> `"auto-scan"`, `"llm-check"`, `"manual"` 등 영문 진단방법값 사용 금지.
> `source` 필드(auto-scan/llm-check/llm-check(fn-detected))는 영문 유지.

### scope.type — 허용값 5종

| 값 | 사용 조건 |
|---|---|
| `endpoint` | 특정 API endpoint 에서 발생하는 취약점 |
| `file` | 특정 소스 파일 자체가 취약 (JSP 직접 노출, JS DOM XSS, Dead Code 패턴 등) |
| `config` | 설정·필터·Security 설정 결함 (XSS 필터 미구현, CORS 오설정 등) |
| `dependency` | 외부 라이브러리 CVE |
| `global` | 서비스 전체에 영향 (전역 필터 완전 부재 강조 시) |

> ⚠️ `list`, `project`, `frontend-component`, `module`, `service` 등 비표준 값 사용 금지.
> XSS 필터 finding: `config`(필터 설정 파일 기준) 또는 `global`(전체 서비스 영향 강조) 중 택 1.

---

## 4. 데이터 보호 취약점 (sec-scan-data)

| 취약점 유형 | `category` (정확한 표준값) | `cwe_id` | `owasp_category` | 기본 `severity` | `scope.type` |
|---|---|---|---|---|---|
| 하드코딩 비밀값 (API Key, Password, Secret) | `HARDCODED_SECRET` | `CWE-798` | `A02:2021 Cryptographic Failures` | `High` | `file` |
| 민감정보 로그 출력 (PII, 카드번호, 비밀번호) | `SENSITIVE_LOGGING` | `CWE-532` | `A09:2021 Security Logging and Monitoring Failures` | `Medium` | `file` |
| 취약 암호화 알고리즘 (MD5, SHA1, DES, ECB) | `WEAK_CRYPTO` | `CWE-327` | `A02:2021 Cryptographic Failures` | `High` | `file` |
| JWT 서명 검증 미흡 (alg:none, 서명 미검증) | `JWT_INCOMPLETE` | `CWE-347` | `A02:2021 Cryptographic Failures` | `High` | `endpoint` |
| DTO 과도 노출 (Response에 민감 필드 포함) | `DTO_EXPOSURE` | `CWE-200` | `A01:2021 Broken Access Control` | `Medium` | `endpoint` |
| CORS 오설정 (wildcard origin, credentials) | `CORS_MISCONFIG` | `CWE-346` | `A05:2021 Security Misconfiguration` | `High` | `config` |
| 보안 헤더 누락 (HSTS, CSP, X-Frame-Options) | `SECURITY_HEADER` | `CWE-693` | `A05:2021 Security Misconfiguration` | `Medium` | `config` |
| 안전하지 않은 TLS 클라이언트 (인증서 검증 비활성화) | `INSECURE_TLS_CLIENT` | `CWE-295` | `A02:2021 Cryptographic Failures` | `Medium` | `file` |
| 안전하지 않은 역직렬화 | `UNSAFE_DESERIALIZATION` | `CWE-502` | `A08:2021 Software and Data Integrity Failures` | `Critical` | `file` |

### category 표준값 결정 규칙

- `HARDCODED_SECRET` — 소스코드·설정파일에 하드코딩된 자격증명, API 키, 비밀번호 전체.
- `SENSITIVE_LOGGING` — 로그 출력문에 개인식별정보(PII), 금융정보, 인증 자격증명이 포함되는 경우.
- `WEAK_CRYPTO` — 알고리즘 자체가 취약한 경우(MD5/SHA1 해시, DES/3DES 암호화, AES-ECB 모드).
- `JWT_INCOMPLETE` — `alg: none` 허용, 서명 미검증, 만료 미검증 등 JWT 처리 결함 전체.
- `DTO_EXPOSURE` — API 응답에 비밀번호 해시, 내부 식별자, PII 등이 포함된 DTO/Entity 직접 반환.
- `CORS_MISCONFIG` — `Access-Control-Allow-Origin: *` + credentials, 임의 Origin 반사, 미설정.
- `SECURITY_HEADER` — HTTP 응답에 HSTS/CSP/X-Frame-Options/X-Content-Type-Options 등 누락.
- `INSECURE_TLS_CLIENT` — `SSLContext.getInstance("SSL")`, 인증서 검증 비활성 TrustManager, 평문 채널 사용.
- `UNSAFE_DESERIALIZATION` — `ObjectInputStream`, Jackson 기본 타입, Redis 기본 직렬화 등 신뢰 불가 데이터 역직렬화.

> **❌ 금지 category 값 예시**: `Hardcoded Credential`, `Sensitive Data Exposure`, `Weak Cryptography`,
> `하드코딩`, `암호화 취약`, `보안헤더 미설정`, `CORS` — 위 표준값 이외 사용 금지

---

## 5. 파일 처리 취약점 (sec-scan-file)

| 취약점 유형 | `category` (정확한 표준값) | `cwe_id` | `owasp_category` | 기본 `severity` | `scope.type` |
|---|---|---|---|---|---|
| 파일 업로드 취약점 (확장자·MIME 미검증, 경로 조작) | `파일 업로드 취약점` | `CWE-434` | `A04:2021 Insecure Design` | `Critical` | `endpoint` |
| 파일 다운로드 경로 조작 (Path Traversal, LFI) | `파일 다운로드 경로 조작` | `CWE-22` | `A01:2021 Broken Access Control` | `High` | `endpoint` |
| 원격 파일 포함 (RFI, SSRF via file param) | `원격 파일 포함` | `CWE-918` | `A10:2021 Server-Side Request Forgery (SSRF)` | `High` | `endpoint` |
| 파일 처리 기능 없음 (범위 확인) | `파일 처리 범위 확인` | `N/A` | `A04:2021 Insecure Design` | `Informational` | `global` |

### category 표준값 결정 규칙

- `파일 업로드 취약점` — MultipartFile 처리 시 확장자/MIME 미검증, 저장 경로 미고정, 파일명 그대로 저장.
- `파일 다운로드 경로 조작` — 요청 파라미터로 파일 경로 조합, `../` 시퀀스 미차단, 절대 경로 허용.
- `원격 파일 포함` — 요청 파라미터의 URL을 서버가 직접 fetch/include하는 경우(URL param → HTTP 요청).
- `파일 처리 범위 확인` — 해당 모듈에 파일 처리 기능 자체가 없어 진단 불필요함을 명시할 때 사용.

> **❌ 금지 category 값 예시**: `FileProcessing/UPLOAD`, `File Upload`, `파일업로드`, `LFI`, `RFI`,
> `Path Traversal`, `파일 처리` — 위 표준값 이외 사용 금지

---

## 변경 이력

| 날짜 | 요약 |
|---|---|
| 2026-05-04 | 초기 작성 — injection/xss 진단 결과물 일관성 고도화 P0 작업 |
| 2026-05-07 | Section 4 (DATA), Section 5 (FILE) 추가 — schema 위반 방지 고도화 |
