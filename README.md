# palantir

**LLM 기반 SAST 보안 진단 자동화 도구** — Claude Code를 진단 에이전트로 활용해 소스코드 취약점 탐지·판정·보고서 생성·Confluence 게시·Jira 티켓 등록·이행점검까지 전 과정을 자동화한다.

```
소스코드  ──▶  Auto-Scan  ──▶  LLM-Check  ──▶  /sec-review  ──▶  보고서·클렌징  ──▶  Jira  ──▶  이행점검
(Bitbucket)   (후보 탐지)     (교차검증·      (자동판정 +       (Confluence)       (티켓)     (/sec-remediation-check)
                              수동진단)        수동 정밀검토)
```

- **진단 skill 7종**: injection · xss · file · data · auth · php · sca
- **판정 skill**: `/sec-review` — 규칙 → 과거 판정 이력 → 소스 대조 3단계 자동 판정, 클렌징·게시까지 무중단 수행
- **사후 skill**: `/sec-remediation-check` — Jira 티켓 단위 조치 여부 재검증

---

## 목차

1. [전체 워크플로](#전체-워크플로)
2. [빠른 시작 — 단일 레포 진단](#빠른-시작--단일-레포-진단)
3. [Skills 상세](#skills-상세)
   - [sec-scan-injection](#sec-scan-injection--injection-취약점) · [sec-scan-xss](#sec-scan-xss--cross-site-scripting) · [sec-scan-file](#sec-scan-file--파일-처리-취약점) · [sec-scan-data](#sec-scan-data--데이터-보호)
   - [sec-scan-auth](#sec-scan-auth--인증인가어뷰징) · [sec-scan-php](#sec-scan-php--레거시-php) · [sec-scan-sca](#sec-scan-sca--오픈소스-cve)
   - [언어별 지원 현황](#언어별-지원-현황)
4. [판정 — `/sec-review`](#판정--sec-review)
5. [최종 보고서 생성 — `approve_report.py`](#최종-보고서-생성--approve_reportpy)
6. [Jira 티켓 등록](#jira-티켓-등록)
7. [이행점검 — `/sec-remediation-check`](#이행점검--sec-remediation-check)
8. [보안 가드레일](#보안-가드레일)
9. [진단이력 업로드 — `audit_result`](#진단이력-업로드--audit_result)
10. [진단 현황 관리](#진단-현황-관리)
11. [배치 파이프라인](#배치-파이프라인--pipeline_runnerpy)
12. [디렉토리 구조](#디렉토리-구조)
13. [환경 설정](#환경-설정)

---

## 전체 워크플로

```
┌────────────┬──────────────────┬──────────────────────────┬──────────────────┬──────────────────┐
│  STEP 1    │     STEP 2       │         STEP 3           │     STEP 4       │     STEP 5       │
│  Clone     │   SAST/SCA 진단  │   판정 (/sec-review)     │  클렌징·보고·배포 │   이행점검        │
├────────────┼──────────────────┼──────────────────────────┼──────────────────┼──────────────────┤
│ clone_     │ /sec-scan-       │ §1a audit 정합성 검증    │ §5e 클렌징        │ /sec-remediation │
│ repo.py    │  injection       │ §1b 저영향 항목 제외      │  testbed 삭제 +  │  -check          │
│            │  xss             │ §4  자동 판정            │  레지스트리 게시  │  <TICKET-KEY>    │
│ testbed/   │  file            │   ① 판정 규칙            │ §6 approve_      │                  │
│ <repo>/    │  data            │   ② 과거 판정 이력       │  report.py       │ 조치완료/부분/    │
│            │  auth            │   ③ 소스 대조 정밀검토   │  --publish       │ 미조치 판정 →     │
│            │  (php 자동위임)  │ §5a 그룹 병합            │ • Confluence     │ Jira 코멘트 +     │
│            │  sca             │ §5b report_expand 생성   │ • Jira Gateway   │ 상태 전이(승인후) │
│            │                  │ §5d 서비스 특징·추가진단 │ • audit_result   │                  │
└────────────┴──────────────────┴──────────────────────────┴──────────────────┴──────────────────┘
```

> 각 skill은 독립 실행 단위다. 스캔 skill 완료 후 다음 skill이나 `/sec-review`로 자동 이행하지 않는다.
> 예외는 두 가지 — ① 스캔 skill이 PHP 레포를 만나면 `/sec-scan-php`로 위임, ② `/sec-review`는 판정 완료 후 클렌징과 보고서 게시까지 이어서 실행.

**산출물 흐름:**

```
state/<repo>/injection/<RUN_ID>/findings_INJ.json   ─┐
state/<repo>/xss/<RUN_ID>/findings_XSS.json          │
state/<repo>/file/<RUN_ID>/findings_FILE.json        │
state/<repo>/data/<RUN_ID>/findings_DATA.json        ├─▶ /sec-review ──▶ review_status / review_note
state/<repo>/auth/<RUN_ID>/findings_AUTH.json        │        │           report_expand
state/<repo>/php/<RUN_ID>/findings_php.json          │        │           state/audit_log.json (판정 기록)
state/<repo>/sca/<RUN_ID>/findings_SCA.json         ─┘        ▼
                                                    retroactive_cleanse.py → approve_report.py --publish
                                                              │
                     ┌──────────────────┬─────────────────────┼──────────────────┐
                     ▼                  ▼                     ▼                  ▼
              Confluence 페이지    Jira Gateway         audit_result      vuln_registry.json
              (최종 보고서)        (티켓 등록)          (Bitbucket)       (service_meta + runs[] + findings[])
```

**1 repo = 1 누적 JSON** (`state/<repo>/vuln_registry.json`):

```json
{
  "schema_version": "2.0",
  "service_meta": { "bb_project": "...", "service_characteristics": "...", "additional_diagnosis_needed": false },
  "runs": [ { "run_id": "20260617_1030", "confluence_url": "...", "finding_counts": {...} } ],
  "findings": [ { "uid": "...", "status": "open", "history": [...] } ]
}
```

---

## 빠른 시작 — 단일 레포 진단

`my-service-api` 를 처음부터 끝까지 진단하는 절차.

### Step 1 — 소스코드 Clone

```bash
# WSL에서 그대로 실행 — 내부에서 Windows PowerShell(git)을 자동 경유해 사내 Bitbucket에 접근
python3 tools/clone_repo.py <PROJECT_KEY> my-service-api
python3 tools/clone_repo.py <PROJECT_KEY> my-service-api --branch develop   # 브랜치 지정
```

- 브랜치를 지정하지 않으면 가장 최근 커밋된 안정 브랜치를 자동 감지한다.
- 소스는 `testbed/my-service-api/`, 메타데이터는 `state/my-service-api/repo_meta.json`에 저장된다.

### Step 2 — 진단 skill 실행

Claude Code 세션에서 슬래시 커맨드로 실행한다. 각 skill은 **자산 식별 → Auto-Scan → LLM-Check → Summary**를 확인 질문 없이 끝까지 진행하며, 결과는 **RUN_ID**(`YYYYMMDD_HHMM`)로 구분된다.

```
/sec-scan-injection  my-service-api
/sec-scan-xss        my-service-api
/sec-scan-file       my-service-api
/sec-scan-data       my-service-api
/sec-scan-auth       my-service-api     # Java/Kotlin Spring 백엔드만 해당
/sec-scan-sca        my-service-api
```

- PHP 레포라면 첫 스캔 skill이 `/sec-scan-php`를 대신 실행한다(이미 결과가 있으면 재실행하지 않음).
- Python 레포는 각 skill이 `shared/references/python_diagnosis_criteria.md` 기준으로 수동 진단한다.

```
state/my-service-api/
├── repo_meta.json
├── injection/20260609_1030/findings_INJ.json
├── xss/20260609_1045/findings_XSS.json
├── file/20260609_1100/findings_FILE.json
├── data/20260609_1115/findings_DATA.json
├── auth/20260609_1130/findings_AUTH.json
└── sca/20260609_1145/findings_SCA.json
```

### Step 3 — 판정 + 보고서 게시

```
/sec-review my-service-api                  # 레포 단위 모드 (skill별 최신 RUN_ID 자동 선택)
/sec-review 20260609_1030 my-service-api    # RUN_ID 모드
```

판정이 끝나면 클렌징(`retroactive_cleanse.py`)과 최종 보고서 생성·Confluence 게시·Jira 전송(`approve_report.py --publish`)까지 **자동으로 이어서 실행**된다. 별도로 보고서 명령을 실행할 필요는 없다.

```
=== 리뷰 완료 ===
정탐: 8건  /  오탐: 4건  /  미판정: 0건
수동 정밀검토: 3건 (유지 2 / 조정 1 / 오탐 0) — review_note '[수동검증]'
report_expand 생성: 8건

클렌징 완료 — testbed 삭제 / state 감사 / 클렌징 레지스트리 갱신
최종 보고서   : logs/final_my-service-api_<RUN_ID>.md
Confluence 게시: ✅ <page 링크>
```

### Step 4 — 이행점검 (조치 기한 이후)

```
/sec-remediation-check <TICKET-KEY>
```

---

## Skills 상세

### 공통 구조

| 단계 | 내용 |
|------|------|
| Phase 1 — 자산 식별 | `task_11_asset_identification.md` — 언어/프레임워크/빌드 시스템 판별, PHP는 위임·Python은 수동 진단 분기 |
| Auto-Scan | `shared/scripts/` 스캐너 실행 — 판정형(injection/xss/file/data/sca) 또는 **후보 태깅형**(auth/php) |
| LLM-Check | `cross_verification.md` + skill별 task 프롬프트로 교차검증·수동진단, `llm_verdict`·`manual_review_note` 기록 |
| Summary | `state/<repo>/<skill>/<RUN_ID>/summary_<skill>.md` |
| Phase C-1 | LLM 데이터 접근 로그 기록 (`llm_data_cleansing_policy.md`) — testbed 삭제는 `/sec-review`에서 |

> **HARD RULE**: 스캔 skill은 `reviewed`/`review_status`(사람 판정 필드)를 설정하지 않는다. 판정은 `/sec-review`만 부여한다(SCA 예외 — 아래 참조).

---

### `/sec-scan-injection` — Injection 취약점

**진단 항목**: SQL Injection · OS Command Injection · SSI Injection · SSTI · SpEL Injection

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin (Spring Boot, MyBatis, JPA, Querydsl) |
| 스크립트 | `scan_injection_enhanced.py` (endpoint별 양호/취약 판정), `scan_injection_patterns.py`, `scan_injection_rules.py` |
| 탐지 방식 | API 인벤토리(`scan_api.py`) 기반 Taint-flow 추적 — 외부 입력 → DB/OS 호출 경로 |
| 커스텀 규칙 | `shared/references/rules/semgrep/` (Kotlin 문자열 템플릿 SQL, `String.format` SQL, native query 조합, Thymeleaf SSTI 등), `rules/joern/` |
| 판정 기준 | `sec-scan-injection/references/injection_diagnosis_criteria.md` |

```
HTTP 요청 파라미터 (@RequestParam, @PathVariable, @RequestBody, request.getParameter())
             │
             ▼
    검증/바인딩 없이 전달?
    ┌────────┴────────┐
    │ YES (취약)       │ NO (양호)
    ▼                 ▼
  SQL 문자열 조합      PreparedStatement / MyBatis #{}
  MyBatis ${}         JPA 파라미터 바인딩
  Kotlin "${...}"     입력 검증·화이트리스트
  Runtime.exec()
```

> MyBatis `${}`는 파라미터 타입이 int여도 최소 잠재(4등급) 이상으로 판정한다(보수적 기준).

---

### `/sec-scan-xss` — Cross-Site Scripting

**진단 항목**: Persistent XSS · Reflected XSS · DOM XSS · Open Redirect · Proxy XSS · 전역 XSS 필터 부재

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin (Spring, JSP, Thymeleaf), JavaScript / TypeScript (React, Vue, Next.js) |
| 스크립트 | `shared/scripts/scan_xss.py` (v2.6) |
| 탐지 방식 | 출력 인코딩 누락 + 저장 후 재출력 경로 추적, 뷰 컨텍스트(JS 문자열 vs HTML 텍스트/속성) 분리 판정 |
| 주요 패턴 | `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `th:utext`, 무검증 리다이렉트 |

```
Persistent XSS:  자유텍스트 입력 ──▶ DB 저장 ──▶ 타 사용자 화면 출력 (인코딩 없음)
Reflected XSS:   URL 파라미터 ──▶ 즉시 HTML 응답 출력 (인코딩 없음)
DOM XSS:         location / 외부 응답 ──▶ innerHTML 등 위험 싱크 직접 삽입
Open Redirect:   파라미터의 URL ──▶ sendRedirect() 무검증
```

- 반복형 취약점은 영향 엔드포인트를 **확정·제외 모두 엔드포인트 단위로 전수 기재**한다. `tools/check_endpoint_coverage.py`가 누락을 기계적으로 대조한다.
- 전역 XSS 필터 권고는 입력 채널별로 분기한다 — 폼 파라미터는 서블릿 필터(Lucy/AntiSamy), `@RequestBody` JSON은 Jackson `JsonDeserializer`.

---

### `/sec-scan-file` — 파일 처리 취약점

**진단 항목**: File Upload · File Download · Path Traversal · LFI · RFI

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin (Spring) |
| 스크립트 | `shared/scripts/scan_file_processing.py` |
| 탐지 방식 | 파일명/경로 파라미터 검증 여부, 저장 위치의 웹 서빙 여부, 확장자 허용 목록 |

```java
// 취약 — 확장자 검증 없음
String filename = file.getOriginalFilename();
Files.copy(file.getInputStream(), Paths.get(uploadDir + "/" + filename));

// 안전 — 확장자 화이트리스트 + UUID 재명명
String ext = FilenameUtils.getExtension(filename);
if (!ALLOWED_EXTENSIONS.contains(ext.toLowerCase())) throw new InvalidFileException();
String savedName = UUID.randomUUID() + "." + ext;
```

> Path Traversal·악성파일 업로드 등 규정 명시 항목은 노출 범위를 이유로 등급을 낮추지 않는다(확정 5등급 / 요건 일부 미확인 시 잠재 4등급).
> MIME/magic bytes 검증 부재는 업로드 → 실행 체이닝이 확인될 때만 리포팅한다.

---

### `/sec-scan-data` — 데이터 보호

**진단 항목**: CORS · 하드코딩 자격증명 · JWT · 취약 암호화 · 민감정보 로깅 · TLS 검증 우회 · 디버그 모드 · 역직렬화

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin, JavaScript / TypeScript, 설정 파일(`application*.yml/properties`, `.env`) |
| 스크립트 | `shared/scripts/scan_data_protection.py` (v1.4) — 시크릿 값은 `secret_gate.py`로 자동 마스킹 |
| 옵션 | `--api-inventory` (auth skill과 API 인벤토리 공유) |

| 카테고리 | 탐지 내용 | 위험도 기준 |
|----------|-----------|-------------|
| `HARDCODED_SECRET` | DB/API/클라우드 자격증명 하드코딩 | 운영 동일 = High, 별도 = Medium (상한 High) |
| `SENSITIVE_LOGGING` | 로그에 개인정보·인증정보 출력 | 운영 LOG = 취약/High, debug LOG = 정보/Medium |
| `CORS_MISCONFIG` | 와일드카드/반사형 Origin + 자격증명 허용 | High |
| `JWT_INCOMPLETE` | `alg: none` 허용, 서명 검증 생략 | High |
| `WEAK_CRYPTO` | MD5/SHA1 해시, ECB 모드, 고정 IV | Medium |
| `INSECURE_TLS_CLIENT` | 인증서/호스트명 검증 비활성화 | 채널로 오가는 데이터 기준 |
| `DEBUG_MODE_ENABLED` / `UNSAFE_DESERIALIZATION` | 운영 디버그 노출, 신뢰할 수 없는 역직렬화 | 사안별 |

> Lombok `@ToString` PII 노출, 보안 헤더 부재 등 저영향 항목은 `/sec-review` §1b에서 리포팅 대상에서 제외된다.

---

### `/sec-scan-auth` — 인증/인가/어뷰징

**진단 항목**: Auth Bypass · 세션 관리 · Brute-force 방어 · IDOR/BOLA · 기능 수준 접근통제 누락 · Mass Assignment · Rate Limit 부재 · 멱등성 부재 · 클라이언트 신뢰 비즈니스 로직

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin Spring 백엔드 전용 (순수 프론트엔드는 "진단 대상 아님"으로 기록 후 종료) |
| 스크립트 | `scan_api.py` (API 인벤토리) → `scan_auth_baseline.py` (후보 태깅) |
| 판정 방식 | **Auto-Scan은 판정하지 않는다** — 전량 `result: "정보"`, `needs_review: true` 후보로 태깅하고 LLM-Check가 전량 수동 진단 |
| 판정 기준 | `sec-scan-auth/references/task_prompts/task_26_auth_abuse_review.md`, `vuln_taxonomy.md` §6 |

```
api_inventory.json (endpoint · auth_required · 파라미터 · 인가 애노테이션)
        │
        ▼  scan_auth_baseline.py — 후보 태깅
  IDOR_CANDIDATE              리소스 식별자 path param + 인증 필요 endpoint
  MISSING_AUTH_CANDIDATE      인증 없이 열린 POST/PUT/DELETE/PATCH
  ABUSE_KEYWORD_CANDIDATE     point/coupon/reward/event/gift 등 금전·리워드 키워드
  NO_AUTHZ_ANNOTATION_CANDIDATE  인증은 있으나 @PreAuthorize/@Secured 등 인가 근거 없음
        │
        ▼  LLM-Check — 비즈니스 맥락 기반 판정
  AUTH_BYPASS / SESSION_MGMT / BRUTE_FORCE_PROTECTION / IDOR /
  MISSING_FUNCTION_ACCESS_CONTROL / MASS_ASSIGNMENT / RATE_LIMIT_ABSENT /
  IDEMPOTENCY_ABSENT / CLIENT_TRUSTED_LOGIC
```

> `task26_llm.json`이 없거나 `findings_AUTH.json`의 `llm_checked`가 false면 업로드를 차단한다(미판정 후보의 보고서 유입 방지).

---

### `/sec-scan-php` — 레거시 PHP

**진단 항목**: SQLi · OS Command · LFI/RFI · Reflected XSS · Hardcoded Secret · Weak Crypto · Path Traversal · Eval/Code Injection(CWE-95) · Insecure TLS Client

| 항목 | 내용 |
|------|------|
| 대상 | 라우터·프레임워크 없는 raw PHP (1파일 = 1웹 진입점) |
| 스크립트 | `shared/scripts/scan_php_baseline.py` — 후보 태깅만 수행(정적분석기 없음) |
| 판정 방식 | LLM-Check가 candidate_type별 판정표로 전량 수동 진단 |
| 판정 기준 | `sec-scan-php/references/php_diagnosis_criteria.md`, `task_php_llm_review.md` |
| 실행 경로 | 5개 스캔 skill이 Phase 1에서 PHP를 감지하면 자동 위임 (`state/<repo>/php/*/findings_php.json`이 있으면 생략) |

- 벤더 라이브러리(PHPExcel 등)는 스캔 단계에서 제외한다.
- 동일 원인 후보는 1건으로 병합하고, 양호 처리한 후보는 근거를 함께 기록한다.

---

### `/sec-scan-sca` — 오픈소스 CVE

**진단 항목**: 오픈소스 라이브러리 알려진 취약점 (CVE/GHSA)

| 항목 | 내용 |
|------|------|
| 지원 빌드 | Gradle (전이 의존성 포함), npm (`package-lock.json`), Maven (`pom.xml` 단독일 때) |
| 스크립트 | `shared/scripts/scan_sca_gradle_tree.py` |
| 취약점 DB | **OSV.dev** (`querybatch` 일괄 조회) |
| 빌드 보정 | 사내 Nexus 전용 저장소 설정을 mavenCentral로 임시 치환, Windows JDK 자동 탐색 |

```
build.gradle / package-lock.json
        │  (pom.xml과 공존 시 Gradle 우선 — 전이 의존성 누락 방지)
        ▼
  gradle dependencies 트리 파싱  →  OSV.dev 조회  →  sca.json
        │
        ▼  LLM-Check (task_sca_llm_review.md)
  ① 실사용 grep  ② 발생 조건 코드 확인  ③ 관련성 판정  ④ 한국어 설명
        │
        ▼  3-Tier 분류 → findings_SCA.json
```

| Tier | 조건 | 처리 |
|------|------|------|
| Tier 1 — 취약 | 관련성 `적용` | 보고서 취약, 즉시 패치 |
| Tier 2 — 정보 | `제한적` + CVSS ≥ 9.0 | 보고서 정보, 공격 조건 명시 |
| Tier 3 — BOM 통합 | `제한적` + CVSS < 9.0 | `SCA-BOM-001` 1건으로 통합 (BOM 업그레이드 권고) |
| 제외 | `조건미충족` / `확인불가` | 보고서 제외 |

> **SCA 예외**: SCA는 LLM-Check 단계에서 `review_status`를 설정하는 유일한 skill이며 `/sec-review` 수집 대상에서 제외된다.
> 대신 보고서에 기본 제외되고, `approve_report.py --include-sca`를 사람이 지정해야 포함된다.

---

### 언어별 지원 현황

| 언어 | injection | xss | file | data | auth | sca |
|------|:---------:|:---:|:----:|:----:|:----:|:---:|
| Java / Kotlin (Spring) | 자동 | 자동 | 자동 | 자동 | 후보+LLM | Gradle/Maven |
| JavaScript / TypeScript | — | 자동 | — | 자동 | — | npm |
| PHP (raw) | `/sec-scan-php` 위임 (후보+LLM) |||||  — |
| Python | `python_diagnosis_criteria.md` 기준 LLM 수동 진단 ||||| — |

---

## 판정 — `/sec-review`

모든 스캔 skill 완료 후 실행한다. finding 순회 순서는 `injection > xss > file > data > auth > php` 로 고정이다.

```
/sec-review <repo>             # 레포 단위 모드 (skill별 최신 RUN_ID 자동 선택)
/sec-review <RUN_ID> <repo>    # RUN_ID 모드
```

### 실행 단계

| 단계 | 내용 |
|------|------|
| §0b–0d | audit 세션 등록, 판정 기준 파일 재로드, 중단 세션 재개 감지 |
| §1a | **audit 정합성 검증** — `reviewed: true`인데 audit_log에 사람 판정 기록이 없으면 재편입 (LLM 판정 유출 방지) |
| §1b | 저영향 정보성 카테고리 자동 제외 (`@ToString` PII, 보안 헤더 부재, 체이닝 미확인 MIME 등) |
| §2 | 전체 취약점 개요 표 출력 |
| §4 | **finding별 자동 판정** (아래) — 모든 finding이 `reviewed: true`로 종결, 스킵 없음 |
| §4c | `tools/audit_utils.py log-review`로 판정 근거 기록 (`decided_by: rule / auto / human`) |
| §5a | 그룹 병합 — 같은 파일 동일 유형, `HARDCODED_SECRET`/`DTO_EXPOSURE`는 파일 간 병합(severity 동일할 때만) |
| §5b | Phase 2 — 정탐 finding별 `report_expand`(코드 확인 결과·위험 시나리오·취약 위치) 생성 + 자기일관성 검증 + 엔드포인트 커버리지 대조 |
| §5d | 서비스 특징 분석 + 동적진단/모의해킹 추가 필요 여부 판단 (정탐 PoC·시나리오 종합) |
| §5e | **Phase C-2 클렌징** — `retroactive_cleanse.py`: testbed 삭제 + 클렌징 레지스트리 Confluence 게시 |
| §5f | 정탐 0건이면 체크리스트를 `전체양호`로 갱신 (레포 단위 모드 한정) |
| §6 | `approve_report.py --publish` 자동 실행 |

### §4 자동 판정 3단계

```
finding
  │
  ├─① 판정 규칙 매치? ─────────────▶ 즉시 적용                       decided_by: rule
  │    (보수적 기준·자격증명·로그/DTO·규정 명시 등급·최소 Medium 하한)
  │
  ├─② tools/judgment_lookup.py — 과거 유사 판정 검색 (top-k)
  │    confidence high ───────────▶ 채택                            decided_by: auto
  │    confidence low + 유지/상향 ─▶ 전제조건 검증 통과 시만 채택
  │    그 외 (none, low 하향) ─────▶ ③으로
  │
  └─③ 수동 정밀검토 — testbed 소스 대조 (없으면 재clone)
       검증 질문 1~3개 → 코드 근거(파일:라인) 확인 → 판정 확정
       review_note 앞에 [수동검증]                                   decided_by: human
```

- **보수적 기준 예시**: MyBatis `${}`, SpEL `StandardEvaluationContext`, Proxy XSS, 전역 XSS 필터 부재, OS Command Injection, DOM XSS → 취약/High.
- **판정 이력 인덱스**: `tools/consolidate_judgment_index.py`가 과거 판정을 클러스터 단위로 압축해 `state/precedent_index.json`을 만든다. leave-one-out 평가(`judgment_lookup.py --exclude-repo/--exclude-finding-id`)로 신뢰도 구간을 검증한다.
- `review_note`의 recommendation 1번 항목은 보고서 조치 요약으로 그대로 추출되므로 §5b에서 품질을 점검한다.

---

## 최종 보고서 생성 — `approve_report.py`

`/sec-review` §6에서 자동 실행된다. 수동 재생성이 필요할 때만 직접 실행한다.

```bash
python3 tools/approve_report.py --repo <repo> --publish                    # 레포 단위
python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish  # RUN_ID 단위
python3 tools/approve_report.py --repo <repo> --publish --include-sca      # SCA 포함
```

| 단계 | 내용 |
|------|------|
| `[1/4]` | 오탐 판정 적용 (오탐 → 양호) |
| `[2/4]` | 1차 보고서 생성 (`generate_report.py`) |
| `[3/4]` | 최종 보고서 생성 (`generate_final_report.py`) + Confluence 게시 — 보고 대상이 없으면 게시 생략 |
| `[4/4]` | Jira Gateway 전송 — 실제 전송 성공을 확인한 뒤 완료 요약 출력 |

| 옵션 | 설명 |
|------|------|
| `--publish` | Confluence 게시 + Jira 전송 + audit_result 업로드 |
| `--include-sca` | SCA findings 포함 (기본 제외) |
| `--parent <PAGE_ID>` / `--title` | 게시 위치·제목 지정 |
| `--force` | 기존 보고서 재생성 |
| `--force-publish` | 게시 게이트(메타데이터 검증 등) 우회 — 원인 확인 후에만 사용 |

**게시 전 게이트**: `repo_meta.json` 누락 시 `backfill_repo_meta.py`로 자동 복구, 시크릿 재검사(`secret_gate`), 병합 finding의 파일:라인·제목 유실 가드.

**보고서 구조** (`logs/final_<repo>_<RUN_ID>.md`): 진단 개요(레포·담당자·서비스 특징·추가진단 필요여부) → 취약점 개요(현황 + 보안 위협 + 조치 권고) → 취약점 목록 → finding별 상세(`:::expand` 매크로에 report_expand).

- **담당자 필드**: Vision API 우선 조회(`vision_status_db.py` 캐시) → Bitbucket 커밋자 기반 후보 순으로 결정.

---

## Jira 티켓 등록

`approve_report.py --publish`의 `[4/4]` 단계에서 **palantir-jira-gateway**로 전송되어 티켓이 생성된다.

| Jira 필드 | 내용 |
|-----------|------|
| 프로젝트 | `.env`의 `JIRA_PROJECT_KEY` |
| 제목 | `[보안] <finding 제목>` |
| 설명 (Wiki Markup) | 1. 진단 개요 → [필수 회신] 안내 → 2. 취약점 요약 표 → 참조 진단절차 |
| 조치 기한 | `JIRA_REMEDIATION_DATE_FIELD_ID` 커스텀 필드 (`setup_jira_custom_field.py`로 최초 1회 생성) |
| 라벨 | `YYYY-MM`, `YYMM`, `PALANTIR`, `{PROJECT_KEY}`, `정기`, repo명 |
| 담당자·watcher | Vision 담당자 사번 → 없으면 Bitbucket 최근 커밋자 기반 후보 |

| 도구 | 용도 |
|------|------|
| `create_jira_ticket.py` | 수동 티켓 생성 |
| `post_jira_comment.py` | 위키마크업 코멘트 게시 + 상태 전이 (`--reassign-to-developer`, `--edit-comment-id`) |
| `add_jira_project_role.py` | 담당자 배정이 불가한 외부 계정을 프로젝트 role에 추가 |
| `backfill_ticket_committers.py` / `backfill_jira_project_labels.py` | 기발급 티켓 담당자·라벨 소급 갱신 |
| `redact_live_jira_issue.py` | 발행된 티켓 본문의 미마스킹 자격증명 소급 마스킹 |

> Jira 쓰기(코멘트·상태 전이·담당자 변경·role 추가)는 기능 구현 승인과 별개로 **매번 실행 전 승인**을 받는다.

---

## 이행점검 — `/sec-remediation-check`

Jira 티켓에 명시된 조치 대상이 최신 소스에서 실제로 조치됐는지 재검증한다. 신규 진단이 아니라 기존 finding의 사후 검증이다.

```
/sec-remediation-check <TICKET-KEY>                      # 2차부터 직전 '조치완료' 항목은 이어받음(carry-forward)
/sec-remediation-check <TICKET-KEY> --full               # 전량 재검증
/sec-remediation-check <TICKET-KEY> --branch <BRANCH>    # 미병합 브랜치에서 확인 (--full 병행 권장)
```

| Phase | 내용 |
|-------|------|
| 0 | `fetch_jira_remediation_targets.py` — 티켓 2.2 요약표 파싱 → `state/<repo>/remediation/<TICKET>/targets.json` |
| 1 | (category + 파일:라인)으로 원본 finding 매칭, `/sec-review` 판정 교차확인 |
| 2 | 최신 소스 clone (브랜치 자동 감지 또는 `--branch`) |
| 3 | 항목별 판정 — 조치완료 / 부분조치 / 미조치 / 확인불가 / 검증생략 / 검증제외 / 조치제외 (`remediation_verdict_criteria.md`) |
| 4 | Jira 코멘트 게시 + 상태 전이 — **dry-run 결과 확인 후 승인 시에만 실제 POST** |

> 파일이 사라졌다고 바로 "확인불가"로 단정하지 않는다. 먼저 Jira 전체 코멘트에서 개발자 회신(이전·삭제 사유)을 확인한다.
> 회차 간 비교는 `tools/ihaeng_compare.py`로 수행한다.

---

## 보안 가드레일

진단 산출물에는 고객사 소스코드와 자격증명이 포함될 수 있으므로 여러 단계에서 차단한다.

| 장치 | 위치 | 역할 |
|------|------|------|
| 시크릿 마스킹 | `shared/scripts/secret_gate.py` | 탐지·마스킹 공용 모듈 (AWS 키, `.env KEY=value`, 토큰 등). 스캐너·보고서·업로드가 공유 |
| 업로드 하드 게이트 | `tools/secret_scan_gate.py` | audit_result push 직전 최후 방어선 — 미마스킹 시크릿이 있으면 업로드 차단 |
| 소급 마스킹 | `retroactive_secret_mask.py`, `redact_live_jira_issue.py` | 기존 findings·발행 티켓 소급 정리 |
| LLM 데이터 클렌징 | `llm_data_cleansing_policy.md`, `phase_c_cleansing.md`, `retroactive_cleanse.py` | LLM 접근 로그 기록(C-1) → 판정 완료 후 testbed 삭제 + 레지스트리 게시(C-2). 레지스트리 row 축소 가드 포함 |
| 판정 감사 | `tools/audit_utils.py`, `state/audit_log.json` | 판정·보고서 게시·이행점검 이벤트 기록, 사람 판정 필드 침범 탐지 |
| 스키마 검증 | `shared/scripts/validate_findings.py` | `findings_*.json` lint (`output_schemas.md`) |
| 커버리지 점검 | `scan_coverage_check.py`, `check_endpoint_coverage.py` | 스캐너 대상/제외 파일, 영향 엔드포인트 누락 대조 |
| 테스트베드 보호 | `cleanup_testbed.py`, `backfill_repo_meta.py` | 진단 후 소스 삭제, 사전 존재 testbed는 삭제하지 않음 |

**공개 레포 원칙**: 고객사명·레포명·Confluence 페이지 ID·사내 호스트는 코드와 문서에 하드코딩하지 않는다. 운영 값은 `config/site.local.json`과 `.env`(모두 gitignore)에서 읽는다 — [환경 설정](#환경-설정) 참조.

---

## 진단이력 업로드 — `audit_result`

진단 결과 파일을 `secbb/audit_result` Bitbucket 레포에 업로드해 누적 이력을 관리한다. `approve_report.py --publish` 실행 시 자동 업로드된다.

```
secbb/audit_result/
└── <repo>/<YYYYMMDD>/
    ├── findings_INJ.json · findings_XSS.json · findings_FILE.json · findings_DATA.json
    ├── findings_AUTH.json · findings_php.json · findings_SCA.json
    ├── scan_meta.json
    └── final_<repo>_<date>.md
```

```bash
python3 tools/push_audit_result.py --repo <repo> [--run-id <RUN_ID>]   # 단건
python3 tools/bulk_push_audit_result.py [--repos repo1,repo2] [--dry-run]   # 일괄
python3 tools/commit_report.py ...                                       # palantir-reports 레포 커밋
```

> WSL은 사내 Bitbucket에 직접 접근할 수 없으므로 업로드·clone 스크립트는 내부적으로 Windows PowerShell을 경유한다. 동시 실행 경쟁이나 non-fast-forward 발생 시 자동 재clone 후 재시도한다.

---

## 진단 현황 관리

진단 대상 체크리스트(`docs/scan_plan.md`, 로컬 전용)와 Confluence 현황 페이지를 동기화하는 도구.

| 도구 | 용도 |
|------|------|
| `list_target_repos.py` | Bitbucket에서 진단 대상 서비스군 레포 전수 조사 (`target_repo_keywords` / `target_project_keys`) |
| `update_scan_plan.py` | 체크리스트 행 갱신 + Confluence 동기화 (`--all-clear <repo>` 전체양호 처리) |
| `sync_plan_confluence.py` | 진단 계획·클렌징 레지스트리 등 관련 페이지 일괄 동기화 |
| `build_service_history_table.py` | 서비스별 신청이력·결과 현황 표 생성 |
| `build_system_code_scan_status.py` + `system_code_lookup.py` | 전사 시스템코드별 진단 현황 집계 (`group_rules` 기준 서비스군 분류) |
| `lookup_repo_meta.py` | repo 슬러그 → 프로젝트 키 / Fortify 티켓 키 조회 |
| `backfill_fortify_flags.py`, `backfill_exposure_col.py`, `add_system_code_col_to_plan.py` | 체크리스트에 Fortify 이력·대내외 구분·시스템코드 열 백필 |
| `build_maintainer_cache.py`, `fix_vision_assignee_id.py`, `backfill_maintainer_id.py` | 담당자 캐시·사번 보정 |

---

## 배치 파이프라인 — `pipeline_runner.py`

여러 레포를 Claude 세션 없이 일괄 진단한다. `trigger/scan_targets.yaml`에서 `active: true`인 레포를 처리한다.

```bash
python3 tools/pipeline_runner.py --dry-run                 # 계획 확인
python3 tools/pipeline_runner.py                           # 전체 실행
python3 tools/pipeline_runner.py --repos my-service-api
python3 tools/pipeline_runner.py --skills injection sca
python3 tools/pipeline_runner.py --no-clone                # testbed에 소스가 있을 때
python3 tools/pipeline_runner.py --report draft            # 완료 후 1차 보고서 생성
```

- 배치에서 실행 가능한 skill은 `injection · xss · file · data · sca` 이다(`run_skill.py`). auth·php는 Claude Code 세션의 슬래시 커맨드로 실행한다.
- 야간 배치는 **레포 크기 오름차순**으로 정렬해 rate limit 조기 소진을 피한다.
- rate limit으로 LLM-Check가 끊기면 **동일 RUN_ID**로 재개한다 (`pipeline_runner.py`는 새 RUN_ID를 만들기 때문에 재개 용도로 쓸 수 없다):

```bash
python3 tools/run_skill.py <skill> testbed/<repo> state/<repo>/<skill>/<RUN_ID> --skip-scan
```

- 완료 판정은 `llm_checked` 값이 아니라 `llm_check_failed.json` 부재 여부로 한다.

```yaml
# trigger/scan_targets.yaml (gitignore — 예시: trigger/scan_targets.example.yaml)
defaults:
  provider: claude-cli
  max_budget_usd: 3.0
  max_turns: 80

targets:
  - project: MY_PROJECT
    repo: my-service-api
    active: true
    repo_type: backend       # backend | frontend | php (생략 시 자동 감지)
    skills: [injection, xss] # 생략 시 repo_type별 기본값
```

---

## 디렉토리 구조

```
palantir/
├── .claude/commands/               # 슬래시 커맨드
│   ├── sec-scan-{injection,xss,file,data,auth,sca}.md
│   ├── sec-review.md
│   └── sec-remediation-check.md
│
├── sec-scan-injection/             # SKILL.md + references/ (진단 기준, task 프롬프트)
├── sec-scan-xss/
├── sec-scan-file/
├── sec-scan-data/
├── sec-scan-auth/                  # task_26_auth_abuse_review.md
├── sec-scan-php/                   # php_diagnosis_criteria.md, task_php_*.md
├── sec-scan-sca/                   # task_sca.md, task_sca_llm_review.md
├── sec-scan-remediation/           # remediation_verdict_criteria.md, task_31_remediation_verify.md
│
├── shared/
│   ├── references/                 # 공통 기준 — severity_criteria, vuln_taxonomy, cross_verification,
│   │   │                           #   output_schemas, finding_writing_guide, python_diagnosis_criteria,
│   │   │                           #   llm_data_cleansing_policy, secret_scanning, taint_tracking ...
│   │   ├── rules/semgrep/          # 커스텀 Semgrep 규칙
│   │   ├── rules/joern/            # Joern taint 쿼리
│   │   └── task_prompts/task_11_asset_identification.md
│   └── scripts/                    # 스캐너·공용 모듈
│       ├── scan_api.py                 # API 인벤토리
│       ├── scan_injection_enhanced.py · scan_injection_patterns.py · scan_injection_rules.py
│       ├── scan_xss.py · scan_file_processing.py · scan_data_protection.py
│       ├── scan_auth_baseline.py · scan_php_baseline.py
│       ├── scan_sca_gradle_tree.py
│       ├── secret_gate.py · validate_findings.py
│       └── fetch_jira_remediation_targets.py
│
├── tools/                          # 판정·보고·배포·운영 도구 (위 각 절 참조)
│   ├── clone_repo.py · pipeline_runner.py · run_skill.py
│   ├── judgment_lookup.py · consolidate_judgment_index.py · audit_utils.py
│   ├── approve_report.py · generate_report.py · generate_final_report.py · publish_confluence.py
│   ├── create_jira_ticket.py · post_jira_comment.py · jira_utils.py
│   ├── retroactive_cleanse.py · secret_scan_gate.py · check_endpoint_coverage.py
│   ├── push_audit_result.py · bulk_push_audit_result.py · commit_report.py
│   ├── update_scan_plan.py · sync_plan_confluence.py · list_target_repos.py
│   └── site_config.py              # config/site.local.json 로더
│
├── config/
│   ├── site.example.json           # 운영 설정 키 예시 (공개)
│   └── site.local.json             # 실제 값 (gitignore)
├── trigger/
│   ├── scan_targets.example.yaml   # 배치 대상 예시 (공개)
│   └── scan_targets.yaml           # 실제 운영 파일 (gitignore)
├── docs/
│   ├── report_pipeline_guide.md    # 보고서·Jira 본문 생성 로직 가이드
│   └── design/                     # 설계 문서 (sec-review 자율화 등)
│
├── testbed/                        # 고객사 소스코드 (gitignore)
├── state/                          # 진단 결과 (gitignore)
│   ├── audit_log.json              # 판정·게시·이행점검 감사 로그
│   ├── precedent_index.json        # 판정 이력 압축 인덱스
│   └── <repo>/
│       ├── repo_meta.json · review_meta.json · vuln_registry.json
│       ├── llm_data_access_log.json
│       ├── <skill>/<RUN_ID>/findings_*.json
│       └── remediation/<TICKET>/
├── logs/                           # 최종 보고서 Markdown (gitignore)
├── RELEASE_NOTES.md · ROADMAP.md
├── requirements.txt
└── CLAUDE.md                       # Claude Code 프로젝트 지침 (자율 완주·skill 경계 규칙)
```

---

## 환경 설정

### 요구사항

- Python 3.10+
- [Claude Code CLI](https://claude.ai/code) — `claude` 명령어 (Claude Pro 구독, 기본 provider)
- Windows PowerShell + git — 사내 Bitbucket clone/push 경유 (WSL에서 자동 호출)
- JDK — Gradle SCA 의존성 트리 추출 (`/mnt/c/Users/*/.jdks` 자동 탐색)

```bash
pip install -r requirements.txt
```

### `.env` — 자격증명·호스트 (gitignore)

`cp .env.example .env` 후 값을 채운다.

```bash
# ── Confluence ────────────────────────────────
CONFLUENCE_BASE_URL=          CONFLUENCE_SPACE_KEY=
CONFLUENCE_PARENT_ID=         CONFLUENCE_TOKEN=          # Bearer
CONFLUENCE_REGISTRY_PAGE_ID=                             # 클렌징 레지스트리

# ── Bitbucket ─────────────────────────────────
BITBUCKET_BASE_URL=           BITBUCKET_TOKEN=           # 내부 (audit_result)
CUSTOMER_BB_TOKEN=            AUDIT_RESULT_REPO_URL=     # 고객사 (clone)

# ── Jira ──────────────────────────────────────
JIRA_URL=                     JIRA_TOKEN=
JIRA_EMAIL=                                              # Server/DC: 빈값, Cloud: 이메일
JIRA_PROJECT_KEY=                                        # 티켓 키 접두어
JIRA_REMEDIATION_DATE_FIELD_ID=
JIRA_GATEWAY_URL=             JIRA_TOKEN_REMEDIATION=
JIRA_DEFAULT_ASSIGNEE=                                   # 담당자 미확인 시 기본값

# ── 담당자 조회 / Fortify ─────────────────────
VISION_BASE_URL=              JENKINS_BASE_URL=
JENKINS_USER=                 JENKINS_TOKEN=
SSC_BASE_URL=                 SSC_TOKEN=

# ── LLM Provider (claude-cli는 설정 불필요) ────
GEMINI_API_KEY=               OPENAI_API_KEY=
```

### `config/site.local.json` — 고객사·운영 설정 (gitignore)

공개 레포에 두지 않는 운영 값. 키 목록은 `config/site.example.json`을 복사해 채운다. 파일이 없으면 빈 기본값으로 동작한다.

| 키 | 용도 |
|----|------|
| `customer_label` | 보고서·레지스트리에 표기할 고객사 라벨 |
| `target_repo_keywords`, `target_project_keys` | 진단 대상 레포 전수 조사 기준 |
| `project_labels`, `group_rules`, `extra_acronyms` | 프로젝트 표시명, 서비스군 분류 정규식, 보고서 약어 |
| `plan_page_title`, `plan_parent_page_id`, `scan_plan_page_id` | 진단 계획 Confluence 페이지 |
| `cleansing_page_id`, `service_history_page_id`, `service_history_page_title` | 클렌징 레지스트리·신청이력 페이지 |
| `process_guide_url` | Jira 티켓 본문의 진단 절차 링크 |
| `internal_email_domains` | 커밋자 중 내부 인원 판별 |

> 새 PC에서는 레포를 clone한 뒤 `.env`와 `config/site.local.json`을 별도로 복사해야 한다.

### LLM Provider

| Provider | 설정 | 특징 |
|----------|------|------|
| `claude-cli` | 불필요 | Claude Pro 구독 활용, **기본값** |
| `anthropic` / `openai` / `gemini` / `openrouter` 등 | 해당 API 키 | `run_skill.py --provider`로 지정 (배치 전용) |

---

## 관련 레포

| 레포 | 경로 | 역할 |
|------|------|------|
| **palantir** (이 레포) | `~/palantir/` | 진단 도구, skill, 스크립트 |
| palantir-testbed | `testbed/` | 고객사 소스코드 clone 저장소 |
| palantir-state | `state/` | 진단 결과 JSON / 감사 로그 |
| palantir-reports | `~/palantir-reports/` | 서비스별 최종 보고서 누적 |
| palantir-jira-gateway | `~/palantir-jira-gateway/` | 보고서 → Jira 티켓 변환·발행 게이트웨이 |
| audit_result | Bitbucket secbb | findings JSON + 보고서 이력 |
