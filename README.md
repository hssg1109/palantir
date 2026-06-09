# palantir

**LLM 기반 SAST 보안 진단 자동화 도구** — Claude Code를 진단 에이전트로 활용해 소스코드 취약점 탐지·리뷰·보고서 생성·Confluence 게시·Jira 티켓 등록까지 전 과정을 자동화한다.

```
소스코드  ──▶  정적 분석  ──▶  LLM 교차검증  ──▶  인터랙티브 리뷰  ──▶  보고서  ──▶  Jira
(Bitbucket)   (5개 skill)     (오탐 필터링)     (/sec-review)       (Confluence)    (티켓)
```

---

## 목차

1. [전체 워크플로](#전체-워크플로)
2. [빠른 시작 — 단일 레포 진단](#빠른-시작--단일-레포-진단-tutorial)
3. [Skills 상세](#skills-상세)
   - [sec-scan-injection](#sec-scan-injection--injection-취약점)
   - [sec-scan-xss](#sec-scan-xss--cross-site-scripting)
   - [sec-scan-file](#sec-scan-file--파일-처리-취약점)
   - [sec-scan-data](#sec-scan-data--데이터-보호)
   - [sec-scan-sca](#sec-scan-sca--오픈소스-cve)
4. [인터랙티브 리뷰](#인터랙티브-리뷰--sec-review)
5. [최종 보고서 생성](#최종-보고서-생성--approve_reportpy)
6. [Jira 티켓 등록](#jira-티켓-등록)
7. [진단이력 업로드](#진단이력-업로드--audit_result)
8. [배치 파이프라인](#배치-파이프라인--pipeline_runnerpy)
9. [디렉토리 구조](#디렉토리-구조)
10. [환경 설정](#환경-설정)

---

## 전체 워크플로

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           palantir 진단 파이프라인                             │
├──────────┬──────────────┬───────────────┬───────────────┬─────────────────── ┤
│  STEP 1  │    STEP 2    │    STEP 3     │    STEP 4     │      STEP 5         │
│  Clone   │  SAST 진단   │   리뷰        │   보고서       │   배포              │
│          │              │               │               │                     │
│ clone_   │ /sec-scan-   │ /sec-review   │ approve_      │ • Confluence 게시   │
│ repo.py  │ injection    │  <RUN_ID>     │  report.py    │ • Jira 티켓 생성    │
│          │ /sec-scan-   │  <repo>       │  --publish    │ • audit_result      │
│ testbed/ │ xss          │               │               │   업로드            │
│ <repo>/  │ /sec-scan-   │ 정탐/오탐     │ logs/         │                     │
│          │ file         │ 판정          │ final_*.md    │                     │
│          │ /sec-scan-   │               │               │                     │
│          │ data         │               │               │                     │
│          │ /sec-scan-   │               │               │                     │
│          │ sca          │               │               │                     │
└──────────┴──────────────┴───────────────┴───────────────┴─────────────────── ┘
```

**산출물 흐름:**

```
state/<repo>/injection/<RUN_ID>/findings_INJ.json   ─┐
state/<repo>/xss/<RUN_ID>/findings_XSS.json          ├─▶ /sec-review
state/<repo>/file/<RUN_ID>/findings_FILE.json         │      │
state/<repo>/data/<RUN_ID>/findings_DATA.json         │      ▼
state/<repo>/sca/<RUN_ID>/findings_SCA.json          ─┘  review_status 기록
                                                              │
                                                              ▼
                                                    logs/final_<repo>_<date>.md
                                                              │
                                          ┌───────────────────┼───────────────┐
                                          ▼                   ▼               ▼
                                   Confluence 페이지    Jira 티켓 생성    audit_result
                                   (자동 게시)          (취약점별)        (Bitbucket)
```

---

## 빠른 시작 — 단일 레포 진단 (Tutorial)

`my-service-api` 를 처음부터 끝까지 진단하는 전체 절차를 단계별로 설명한다.

### Step 1 — 소스코드 Clone

> **Windows PowerShell에서 실행** (WSL 환경은 사내 Bitbucket 네트워크 미지원)

```powershell
# PowerShell
python3 tools/clone_repo.py <PROJECT_KEY> my-service-api
```

성공 시 `testbed/my-service-api/` 에 소스코드가 저장된다.

```
testbed/
└── my-service-api/
    ├── src/
    ├── build.gradle
    └── ...
```

---

### Step 2 — SAST 진단 (5개 Skill 순차 실행)

Claude Code 세션에서 슬래시 커맨드로 실행한다. 각 skill은 독립적으로 실행되며 **RUN_ID**(`YYYYMMDD_HHMM`)로 결과가 구분된다.

```
/sec-scan-injection  my-service-api
```

진단 완료까지 기다린 후 다음 skill 실행:

```
/sec-scan-xss        my-service-api
/sec-scan-file       my-service-api
/sec-scan-data       my-service-api
/sec-scan-sca        my-service-api
```

각 skill 완료 후 아래와 같이 결과 파일이 생성된다:

```
state/my-service-api/
├── injection/
│   └── 20260609_1030/
│       ├── findings_INJ.json     ← 탐지 결과
│       └── scan_meta.json        ← 진단 메타데이터
├── xss/
│   └── 20260609_1045/
│       └── findings_XSS.json
├── file/
│   └── 20260609_1100/
│       └── findings_FILE.json
├── data/
│   └── 20260609_1115/
│       └── findings_DATA.json
└── sca/
    └── 20260609_1130/
        └── findings_SCA.json
```

> **팁**: SCA skill은 RUN_ID가 다를 수 있다. `/sec-review` 는 skill별 최신 RUN_ID를 자동 감지하므로 문제 없다.

---

### Step 3 — 인터랙티브 리뷰

5개 skill 완료 후 `/sec-review` 로 findings를 한 번에 리뷰한다.

```
/sec-review 20260609_1030 my-service-api
```

또는 RUN_ID 없이 (skill별 최신 자동 선택):

```
/sec-review my-service-api
```

리뷰 화면 예시:

```
=== 리뷰 대상 전체 목록 ===
레포   : my-service-api
대상   : 12건

 #  | 분류      | ID          | 위험도 | 제목 요약
----+-----------+-------------+--------+------------------------------------------
  1 | injection | INJ-001     | High   | SQL Injection — 사용자 검색 파라미터 미검증
  2 | xss       | XSS-001     | Medium | Reflected XSS — 에러 메시지 출력
  3 | data      | DATA-003    | High   | 하드코딩 API Key — application.properties
...
```

**판정 입력:**

| 입력 | 동작 |
|------|------|
| `1` 또는 `y` | 정탐 → 결과 판정(취약/정보) → 위험도 조정 → 메모 |
| `0` 또는 `n` | 오탐 → 사유 입력 |
| `s` 또는 Enter | 스킵 (나중에 판정) |
| `q` | 종료 (진행 저장) |
| 질문 텍스트 | Claude가 소스코드 직접 확인 후 분석 |

모든 판정 완료 후 **Phase 2** 가 자동 실행된다 — 정탐 finding마다 `report_expand`(보고서 상세 분석 블록) 자동 생성.

---

### Step 4 — 최종 보고서 생성 + 배포

```bash
# 보고서 생성 + Confluence 게시 + Jira 티켓 + audit_result 업로드 (전체 자동)
python3 tools/approve_report.py --run-id 20260609_1030 --repo my-service-api --publish
```

실행 결과:

```
[approve]  정탐 8건 / 오탐 4건 확인
[report]   logs/final_my-service-api_20260609.md 생성
[publish]  Confluence 게시 완료 → https://wiki.company.com/...
[jira]     Jira 티켓 8건 생성 완료
[audit]    VULCHK/audit_result 업로드 완료
```

---

## Skills 상세

### `/sec-scan-injection` — Injection 취약점

**진단 항목**: SQL Injection · OS Command Injection · SSI Injection

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin (Spring Boot), PHP |
| 스크립트 | `shared/scripts/scan_injection_enhanced.py` |
| 탐지 방식 | Taint-flow 추적 — 외부 입력 → DB/OS 호출 경로 |
| 주요 탐지 패턴 | `@RequestParam`, `HttpServletRequest.getParameter()`, JDBC `Statement.execute()` 직접 사용, MyBatis `${}` 치환자 |

**탐지 원리:**

```
HTTP 요청 파라미터
    (@RequestParam, @PathVariable, request.getParameter())
             │
             ▼
    검증/인코딩 없이 전달?
             │
    ┌────────┴────────┐
    │ YES (취약)       │ NO (안전)
    ▼                 ▼
  SQL 쿼리 직접 조합   PreparedStatement / @Param
  OS exec() 호출      MyBatis #{} 바인딩
  SSI 포함 구문        입력 검증 로직
```

**주요 Finding 필드:**

```json
{
  "finding_id": "INJ-001",
  "category": "SQL_INJECTION",
  "severity": "High",
  "title": "SQL Injection — 사용자 검색 파라미터 미검증",
  "scope": {
    "affected_file": "src/main/java/com/example/UserService.java",
    "affected_line": 142
  },
  "evidence": {
    "snippet": "String query = \"SELECT * FROM users WHERE id='\" + userId + \"'\";"
  }
}
```

---

### `/sec-scan-xss` — Cross-Site Scripting

**진단 항목**: Persistent XSS · Reflected XSS · DOM XSS · Open Redirect

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin (Spring), JavaScript / TypeScript (React, Vue, Next.js) |
| 스크립트 | `shared/scripts/scan_xss.py` |
| 탐지 방식 | 출력 인코딩 누락 + DB 저장 후 재출력 경로 추적 |
| 주요 탐지 패턴 | `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, Thymeleaf `th:utext`, 무검증 리다이렉트 |

**XSS 유형별 공격 경로:**

```
Persistent XSS:  사용자 입력 ──▶ DB 저장 ──▶ 타 사용자 화면 출력 (인코딩 없음)
Reflected XSS:   URL 파라미터 ──▶ 즉시 HTML 응답 출력 (인코딩 없음)
DOM XSS:         location.hash/search ──▶ innerHTML 직접 삽입
Open Redirect:   파라미터의 URL ──▶ response.sendRedirect() 무검증
```

---

### `/sec-scan-file` — 파일 처리 취약점

**진단 항목**: File Upload · File Download · LFI · RFI

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin (Spring), PHP |
| 스크립트 | `shared/scripts/scan_file_processing.py` |
| 탐지 방식 | 파일명/경로 파라미터 검증 여부, 저장 위치, MIME 검증 |
| 주요 탐지 패턴 | `MultipartFile` 확장자 미검증, `../` 경로 조작, 절대경로 파라미터 노출 |

**취약 패턴 예시:**

```java
// 취약 — 확장자 검증 없음
String filename = file.getOriginalFilename();
Files.copy(file.getInputStream(), Paths.get(uploadDir + "/" + filename));

// 안전 — 확장자 화이트리스트 + UUID 재명명
String ext = FilenameUtils.getExtension(filename);
if (!ALLOWED_EXTENSIONS.contains(ext.toLowerCase())) throw new InvalidFileException();
String savedName = UUID.randomUUID() + "." + ext;
```

---

### `/sec-scan-data` — 데이터 보호

**진단 항목**: CORS 설정 오류 · 하드코딩 Secrets · JWT 취약점 · 암호화 취약점 · PII 로깅

| 항목 | 내용 |
|------|------|
| 지원 언어 | Java / Kotlin, JavaScript / TypeScript |
| 스크립트 | `shared/scripts/scan_data_protection.py` |
| 탐지 방식 | 설정 파일 + 코드 패턴 분석, API 응답 PII 노출 추적 |
| 주요 탐지 패턴 | `allowedOrigins("*")`, API 키 하드코딩, `MD5`/`SHA1` 사용, `log.debug(userId)` |

**카테고리별 탐지 대상:**

| 카테고리 | 탐지 내용 | 위험 수준 |
|----------|-----------|-----------|
| `CORS_MISCONFIGURATION` | `Access-Control-Allow-Origin: *` + 자격증명 허용 | High |
| `HARDCODED_SECRET` | AWS key, API token, DB password 하드코딩 | Critical |
| `JWT_VULNERABILITY` | `alg: none` 허용, 서명 검증 생략 | High |
| `WEAK_CRYPTOGRAPHY` | MD5/SHA1 단방향 해시, ECB 모드 AES | Medium |
| `PII_LOGGING` | 로그에 주민번호, 전화번호, 비밀번호 출력 | Medium |

---

### `/sec-scan-sca` — 오픈소스 CVE

**진단 항목**: 오픈소스 라이브러리 알려진 취약점 (CVE)

| 항목 | 내용 |
|------|------|
| 지원 빌드 | Gradle (`build.gradle`, `gradle/libs.versions.toml`), npm (`package.json`) |
| 스크립트 | `shared/scripts/scan_sca_gradle_tree.py` |
| 탐지 방식 | 의존성 트리 파싱 → NVD CVE DB 조회 → LLM 실제 영향 검증 |
| CVE DB | NVD (National Vulnerability Database) |

**탐지 흐름:**

```
build.gradle / package.json
        │
        ▼
  의존성 트리 파싱
  (gradle dependencies 실행)
        │
        ▼
  버전별 CVE 조회
  (NVD API v2)
        │
        ▼
  LLM 실제 영향 검증
  └── 취약 API 실제 호출 여부 확인
  └── 공격 가능 경로 존재 여부 판단
        │
        ▼
  findings_SCA.json
```

**LLM 검증 예시:**

```
CVE-2021-44228 (Log4Shell) — log4j-core 2.14.1
LLM 판정: 실제 영향 있음
근거: LogManager.getLogger() 호출 확인됨 (UserService.java:23)
      외부 입력이 로그 메시지에 포함됨 (request.getParameter("query"))
```

---

## 인터랙티브 리뷰 — `/sec-review`

5개 skill 완료 후 실행. 모든 finding을 한 화면에서 순차 판정한다.

### 실행 형식

```
/sec-review <RUN_ID> <repo>    # 특정 RUN_ID 지정
/sec-review <repo>             # skill별 최신 RUN_ID 자동 선택
```

### Finding 제시 화면

```
[3/12] data — DATA-003
위험도 : High
제목   : 하드코딩 API Key — application.properties
위치   : src/main/resources/application.properties:47
설명   : AWS Access Key가 설정 파일에 하드코딩되어 있습니다.
증거   : aws.access-key=AKIAIOSFODNN7EXAMPLE

판정 [1=정탐 / 0=오탐 / s=스킵 / q=종료 / 의견 입력]:
```

### 판정 흐름 (정탐 선택 시)

```
판정 입력: 1

결과 판정 [v=취약 / i=정보 / Enter=스캔값 유지 (취약)]: v

위험도 조정 [Enter=유지 (High) / c=Critical / h=High / m=Medium / l=Low / i=Informational]: c

메모 (Enter 스킵): 실제 AWS 키 확인 — 즉시 로테이션 필요

→ 저장: review_status=정탐, severity=Critical, review_note 기록
```

### Phase 2 — 보고서 Expand 자동 생성

모든 판정 완료 후 Phase 2가 자동 실행된다. 정탐 finding마다 `testbed/<repo>/` 소스코드를 직접 탐색하여 Confluence 보고서용 상세 분석 블록(`report_expand`)을 생성한다.

```
=== Phase 2: 보고서 expand 초안 생성 ===
대상: 8건 (reviewed=true, 정탐)

[P2] INJ-001 — report_expand 생성 완료 (24줄)
[P2] DATA-003 — report_expand 생성 완료 (18줄)
...
```

---

## 최종 보고서 생성 — `approve_report.py`

### 기본 실행

```bash
# 보고서 생성만 (Confluence 미게시)
python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo>

# 보고서 생성 + Confluence 게시
python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish
```

### 실행 단계

```
[approve]  findings 수집 및 정탐/오탐 집계
[report]   generate_final_report.py 호출 → Markdown 보고서 생성
           → logs/final_<repo>_<YYYYMMDD>.md
[publish]  Confluence REST API로 페이지 생성/업데이트  ← --publish 시
[jira]     취약 finding별 Jira 이슈 생성              ← --publish 시
[audit]    VULCHK/audit_result 레포에 진단이력 업로드  ← --publish 시
```

### 생성 보고서 구조 (`logs/final_<repo>_<date>.md`)

```markdown
# [레포명] 보안 취약점 진단 보고서

## 1. 진단 개요
| 항목 | 내용 |
| 진단 레포 | my-service-api |
| 진단 일시 | 2026-06-09 |
| 취약점 건수 | Critical 1 / High 3 / Medium 2 / Low 2 |

## 2. 취약점 목록
| ID | 분류 | 제목 | 위험도 | 조치 기한 |
...

## 3. 취약점 상세
### INJ-001 — SQL Injection
:::expand 상세 검증 결과 (코드 직접 확인)
<report_expand 내용>
:::
...
```

---

## Jira 티켓 등록

`approve_report.py --publish` 실행 시 정탐 finding마다 Jira 이슈가 자동 생성된다.

### 생성 티켓 정보

| Jira 필드 | 내용 |
|-----------|------|
| 프로젝트 | `.env`의 `JIRA_PROJECT_KEY` |
| 이슈 유형 | Bug |
| 제목 | `[보안] <finding 제목>` |
| 설명 | 취약점 설명, 재현 경로, 위험 시나리오 |
| 우선순위 | severity 매핑 (Critical→Highest, High→High, ...) |
| 조치 기한 | `JIRA_REMEDIATION_DATE_FIELD_ID` 커스텀 필드 |

### 수동 티켓 생성

```bash
python3 tools/create_jira_ticket.py --repo <repo> --finding-id <ID>
```

### `.env` 설정 (Jira)

```bash
JIRA_URL=https://jira.company.com
JIRA_EMAIL=                          # Cloud: 이메일, Server/DC: 빈값
JIRA_TOKEN=<PAT>
JIRA_PROJECT_KEY=SECUFINDINGS
JIRA_REMEDIATION_DATE_FIELD_ID=customfield_21500
```

---

## 진단이력 업로드 — `audit_result`

진단 완료된 결과 파일을 `VULCHK/audit_result` Bitbucket 레포에 업로드하여 누적 이력을 관리한다.

### 업로드 구조

```
VULCHK/audit_result/
└── <repo>/
    └── <YYYYMMDD>/
        ├── findings_INJ.json
        ├── findings_XSS.json
        ├── findings_FILE.json
        ├── findings_DATA.json
        ├── findings_SCA.json
        ├── scan_meta.json
        └── final_<repo>_<date>.md
```

### 자동 업로드

`approve_report.py --publish` 실행 시 `[audit]` 단계에서 자동으로 업로드된다.

### 수동 업로드

```bash
# 단일 레포
python3 tools/push_audit_result.py --repo <repo>
python3 tools/push_audit_result.py --repo <repo> --run-id <RUN_ID>

# 전체 일괄 업로드 (보고서 생성된 레포 전체)
python3 tools/bulk_push_audit_result.py

# 특정 레포만 지정
python3 tools/bulk_push_audit_result.py --repos repo1,repo2

# 파일 복사만 확인 (git push 없음)
python3 tools/bulk_push_audit_result.py --dry-run
```

> **WSL 제약**: `code.skplanet.com` 은 WSL에서 직접 접근 불가. 업로드 스크립트는 내부적으로 PowerShell(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`)을 경유하여 git push한다.

---

## 배치 파이프라인 — `pipeline_runner.py`

여러 레포를 일괄 진단한다. `trigger/scan_targets.yaml` 에서 `active: true` 인 레포를 자동 처리.

```bash
# 전체 실행
python3 tools/pipeline_runner.py

# 계획 확인 (실제 실행 없음)
python3 tools/pipeline_runner.py --dry-run

# 특정 레포만
python3 tools/pipeline_runner.py --repos my-service-api,another-api

# 특정 skill만
python3 tools/pipeline_runner.py --skills injection sca

# clone 건너뜀 (이미 testbed/ 에 소스 있을 때)
python3 tools/pipeline_runner.py --no-clone

# 완료 후 1차 보고서 자동 생성
python3 tools/pipeline_runner.py --report draft
```

### `trigger/scan_targets.yaml` 예시

```yaml
defaults:
  provider: claude-cli       # LLM provider (claude-cli / openai / gemini)
  max_budget_usd: 3.0

repos:
  - project: MYPROJECT
    repo: my-service-api
    active: true
    repo_type: backend       # backend | frontend | php
    note: "Spring Boot 3 / Java 17"

  - project: MYPROJECT
    repo: my-frontend
    active: true
    repo_type: frontend
    skills: [xss, data]      # 특정 skill만 실행
```

> `trigger/scan_targets.yaml` 은 `.gitignore` 처리됨 (고객사 정보 포함). 예시 파일: `trigger/scan_targets.example.yaml`

---

## 디렉토리 구조

```
palantir/
├── .claude/
│   └── commands/                   # 슬래시 커맨드 정의
│       ├── sec-scan-injection.md
│       ├── sec-scan-xss.md
│       ├── sec-scan-file.md
│       ├── sec-scan-data.md
│       ├── sec-scan-sca.md
│       └── sec-review.md
│
├── sec-scan-injection/             # Injection skill
│   ├── SKILL.md                    # skill 실행 절차 정의
│   └── references/
│       ├── injection_diagnosis_criteria.md
│       └── task_prompts/
│           └── task_22_injection_review.md
│
├── sec-scan-xss/                   # XSS skill
├── sec-scan-file/                  # 파일 처리 skill
├── sec-scan-data/                  # 데이터 보호 skill
├── sec-scan-sca/                   # SCA skill
│
├── shared/
│   ├── references/                 # 공통 진단 기준 / 스키마 / 정책
│   │   └── task_prompts/
│   │       └── task_11_asset_identification.md
│   └── scripts/                    # 공유 Python 스캐너
│       ├── scan_injection_enhanced.py
│       ├── scan_xss.py
│       ├── scan_file_processing.py
│       ├── scan_data_protection.py
│       └── scan_sca_gradle_tree.py
│
├── tools/                          # 보조 도구
│   ├── clone_repo.py               # 소스코드 clone
│   ├── pipeline_runner.py          # 배치 파이프라인
│   ├── approve_report.py           # 보고서 생성 + 배포 통합
│   ├── generate_final_report.py    # Markdown 보고서 생성
│   ├── publish_confluence.py       # Confluence 게시
│   ├── create_jira_ticket.py       # Jira 티켓 생성
│   ├── push_audit_result.py        # 진단이력 단건 업로드
│   ├── bulk_push_audit_result.py   # 진단이력 일괄 업로드
│   └── ...
│
├── trigger/
│   ├── scan_targets.example.yaml   # 배치 대상 예시 (공개)
│   └── scan_targets.yaml           # 실제 운영 파일 (gitignore)
│
├── testbed/                        # 고객사 소스코드 (gitignore)
├── state/                          # 진단 결과 JSON (gitignore)
├── logs/                           # 최종 보고서 Markdown (gitignore)
├── rules/                          # 커스텀 탐지 규칙
├── requirements.txt
└── CLAUDE.md                       # Claude Code 프로젝트 지침
```

---

## 환경 설정

### 요구사항

- Python 3.10+
- [Claude Code CLI](https://claude.ai/code) — `claude` 명령어 (Claude Pro 구독)
- Windows PowerShell — 사내 Bitbucket clone/push 경유

```bash
pip install -r requirements.txt
```

### `.env` 파일

프로젝트 루트에 `.env` 파일을 생성한다. (`.gitignore` 처리됨)

```bash
# ── Confluence ────────────────────────────────────────────
CONFLUENCE_BASE_URL=https://wiki.company.com
CONFLUENCE_SPACE_KEY=SECDIG
CONFLUENCE_PARENT_ID=<부모 페이지 ID>
CONFLUENCE_TOKEN=<Bearer 토큰>

# ── Bitbucket (내부 — audit_result 업로드용) ──────────────
BITBUCKET_TOKEN=<PAT>

# ── Bitbucket (고객사 — 소스코드 clone용) ────────────────
CUSTOMER_BB_TOKEN=<PAT>

# ── Jira ─────────────────────────────────────────────────
JIRA_URL=https://jira.company.com
JIRA_EMAIL=                          # Server/DC: 빈값, Cloud: 이메일
JIRA_TOKEN=<PAT>
JIRA_PROJECT_KEY=SECUFINDINGS
JIRA_REMEDIATION_DATE_FIELD_ID=customfield_XXXXX

# ── NVD (SCA CVE 조회) ────────────────────────────────────
NVD_API_KEY=<API Key>

# ── LLM Provider (하나 선택) ─────────────────────────────
# claude-cli 사용 시 별도 설정 불필요 (Claude Pro 구독으로 동작)
GEMINI_API_KEY=<key>
OPENAI_API_KEY=<key>
```

### LLM Provider 설정

| Provider | 설정 | 특징 |
|----------|------|------|
| `claude-cli` | 별도 설정 불필요 | Claude Pro 구독 활용, **기본값** |
| `gemini` | `GEMINI_API_KEY` 설정 | 빠른 처리, 대형 repo 적합 |
| `openai` | `OPENAI_API_KEY` 설정 | GPT-4o 사용 |

---

## 관련 레포

| 레포 | 경로 | 역할 |
|------|------|------|
| **palantir** (이 레포) | `~/palantir/` | 진단 도구, skill, 스크립트 |
| palantir-testbed | `testbed/` (서브모듈) | 고객사 소스코드 clone 저장소 |
| palantir-state | `state/` (서브모듈) | 진단 결과 JSON / 중간 산출물 |
| palantir-reports | `~/palantir-reports/` | 서비스별 최종 보고서 누적 |
| audit_result | Bitbucket VULCHK | findings JSON + 보고서 이력 |
