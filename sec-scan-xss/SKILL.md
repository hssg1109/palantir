---
name: sec-scan-xss
description: Modularized SAST skill for XSS vulnerability diagnosis — Persistent, Reflected, DOM, and Redirect XSS on web backends and frontends. Runs scan_xss.py then LLM cross-verification. Use when asked to run XSS scan, XSS 진단, or 크로스사이트스크립팅 분석 on a target in testbed/. Part of the broader sec-audit-static pipeline; future updates will include Jira integration.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Scan XSS

## Overview
이 skill은 `sec-audit-static` 전체 파이프라인에서 **XSS(Cross-Site Scripting) 취약점** 진단만을 담당하는 모듈입니다.
Persistent / Reflected / DOM / Redirect XSS 4가지 유형을 모두 포함합니다.

독립 실행 가능: `sec-scan-xss/` + `shared/scripts/scan_xss.py`

향후 Jira 연동 기능이 추가될 예정입니다.

## Workflow

### Step 1: Load references

**로컬 (이 skill 전용)**
- `shared/references/task_prompts/task_11_asset_identification.md` - 자산 식별 절차
- `references/task_prompts/task_23_xss_review.md` - XSS LLM 검토 절차 (Persistent/Reflected/DOM/Redirect)

**공유 (shared/)**
- `shared/references/workflow.md` - Phase/Task 실행 맵, 보안 정책
- `shared/references/output_schemas.md` - JSON 출력 스키마
- `shared/references/severity_criteria.md` - 위험도 매핑
- `shared/references/cross_verification.md` - Phase 3-1 교차검증 + Phase 3-2 LLM 수동 심층진단 절차
- `shared/references/manual_review_prompt.md` - LLM 수동진단 페르소나, 진단기준, 답변원칙
- `shared/references/taint_tracking.md` - Source→Sink 추적
- `shared/references/global_filters.md` - 글로벌 XSS 필터/인터셉터 검증
- `shared/references/finding_writing_guide.md` - finding 품질 기준 (code_snippet 필수, 한국어 설명)
- `shared/references/tooling.md` - 코드 브라우저 도구 (rg/ctags)
- `shared/references/seed_usage.md` - Semgrep/Joern seed 규칙
- `shared/references/large_repo_multi_module.md` - 대형 repo / 멀티 모듈 진단 전략
- `shared/references/unsupported_lang_targets.md` - 자동 스캔 미지원 언어 (PHP 등)

### ⚠️ 사전 필수 — 소스코드 Clone

> testbed/ 에 소스코드가 없으면 진단을 시작할 수 없다.
> **WSL에서 직접 아래 명령을 실행한다.** clone_repo.py가 자동으로 PowerShell(Windows git)을 경유하여 Bitbucket에 접근한다.

```bash
# WSL(Ubuntu) 터미널에서 실행
python3 tools/new_scan.py <repo> --skill xss --clone <PROJECT> <REPO>
# 예: python3 tools/new_scan.py ocb-community-api --skill xss --clone OCBWEBVIEW ocb-community-api
```

실행 결과로 출력되는 `state/<repo>/xss/<YYYYMMDD_HHMM>/` 경로를 skill 실행 시 입력할 것.

testbed/ 에 소스코드가 없으면 **위 명령을 직접 실행하고 clone 완료 후 진단을 이어서 진행**한다.

---

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주 (Autonomous Execution)**: 실행 중에는
> "do you want to proceed?", "계속할까요?", "다음 단계로 진행할까요?" 등
> **어떠한 확인 질문도 하지 않는다.**
>
> - 자산 식별 → Auto-Scan → LLM-Check 전 구간을 중단 없이 진행한다.
> - 스크립트 실패·빌드 오류·파일 없음 등 예상 범위 내 오류는 fallback을 자동 적용하고 계속 진행한다.
> - 예외: 토큰/자격증명 누락처럼 사람만 해결할 수 있는 blocking 오류 발생 시에만 보고 후 대기한다.

### Step 2: Execute tasks

**Phase 1 — 자산 식별 (Asset Identification)**
- `shared/references/task_prompts/task_11_asset_identification.md` 절차 실행
- frontend/backend 판별, 언어/프레임워크 확인, 템플릿 엔진(Thymeleaf/JSP/React 등) 식별
- PHP 등 미지원 언어이면 Auto-Scan Phase skip 후 기록
- **프론트엔드 레포 판별 시** → [프론트엔드 LLM 심층진단 Phase](#frontend-llm-check) 로 분기 (Auto-Scan Phase skip)

**Auto-Scan Phase — XSS 정적 분석 (Python 스크립트, 백엔드 전용)**

> **scan_xss.py는 `--api-inventory` 필수 인자**입니다.
> `scan_api.py`로 엔드포인트 목록을 먼저 추출해야 스크립트가 동작하며,
> 이 목록을 기반으로 **모든 API 엔드포인트를 빠짐없이 순회하며** XSS 여부를 판정합니다.
> API 인벤토리 없이는 per-endpoint 진단 자체가 불가합니다.

```bash
# Step 0: API 엔드포인트 목록 추출 (XSS 스캔 필수 선행 작업)
python3 shared/scripts/scan_api.py <src> \
    -o state/<prefix>/api_scan.json

# Auto-Scan: XSS 스캔 (API 인벤토리 필수)
python3 shared/scripts/scan_xss.py <src> \
    --api-inventory state/<prefix>/api_scan.json \
    -o state/<prefix>/xss.json
```

스크립트 자동 수행 항목 (6-Step):
- `api_scan.json`의 전체 endpoint를 순회 → **누락 없이** 1건씩 판정
- Step 1: Controller 분류 + Content-Type 기반 방어 판정 (`@RestController` vs `@Controller`)
- Step 2: View 렌더링 추적 — JSP `${value}` / Thymeleaf `th:utext` / Handlebars `{{{}}}`
- Step 3: 전역 XSS 필터 탐지 — Lucy XSS Filter / AntiSamy / ESAPI
- Step 4: Redirect / Open Redirect 패턴 탐색
- Step 5: Persistent XSS Taint Tracking (Controller HTTP param → Repository write)
- Step 6: DOM XSS 전역 스캔 (`innerHTML` / `eval()` / `dangerouslySetInnerHTML`)

글로벌 XSS 필터/인터셉터 확인 (`shared/references/global_filters.md`).
출력: `state/<prefix>/xss.json` (endpoint별 취약/양호/정보 판정 포함)

LLM 검토 절차는 `references/task_prompts/task_23_xss_review.md` 전체 절차 준수.

**LLM-Check Phase — 교차검증 + 수동 심층진단 (LLM)**
- **LLM-Check Phase 1** (자동판정 "취약" 건): `shared/references/cross_verification.md` LLM-Check Phase 1 절차
  - Controller → View 렌더링 데이터 흐름 추적
  - 출력 인코딩/이스케이프 여부, XSS 필터 우회 가능성 검증
  - FP는 `diagnosis_method: "교차검증(수동)"` 으로 재분류
- **LLM-Check Phase 2** ("정보/수동검토" 건): `shared/references/cross_verification.md` LLM-Check Phase 2 + `manual_review_prompt.md`
  - 대상: `result: "정보"` + `needs_review: true`, `taint_confirmed: null`
  - 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note`
  - **HARD RULE**: `llm_verdict: "needs_review"` 판정 시 `result` 는 반드시 `"정보"` 로 저장. `"수동검토필요"`, `"정보(수동검토필요)"` 등 비표준 값 사용 금지 — `output_schemas.md` result enum 위반이며 sec-review 필터에서 누락됨.

#### §3a. 전역 XSS 필터 부재 — 구조적 취약점 Finding 생성

Auto-Scan Step 3 또는 LLM-Check 완료 후 `xss_filter_assessment.filter_level == "none"` 인 경우,
**아래 사전 체크를 먼저 수행**하고, 조건을 모두 충족할 때만 structural finding을 생성한다.

##### [사전 체크] XSS 필터 적용 대상 서비스 판별

다음 **3가지 조건을 모두 충족하는 경우에만** finding을 생성한다. 하나라도 미충족이면 finding을 생성하지 않는다.

| 조건 | 판별 방법 |
|------|----------|
| ① **사용자 입력 엔드포인트 존재** | `api_scan.json` 엔드포인트 중 HTTP 파라미터·RequestBody를 수신하는 엔드포인트 ≥ 1개 |
| ② **HTML 렌더링 경로 존재** | JSP/Thymeleaf/Freemarker 등 서버사이드 템플릿 존재, 또는 `text/html` 응답 반환 경로 존재 |
| ③ **XSS 필터 적용이 서비스 장애를 유발하지 않음** | 의도적 HTML 마크업을 수신·저장·출력하는 기능(rich text, WYSIWYG, CMS 등)이 없음 |

**서비스 유형별 판정 기준표**:

| 서비스 유형 | ① | ② | ③ | Finding 생성 여부 |
|-------------|---|---|---|-----------------|
| 배치/스케줄러 서버 (사용자 HTTP 입력 없음) | ✗ | — | — | **생성 안함** |
| Kafka Consumer / MQ 처리 서버 (HTTP 없음) | ✗ | — | — | **생성 안함** |
| 순수 REST JSON API (`@RestController` 전용, HTML 없음) | ✓ | ✗ | — | **생성 안함** |
| 내부 B2B API (HTML 렌더링 없음) | ✓ | ✗ | — | **생성 안함** |
| 웹 서비스 (JSP/Thymeleaf + 사용자 입력 존재) | ✓ | ✓ | ✓ | **생성** |
| Rich Text/CMS (HTML 입력 의도적 허용) | ✓ | ✓ | ✗ | **생성 + recommendation 수정** |

> **③ 서비스 장애 기준**: Rich text editor, 게시판 HTML 작성, CMS 콘텐츠 관리 등 의도적으로 HTML 마크업을 처리하는 기능이 있는 경우, 전역 Lucy XSS Filter 적용 시 콘텐츠가 이스케이프되어 기능 손상 발생 가능. 이 경우 recommendation에 "전역 필터 대신 엔드포인트별 Contextual Escaping 또는 AntiSamy 정책 기반 허용목록 방식 적용 권고" 문구로 대체한다.

##### [추가 조건] 언어/런타임별 미들웨어 실효성 판단

조건 ①②③을 충족하더라도 **언어·런타임에 따라 미들웨어의 실제 방어 범위가 다르다.** 서비스의 주 입력 경로에 대해 미들웨어가 실질적인 보호를 제공하는지 사전 판단한다.

| 런타임 | 전역 필터 실효성 | 핵심 방어 수단 |
|--------|----------------|--------------|
| **Java (Spring/Servlet)** | 높음 — Lucy XSS Servlet Filter가 모든 HTTP 파라미터·바디·헤더를 일괄 정제 | Lucy XSS Filter, AntiSamy, ESAPI |
| **Node.js/Express** | **제한적** — `xss-clean`, `express-validator`는 `req.body`, `req.query`만 정제. `req.url`(URL path)은 정제 대상 아님 | **템플릿 엔진 출력 인코딩** (Jade `!{JSON.stringify()}`, EJS `<%-` 대신 `<%=`, etc.) |
| **Python (Django/Flask)** | 높음 — 템플릿 자동 이스케이핑 기본값, 미들웨어로 보완 가능 | 템플릿 `autoescape`, CSP 헤더 |

**Node.js/Express 서비스의 structural finding 생성 조건 (추가)**:

- 서비스의 주 입력 경로가 `req.url`(URL path) 전용이고 `req.body`/`req.query` 입력이 없는 경우 → **finding 생성 안함** (미들웨어 효과 없음)
- 서비스가 `req.body`/`req.query` 를 HTML 응답에 반영하는 경우 → finding 생성 가능
- finding 생성 시 recommendation은 **Lucy XSS Filter가 아닌** 템플릿 엔진 출력 인코딩 + helmet CSP 설정으로 대체 작성

조건 충족 시 아래 구조의 **`finding_type: "structural"`** finding을 `findings[]`에 추가한다.
이 finding은 개별 XSS endpoint 취약점과 독립된 정책 수준 취약점으로, 리포트에 별도 항목으로 포함된다.

| 필드 | 값 |
|------|-----|
| `finding_type` | `"structural"` |
| `severity` | `"High"` (보수적 기준 고정 — `feedback_conservative_security_policy.md` #4. 개별 Persistent/Reflected XSS 정탐 여부와 무관하게 전역 방어 계층 부재 자체를 High로 판정) |
| `category` | `"XSS 필터 미구현"` |
| `cwe_id` | `"CWE-693"` (Protection Mechanism Failure) |
| `owasp_category` | `"A05:2021 Security Misconfiguration"` |
| `scope.type` | `"global"` |

동반 XSS 취약점이 있으면 `review_note`에 해당 finding_id 명시.

##### 표준 보고서 템플릿 (description / recommendation / report_expand)

보고서 생성 시 아래 텍스트를 기준으로 `<repo>` 및 동반 취약점 ID를 치환하여 사용한다.

**description (표준)**:
```
<repo> 전체 소스(src/) 및 build.gradle 검색 결과, Lucy XSS Servlet Filter, OWASP AntiSamy, ESAPI 등 어떤 전역 XSS 방어 컴포넌트도 발견되지 않습니다. WebSecurityConfiguration에서 CSRF만 disable되어 있으며 XSS 관련 Filter 등록이 없습니다. 전역 필터 미구현 상태에서는 개별 엔드포인트에 XSS sanitization이 누락되는 즉시 Persistent/Reflected XSS가 실현됩니다.
```

**recommendation (표준)**:
```
Lucy XSS Servlet Filter(naver/lucy-xss-servlet) 또는 OWASP AntiSamy를 Spring Security Filter Chain에 전역 등록하십시오. 전역 필터 적용 시 <동반_XSS_ID_목록> 등 개별 엔드포인트 취약점에 대한 방어 심도가 추가됩니다.

단, 전역 필터를 무조건적으로 전체 URL 패턴에 일괄 적용할 경우 정상 요청까지 이스케이프/차단되어 서비스 장애로 이어질 수 있습니다. 서비스 영향도를 사전에 분석(rich text/HTML 입력 허용 API 존재 여부, 기존 정상 요청 파라미터에 `<`, `>`, `&` 등 특수문자가 포함되는 케이스 존재 여부 등)한 뒤, 장애 없는 범위 내에서 단계적으로 적용(예: 스테이징 환경 우선 적용 → 예외 URL 화이트리스트 구성 → 운영 반영)하거나, 즉시 전역 적용이 어려운 경우 우선 담당 개발팀의 영향도 확인이 필요합니다.
```

> **필수 워딩**: 위 recommendation 문구는 severity가 High로 고정되어 즉각 조치가 요구되는 것으로 오인되지 않도록, **"서비스 영향도 고려", "장애 없는 범위 내 조치 권고" 또는 "(서비스 담당팀) 확인 필요"** 중 하나 이상의 표현을 반드시 포함한다. 자유 서술로 대체 작성하더라도 이 문구의 취지(전역 필터 일괄 적용 시 정상 요청 차단·서비스 장애 가능성)는 생략하지 않는다.

**report_expand (표준)**:
```markdown
## 코드 직접 확인 결과

`build.gradle` 전체 및 `src/` 소스코드를 탐색한 결과 Lucy XSS Servlet Filter(`naver/lucy-xss-servlet`), OWASP AntiSamy, ESAPI 등 전역 XSS 방어 컴포넌트가 전혀 등록되어 있지 않다. `WebSecurityConfiguration`에서는 `http.csrf().disable()`만 설정하고 XSS 관련 Filter Chain 등록이 없다.

## 위험 시나리오

전역 XSS 필터가 없는 구조에서는 각 엔드포인트에서 sanitization이 누락되는 즉시 Stored XSS/Reflected XSS가 바로 실현 가능하다. <동반_XSS_ID_설명>은 이 구조적 부재로 인해 실제 취약점으로 발현된다. 신규 API 추가 시에도 개발자가 개별로 sanitization을 적용해야 하는 구조적 위험이 지속된다.

## 방어 컴포넌트 현황

| 방어 수단 | 적용 여부 | 비고 |
|----------|-----------|------|
| Lucy XSS Servlet Filter | 미적용 | build.gradle dependency 없음 |
| OWASP AntiSamy | 미적용 | 소스코드 전체 미사용 |
| ESAPI | 미적용 | 소스코드 전체 미사용 |
| 커스텀 XSS Filter | 미적용 | WebSecurityConfiguration 내 미등록 |

## 조치 시 고려사항

전역 필터를 URL 패턴 `/*`로 일괄 적용할 경우 정상 요청까지 이스케이프·차단되어 서비스 장애가 발생할 수 있다. 적용 전 서비스 영향도(HTML/rich text 입력 허용 API 존재 여부 등)를 확인하고, 장애 없는 범위 내에서 단계적으로 적용할 것을 권고한다.
```

---

### <a name="frontend-llm-check"></a>프론트엔드 LLM 심층진단 Phase (JS/TS 레포 전용)

> **적용 대상**: Phase 1에서 `repo_type = "frontend"` 판정된 레포  
> **접근 방법**: LLM이 직접 소스를 읽고 보안진단전문가로서 Source→Sink Taint 추적  
> `scan_xss.py` 미실행 — 아래 절차로 대체

#### Step FE-0: 진단 범위 확정

```bash
# 프레임워크 확인
cat <src>/package.json | grep -E '"react"|"vue"|"angular"|"next"|"nuxt"|"svelte"'

# 진단 대상 파일 목록 (TS/JS/JSX/TSX/Vue/Svelte)
find <src>/src -type f \( -name "*.tsx" -o -name "*.ts" -o -name "*.jsx" -o -name "*.js" -o -name "*.vue" \) \
  | grep -v node_modules | wc -l
```

파일 수 기록 → 전체 대비 진단 커버리지를 summary에 명시.

#### Step FE-1: Sink 목록 수집 (자동 grep)

> LLM이 직접 아래 명령을 실행하여 위험 sink 후보를 수집한다. 결과가 없으면 "탐지 없음" 기록 후 다음 단계 진행.

```bash
SRC=<src>/src

# [S1] HTML 직접 삽입 — DOM XSS 고위험
rg -n "dangerouslySetInnerHTML|innerHTML\s*[+]?=|outerHTML\s*[+]?=|insertAdjacentHTML" $SRC

# [S2] 코드 실행 — eval/Function/setTimeout 문자열
rg -n "\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]" $SRC

# [S3] document.write / writeln
rg -n "document\.write[ln]?\s*\(" $SRC

# [S4] Open Redirect
rg -n "location\.href\s*=|location\.replace\s*\(|location\.assign\s*\(|window\.open\s*\(" $SRC

# [S5] postMessage 수신 (origin 검증 누락 가능성)
rg -n "addEventListener\s*\(\s*['\"]message['\"]" $SRC

# [S6] 프로토타입 오염 (Prototype Pollution)
rg -n "__proto__\s*\[|constructor\s*\[|\.prototype\s*\[" $SRC

# [S7] script/link 동적 생성
rg -n "createElement\s*\(\s*['\"]script['\"]|setAttribute\s*\(\s*['\"]src['\"]|setAttribute\s*\(\s*['\"]href['\"]" $SRC
```

각 패턴별 hit 수와 파일:라인 목록을 기록한다.

#### Step FE-2: Source 목록 수집 (사용자 입력 경로)

```bash
SRC=<src>/src

# URL 파라미터 / 해시
rg -n "location\.search|location\.hash|URLSearchParams|searchParams\.get\|useSearchParams\|useParams\b" $SRC

# 외부 메시지
rg -n "event\.data\b|message\.data\b" $SRC

# 스토리지 (XSS-stored 경로)
rg -n "localStorage\.getItem|sessionStorage\.getItem|document\.cookie\b" $SRC

# 서버 API 응답 → DOM 반영 경로 (React state/context)
rg -n "useState|useEffect\|axios\.\|fetch\(" $SRC | head -50
```

#### Step FE-3: Source → Sink Taint 추적 (LLM 수동 분석)

Step FE-1/FE-2 hit 목록을 기반으로 LLM이 **각 sink 파일을 직접 읽고** 아래 기준으로 판정한다.

**판정 흐름 (각 sink 후보에 대해 반복):**

```
1. sink 코드 읽기
   - 해당 파일 Read (±20줄 컨텍스트)
   - sink에 전달되는 변수/표현식 식별

2. 변수 역추적 (depth 최대 3 hop)
   - 변수가 props / state / API response에서 오면 → "사용자 제어 가능"
   - 변수가 상수 / import된 정적 값이면 → "사용자 제어 불가" (FP 처리)

3. 살균(sanitize) 여부 확인
   - DOMPurify.sanitize() / xss() / escapeHtml() 적용 여부
   - React dangerouslySetInnerHTML: __html 값에 sanitize 없으면 → 취약
   - innerHTML: 직전에 명시적 sanitize 없으면 → 취약

4. 판정
   - 취약: 사용자 입력 → sanitize 없음 → 위험 sink 도달
   - 정보: 사용자 입력 경로 있으나 sanitize 있음 또는 추적 불가
   - 양호: sink에 사용자 입력 도달 불가 (정적 값 또는 서버사이드 인코딩)
```

> #### ⚠️ HARD RULE — DOMPurify 누락 sink 발견 시 Taint Source 전파 역추적 필수
>
> **하나의 sink에서 DOMPurify 미적용 취약점을 발견한 것으로 탐지 완료 처리하지 않는다.**
> 동일 taint source가 여러 컴포넌트에 전파되는 경우 일부만 finding에 반영되어
> 보고서 누락이 발생한다 (실제 사례: `mallInfo.notice` 소비 컴포넌트 3개 중 1개만 식별).
>
> **절차**:
> 1. sink에서 데이터 출처(API 엔드포인트명 또는 state 필드명) 확인
> 2. 동일 taint source를 소비하는 모든 파일 열거:
>    ```bash
>    rg -n "mallInfo\.notice\|해당_API_경로\|해당_필드명" <src>/src
>    ```
> 3. 열거된 파일 각각에 대해 `dangerouslySetInnerHTML` / `innerHTML` 사용 및 DOMPurify 적용 여부 확인
> 4. 누락된 파일이 있으면 **동일 finding에 통합** (finding_id 1개로 scope.affected_file에 전체 파일 목록 명시)
> 5. `evidence_trail`에 "전파 탐색 완료" 근거 기록
>
> **전수 검토 완료 선언 조건**: taint source grep 결과가 0건이거나, 열거된 파일 전체에 DOMPurify 적용 확인된 경우에만 허용.

**Open Redirect 전용 판정:**
- `location.href = ...` 에 전달되는 값이 외부 파라미터(`?redirect=`, `?next=`, `?url=`)에서 오면 → 취약
- 도메인 화이트리스트 검증 로직 확인 (`startsWith('/')`, `new URL()` 파싱 후 origin 비교 등)

**postMessage 전용 판정:**
- `addEventListener('message', handler)` 핸들러에서 `event.origin` 체크 여부 확인
- origin 검증 없이 `event.data`를 DOM에 삽입하거나 `eval` 실행 시 → 취약

**Prototype Pollution 판정:**
- 사용자 입력이 `Object.assign(target, userInput)` 또는 deep merge 함수에 전달되는지 확인
- `__proto__` / `constructor` 키가 필터링 없이 사용되면 → 취약

#### Step FE-4: CSP / 보안 헤더 확인

```bash
# nginx.conf 존재 시
find <src> -name "nginx.conf" -o -name "*.nginx" | head -5
# Next.js security headers
grep -n "Content-Security-Policy\|X-Frame-Options\|X-Content-Type" <src>/next.config.*

# meta CSP 태그
rg -n "http-equiv.*Content-Security-Policy\|<meta.*CSP" <src>/public/ <src>/src/
```

판정 기준:
| 상태 | 판정 |
|---|---|
| CSP 헤더 없음 + XSS 취약 sink 존재 | 심각도 상향 (High → Critical) |
| CSP 있으나 `unsafe-inline` / `unsafe-eval` | 정보 (CSP 우회 가능) |
| CSP 적절 (`nonce` 또는 hash 기반) | 방어 요소로 기록 |

#### Step FE-5: Finding 작성 및 `findings_XSS.json` 생성

각 취약 항목을 finding으로 작성한다. **`taint_flow`는 반드시 `evidence` 안에 포함한다.**

```json
{
  "finding_id": "XSS-001",
  "title": "DOM XSS — dangerouslySetInnerHTML에 미살균 API 응답 삽입",
  "severity": "High",
  "risk_level": 4,
  "category": "DOM XSS",
  "cwe_id": "CWE-79",
  "result": "취약",
  "diagnosis_method": "수동진단(LLM)",
  "source": "llm-check",
  "fn_detected": false,
  "fp_corrected": false,
  "llm_verdict": "TP",
  "llm_reviewed_at": "<ISO8601>",
  "manual_review_note": "CommentList.tsx Read 확인: comment.content가 fetch('/api/comments') 응답에서 직접 dangerouslySetInnerHTML.__html에 전달, DOMPurify 미적용 확인.",
  "scope": {
    "type": "global",
    "affected_file": "src/components/CommentList.tsx",
    "affected_line": 42
  },
  "evidence": {
    "file": "src/components/CommentList.tsx",
    "lines": "40-45",
    "code_snippet": "// CommentList.tsx:42\n<div dangerouslySetInnerHTML={{ __html: comment.content }} />",
    "taint_flow": {
      "source": "GET /api/comments → response.data[].content (사용자 작성 댓글)",
      "sink": "dangerouslySetInnerHTML={{ __html: comment.content }}",
      "sanitized": false,
      "hops": 2,
      "call_chain": [
        "useEffect → fetch('/api/comments') → setComments(data)",
        "comments.map(comment => <div dangerouslySetInnerHTML={{ __html: comment.content }} />)"
      ]
    }
  },
  "description": "사용자가 작성한 댓글 내용(comment.content)이 DOMPurify 등 살균 처리 없이 dangerouslySetInnerHTML에 직접 전달됩니다. 공격자가 악성 스크립트를 댓글로 저장하면 다른 사용자의 브라우저에서 실행됩니다.",
  "recommendation": "DOMPurify.sanitize(comment.content, { USE_PROFILES: { html: true } }) 적용 후 __html에 전달",
  "needs_review": false
}
```

**판정 결과가 없을 경우**: `findings: []` 빈 배열로 저장. `scan_coverage.fn_disclaimer` 명시.

---

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.

### Step 4: findings_XSS.json 생성 및 Summary 출력

LLM-Check Phase 완료 후:

1. **`state/<prefix>/findings_XSS.json` 저장** (`llm_checked: true`) — `shared/references/output_schemas.md` 스키마 준수.
   - `findings[]`: TP / needs_review 항목만 포함. 각 finding에 `llm_verdict`, `manual_review_note`, `evidence.taint_flow` 필수.
   - **`reviewed`/`review_status` 필드는 절대 여기서 설정하지 않는다** — TP로 확정된 항목도 `llm_verdict: "TP"`까지만 기록. 이 두 필드는 `/sec-review` §4의 사람 판정에서만 부여되며 `tools/audit_utils.py log-review`로 `state/audit_log.json`에 기록되는 것만이 유효한 판정 경로다. 예외 없이 `/sec-review`를 거쳐야 한다. (2026-08-03 displayadmin_server XSS-001 — 이 필드가 LLM-Check 단계에서 유출돼 `/sec-review`를 우회한 채 보고서에 반영된 사고 재발 방지)
   - `evidence_trail[]`: FP 재분류 항목 및 전체 양호 항목 보존 (업로드 제외, 로컬 증적).
   - `llm_checked: false` 파일은 업로드 스크립트가 자동 차단함.

2. **`state/<prefix>/summary_xss.md` 생성**

`summary_xss.md` 읽을 파일:

**읽을 파일**:
- `state/<prefix>/findings_XSS.json` — LLM-Check 완료 후 생성된 최종 findings
- `state/<prefix>/xss.json` — 스크립트 자동 판정 원본 (통계 집계용)

**출력 형식**:

```markdown
# XSS 취약점 진단 결과 요약 — <repo명>

진단일: YYYY-MM-DD | 대상: <source_repo_url> | LLM 검증: 완료

## 결과 통계

| 판정 | 건수 |
|---|---|
| 취약 | N |
| 정보 | N |
| 양호 | N |
| **전체 endpoint** | **N** |

XSS 유형별 — Reflected: N / Persistent: N / DOM: N / Redirect: N

## Finding 목록

| ID | 제목 | 위험도 | XSS 유형 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|---|
| XSS-001 | Reflected XSS — 검색어 파라미터 미인코딩 | 4 고위험 | Reflected | src/.../Controller.java:85 | 취약 | 교차검증(수동) |

> 양호 항목은 목록에서 제외. 취약·정보만 기재.

## 소스 파일
- `state/<prefix>/xss.json`
- `state/<prefix>/task23_llm.json` _(LLM 보완, 없으면 생략)_
```

**작성 규칙**:
- Finding 목록은 심각도 내림차순 (Critical → High → Medium → Low → Info)
- `xss_category` 필드에서 XSS 유형 추출 (Reflected / Persistent / DOM / Redirect)
- `affected_files` 또는 `evidence.file` + `evidence.lines` 에서 파일:라인 추출
- findings 출처: `findings_XSS.json`의 `findings[]` 배열 기준
- 양호는 통계에만 포함, 목록에는 미기재

LLM-Check 완료 후 Phase C-1을 수행한다.

---

### Step C: Phase C-1 — LLM 데이터 접근 로그 업데이트

> **정책**: `shared/references/llm_data_cleansing_policy.md` | **절차**: `shared/references/phase_c_cleansing.md`

LLM-Check 완료 직후 수행. **testbed는 이 단계에서 삭제하지 않는다** (이후 file/data/sca 진단에 필요).  
testbed 삭제 + Confluence 등록은 `/sec-review` 완료 시 Phase C-2에서 수행.

**수행**:

1. 이 세션에서 `testbed/<repo>/` 경로를 Read 도구로 접근한 파일 목록 정리 (Phase 1 / Phase 3 구분)
2. `state/<repo>/llm_data_access_log.json` 생성(없으면) 또는 `skills[]` 배열에 xss 항목 append:
   ```json
   {
     "skill": "xss",
     "scan_dir": "state/<repo>/xss/<YYYYMMDD_HHMM>",
     "scanned_at": "<진단 시작 ISO8601 +09:00>",
     "llm_accessed_files": [
       { "phase": "Phase 1 - Asset Identification", "purpose": "자산 식별", "files": ["testbed/<repo>/build.gradle", "..."] },
       { "phase": "Phase 3 - LLM-Check", "purpose": "교차검증", "files": ["testbed/<repo>/src/..."] }
     ]
   }
   ```
3. 신규 생성 시 `project`는 `state/<repo>/20*/scan_meta.json`의 `bb_project` 값 사용 (없으면 `"?"`)
4. `cleansing_completed: false` 유지

**완료 출력**:
```
[Phase C-1] llm_data_access_log.json 업데이트 완료
  skill  : xss
  접근파일: N건 (Phase 1: N / Phase 3: N)
  로그   : state/<repo>/llm_data_access_log.json
  [다음] /sec-review 완료 시 testbed 삭제 + Confluence 레지스트리 등록 수행
```

Phase C-1 완료 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다.

## Resources

### 로컬 (이 skill 폴더 내)
- `shared/references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_23_xss_review.md`

### 공유 (shared/references/)
#### Workflow & Policy
- `workflow.md`, `output_schemas.md`, `severity_criteria.md`

#### Diagnosis Criteria
- `cross_verification.md`, `manual_review_prompt.md`, `taint_tracking.md`, `global_filters.md`

#### Tooling & Rules
- `tooling.md`, `seed_usage.md`
- `large_repo_multi_module.md`, `unsupported_lang_targets.md`
- `rules/semgrep/thymeleaf-ssti.yaml`
- `rules/joern/taint_queries.sc`
