---
name: sec-scan-auth
description: Modularized SAST skill for Authentication/Authorization/Abuse diagnosis — Auth Bypass, Session Management, Brute-force protection, IDOR/BOLA, Missing Function-level Access Control, Mass Assignment, Rate Limit absence, Idempotency absence, Client-trusted business logic. Runs scan_auth_baseline.py (non-judging candidate tagging) then LLM manual diagnosis for all TP/FP and severity judgment. Use when asked to run auth/authorization/abuse scan, 인증/인가/어뷰징 진단, IDOR/BOLA/포인트 어뷰징 분석 on a target in testbed/. Part of the broader sec-audit-static pipeline.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Scan Auth

## Overview
이 skill은 `sec-audit-static` 전체 파이프라인에서 **인증/인가/어뷰징(Authentication / Authorization / Abuse)** 진단만을 담당하는 모듈입니다.

독립 실행 가능: `sec-scan-auth/` + `shared/scripts/scan_api.py` + `shared/scripts/scan_auth_baseline.py`

> ⚠️ **다른 5개 skill과의 핵심 차이 — Auto-Scan은 판정하지 않는다.**
> 인가/어뷰징은 SQL Injection처럼 정규식 매칭만으로 TP/FP를 단정하기 어려운 영역이다.
> `scan_auth_baseline.py`는 **판정 없는 후보 태깅(inventory enrichment)** 만 수행하고
> (전량 `result: "정보"`, `needs_review: true`), category/severity/TP-FP 최종 판정은
> **LLM-Check(수동진단)가 전담**한다. `sec-scan-data`의 "수동진단(LLM)" 패턴을 이 skill에서는
> 전체 endpoint에 대해 기본 동작으로 적용한다고 이해하면 된다.

## Workflow

### Step 1: Load references

**로컬 (이 skill 전용)**
- `shared/references/task_prompts/task_11_asset_identification.md` - 자산 식별 절차
- `references/task_prompts/task_26_auth_abuse_review.md` - 인증/인가/어뷰징 LLM 수동진단 절차 (IDOR/Mass Assignment/Rate Limit/멱등성 판정기준)

**공유 (shared/)**
- `shared/references/workflow.md` - Phase/Task 실행 맵, 보안 정책
- `shared/references/output_schemas.md` - JSON 출력 스키마
- `shared/references/vuln_taxonomy.md` - Section 6 (AUTH) category/cwe_id/owasp_category 표준값
- `shared/references/severity_criteria.md` - 위험도 매핑
- `shared/references/cross_verification.md` - LLM 수동 심층진단 절차
- `shared/references/manual_review_prompt.md` - LLM 수동진단 페르소나, 진단기준, 답변원칙
- `shared/references/finding_writing_guide.md` - finding 품질 기준 (code_snippet 필수, 한국어 설명)
- `shared/references/tooling.md` - 코드 브라우저 도구 (rg/ctags)
- `shared/references/large_repo_multi_module.md` - 대형 repo / 멀티 모듈 진단 전략
- `shared/references/unsupported_lang_targets.md` - 자동 스캔 미지원 언어 (PHP 등)

### ⚠️ 사전 필수 — 소스코드 Clone

> testbed/ 에 소스코드가 없으면 진단을 시작할 수 없다.
> **WSL에서 직접 아래 명령을 실행한다.** clone_repo.py가 자동으로 PowerShell(Windows git)을 경유하여 Bitbucket에 접근한다.

```bash
# WSL(Ubuntu) 터미널에서 실행
python3 tools/clone_repo.py <PROJECT> <REPO>
# 예: python3 tools/clone_repo.py OCBWEBVIEW ocb-community-api
```

실행 결과로 출력되는 `state/<repo>/auth/<YYYYMMDD_HHMM>/` 경로를 skill 실행 시 입력할 것.

testbed/ 에 소스코드가 없으면 **위 명령을 직접 실행하고 clone 완료 후 진단을 이어서 진행**한다.

---

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주 (Autonomous Execution)**: 실행 중에는
> "do you want to proceed?", "계속할까요?", "다음 단계로 진행할까요?" 등
> **어떠한 확인 질문도 하지 않는다.**
>
> - 자산 식별 → Auto-Scan(후보 태깅) → LLM-Check(전량 수동진단) 전 구간을 중단 없이 진행한다.
> - 스크립트 실패·빌드 오류·파일 없음 등 예상 범위 내 오류는 fallback을 자동 적용하고 계속 진행한다.
> - 예외: 토큰/자격증명 누락처럼 사람만 해결할 수 있는 blocking 오류 발생 시에만 보고 후 대기한다.
> - **이 skill은 Java/Kotlin Spring 백엔드 전용**이다 (`scan_api.py`가 Spring MVC/WebFlux 컨트롤러만 파싱). 순수 프론트엔드 레포는 Auto-Scan을 skip하고 Phase 1 자산식별 결과에 "백엔드 API 없음 — 인증/인가 진단 대상 아님"으로 기록 후 종료한다.

### Step 2: Execute tasks

**Phase 1 — 자산 식별 (Asset Identification)**
- `shared/references/task_prompts/task_11_asset_identification.md` 절차 실행
- Spring Controller 존재 여부, 인증 방식(세션/JWT/OAuth), Security 설정 파일(`SecurityConfig`, `WebSecurityConfigurerAdapter`) 위치 식별
- 순수 프론트엔드/PHP 등 미지원 대상이면 Auto-Scan Phase skip 후 기록

**Auto-Scan Phase 1 — API 인벤토리 추출**

```bash
python3 shared/scripts/scan_api.py <src> \
    -o state/<prefix>/api_inventory.json
```

- `endpoints[]`에 `method`/`api`/`auth_required`/`auth_detail`/`handler`/`file`/`line`/`module`/`parameters[]`/`auth_annotations[]` 포함.
- 이미 다른 skill(예: sec-scan-data `--api-inventory` 옵션)에서 같은 세션에 생성한 `api_inventory.json`이 있으면 재사용 가능 — 중복 실행 불필요.

**Auto-Scan Phase 2 — 인증/인가/어뷰징 후보 태깅 (판정 없음)**

```bash
python3 shared/scripts/scan_auth_baseline.py state/<prefix>/api_inventory.json \
    -o state/<prefix>/auth.json
```

태깅 항목 (전부 `result: "정보"`, `needs_review: true` — TP/FP 판정 아님):
- **IDOR_CANDIDATE**: path parameter가 리소스 식별자(`{id}`/`{seq}`/`{no}` 등)이고 `auth_required: true`인 endpoint
- **MISSING_AUTH_CANDIDATE**: `auth_required: false`이면서 HTTP 메서드가 POST/PUT/DELETE/PATCH인 endpoint
- **ABUSE_KEYWORD_CANDIDATE**: 경로/핸들러/파라미터명에 `point`/`coupon`/`reward`/`event`/`gift`/`draw`/`lottery`/`mileage`/`cashback`/`voucher` 등 금전·리워드 키워드가 매칭된 endpoint
- **NO_AUTHZ_ANNOTATION_CANDIDATE**: `auth_required: true`이나 `@PreAuthorize`/`@Secured`/`hasRole` 등 인가(역할/권한) 애노테이션이 확인되지 않는 endpoint

출력: `state/<prefix>/auth.json` (`candidates[]` — 전량 판정 대기, `findings[]`는 항상 빈 배열)

**LLM-Check Phase — 전량 수동 심층진단 (LLM)**
- 대상: `auth.json`의 `candidates[]` 전체 (자동판정된 "취약" 건이 없으므로 Phase 1 교차검증 단계는 생략)
- 절차: `references/task_prompts/task_26_auth_abuse_review.md` — candidate_type별 그룹으로 순회하며 비즈니스 맥락 기반 판정
- `manual_review_prompt.md` 페르소나 재사용
- 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note` + 최종 `category`(vuln_taxonomy.md §6 표준값)/`severity`/`result`("취약"/"정보", FP는 findings에서 제외)

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.
- `findings_AUTH.json`의 각 finding은 `category`가 `vuln_taxonomy.md` §6 표준값(`AUTH_BYPASS`/`SESSION_MGMT`/`BRUTE_FORCE_PROTECTION`/`IDOR`/`MISSING_FUNCTION_ACCESS_CONTROL`/`MASS_ASSIGNMENT`/`RATE_LIMIT_ABSENT`/`IDEMPOTENCY_ABSENT`/`CLIENT_TRUSTED_LOGIC`) 중 하나인지 확인 — Auto-Scan 단계의 `candidate_type`(`*_CANDIDATE`)을 그대로 category에 남기지 말 것.

### Step 4: Summary 출력

LLM-Check Phase 완료 후 `state/<prefix>/summary_auth.md` 를 생성한다.

**읽을 파일**:
- `state/<prefix>/auth.json` — Auto-Scan 후보 태깅 결과
- LLM-Check 결과 (task26_llm.json 등)

**출력 형식**:

```markdown
# 인증/인가/어뷰징 취약점 진단 결과 요약 — <repo명>

진단일: YYYY-MM-DD | 대상: <source_repo_url> | LLM 검증: 완료

## 결과 통계

| 카테고리 | 취약 | 정보 | 양호 |
|---|---|---|---|
| AUTH_BYPASS | N | N | N |
| IDOR | N | N | N |
| MISSING_FUNCTION_ACCESS_CONTROL | N | N | N |
| MASS_ASSIGNMENT | N | N | N |
| RATE_LIMIT_ABSENT | N | N | N |
| IDEMPOTENCY_ABSENT | N | N | N |
| CLIENT_TRUSTED_LOGIC | N | N | N |
| **합계** | **N** | **N** | **N** |

## Finding 목록

| ID | 제목 | 위험도 | 카테고리 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|---|
| AUTH-001 | 포인트 적립 API 멱등성 부재 | 4 고위험 | IDEMPOTENCY_ABSENT | src/.../PointController.java:42 | 취약 | 수동진단(LLM) |

> 양호 항목은 목록에서 제외. 취약·정보만 기재.

## 소스 파일
- `state/<prefix>/auth.json`
```

**작성 규칙**:
- Finding 목록은 심각도 내림차순 (Critical → High → Medium → Low → Info)
- `evidence.file` + `evidence.lines` 에서 파일:라인 추출
- 양호는 통계에만 포함, 목록에는 미기재

### Step 4-1: LLM-Check 완료 확인 — 업로드 전 필수 게이트

> **HARD RULE**: `task26_llm.json` 미존재 상태로 업로드 금지.
> 이 skill은 Auto-Scan이 판정을 하지 않으므로(전량 `needs_review: true`) LLM 교차검증 없는 업로드는 **모든 candidate가 미판정 상태로 리포트에 유입**되는 것과 같다.
> `findings_AUTH.json` 생성 시 반드시 `llm_checked: true` 설정.

업로드 전 확인:
```bash
python3 -c "
import pathlib, sys
prefix = 'state/<prefix>'
has_llm = pathlib.Path(f'{prefix}/task26_llm.json').exists()
findings = pathlib.Path(f'{prefix}/findings_AUTH.json')
if not has_llm:
    print('[BLOCK] task26_llm.json 없음 — LLM-Check 먼저 수행', file=sys.stderr); sys.exit(1)
if findings.exists():
    import json
    d = json.loads(findings.read_text())
    if not d.get('llm_checked', False):
        print('[BLOCK] findings_AUTH.json llm_checked=false', file=sys.stderr); sys.exit(1)
print('[OK] LLM-Check 완료 확인')
"
```

통과 조건 충족 후 Phase C-1을 수행한다.

### Step 4-2: 사람 판정 필드 침범 금지 (HARD RULE)

> **HARD RULE**: 이 skill(Auto-Scan/LLM-Check 어느 단계도)은 `reviewed`/`review_status` 필드를 직접 설정하지 않는다.
> 이 두 필드는 `/sec-review` §4의 사람 판정에서만 부여되며, `tools/audit_utils.py log-review` 호출로 `state/audit_log.json`에 기록되는 것만이 유효한 판정 경로다.
> LLM-Check가 TP로 확정한 finding이라도 `llm_verdict: "TP"` / `manual_review_note` 까지만 기록하고 `reviewed`/`review_status`는 미기재 상태로 남겨, 예외 없이 `/sec-review`를 거치도록 한다.
> (2026-08-03 displayadmin_server XSS-001 — LLM-Check 판정이 사람 판정 필드에 유출되어 `/sec-review`를 우회한 채 보고서에 반영된 사고 재발 방지. `/sec-review` §1a가 audit_log 대조로 이런 유출을 탐지·재편입하지만, 애초에 이 skill 단계에서 설정하지 않는 것이 원칙이다.)

---

### Step C: Phase C-1 — LLM 데이터 접근 로그 업데이트

> **정책**: `shared/references/llm_data_cleansing_policy.md` | **절차**: `shared/references/phase_c_cleansing.md`

LLM-Check 완료 직후 수행. **testbed는 이 단계에서 삭제하지 않는다** (이후 sca 진단에 필요).
testbed 삭제 + Confluence 등록은 `/sec-review` 완료 시 Phase C-2에서 수행.

**수행**:

1. 이 세션에서 `testbed/<repo>/` 경로를 Read 도구로 접근한 파일 목록 정리 (Phase 1 / Phase 3 구분)
2. `state/<repo>/llm_data_access_log.json` 생성(없으면) 또는 `skills[]` 배열에 auth 항목 append:
   ```json
   {
     "skill": "auth",
     "scan_dir": "state/<repo>/auth/<YYYYMMDD_HHMM>",
     "scanned_at": "<진단 시작 ISO8601 +09:00>",
     "llm_accessed_files": [
       { "phase": "Phase 1 - Asset Identification", "purpose": "자산 식별", "files": ["testbed/<repo>/build.gradle", "..."] },
       { "phase": "Phase 3 - LLM-Check", "purpose": "수동진단", "files": ["testbed/<repo>/src/..."] }
     ]
   }
   ```
3. 신규 생성 시 `project`는 `state/<repo>/20*/scan_meta.json`의 `bb_project` 값 사용 (없으면 `"?"`)
4. `cleansing_completed: false` 유지

**완료 출력**:
```
[Phase C-1] llm_data_access_log.json 업데이트 완료
  skill  : auth
  접근파일: N건 (Phase 1: N / Phase 3: N)
  로그   : state/<repo>/llm_data_access_log.json
  [다음] /sec-review 완료 시 testbed 삭제 + Confluence 레지스트리 등록 수행
```

Phase C-1 완료 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다.

## Resources

### 로컬 (이 skill 폴더 내)
- `shared/references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_26_auth_abuse_review.md`

### 공유 (shared/references/)
#### Workflow & Policy
- `workflow.md`, `output_schemas.md`, `severity_criteria.md`, `vuln_taxonomy.md`

#### Diagnosis Criteria
- `cross_verification.md`, `manual_review_prompt.md`

#### Tooling & Rules
- `tooling.md`
- `large_repo_multi_module.md`, `unsupported_lang_targets.md`

### 스크립트
- `shared/scripts/scan_api.py` — API 엔드포인트 인벤토리 추출 (공유, 이미 다른 skill에서 실행했으면 재사용)
- `shared/scripts/scan_auth_baseline.py` — 인증/인가/어뷰징 후보 태깅 (판정 없음, 이 skill 전용)
