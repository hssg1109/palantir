---
name: sec-scan-php
description: Modularized SAST skill for raw/legacy PHP (no framework, no router — file = web endpoint) diagnosis. Covers SQL Injection, OS Command Injection, LFI/RFI, Reflected XSS, Hardcoded Secret, Weak Crypto, Path Traversal, Eval/Code Injection. Runs scan_php_baseline.py (non-judging candidate tagging) then LLM manual diagnosis for all TP/FP, category, and severity judgment — no static analyzer exists for this target class. Use when asked to run PHP scan, PHP 진단, OCB-THP PHP repo 진단 on a target in testbed/. Part of the broader sec-audit-static pipeline.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Scan PHP

## Overview
이 skill은 `sec-audit-static` 전체 파이프라인에서 **라우터/프레임워크가 없는 레거시 raw PHP**
(예: OCB-THP 산하 `ocb_php/` flat 구조 레포) 진단만을 담당하는 모듈입니다.

독립 실행 가능: `sec-scan-php/` + `shared/scripts/scan_php_baseline.py`

> ⚠️ **다른 5개 skill과의 핵심 차이 — 정적분석기 자체가 없다.**
> PHP는 라우터가 없어 파일 자체가 웹 진입점이며(1파일=1endpoint), Java/Kotlin 대상
> `scan_api.py`처럼 프레임워크 애노테이션을 파싱해 엔드포인트를 추출할 방법이 없다.
> `scan_php_baseline.py`는 `sec-scan-auth`와 동일하게 **판정 없는 후보 태깅
> (candidate tagging)** 만 수행하고 (전량 `result: "정보"`, `needs_review: true`),
> category/severity/TP-FP 최종 판정은 **LLM-Check(수동진단)가 전담**한다.

## Workflow

### Step 1: Load references

**로컬 (이 skill 전용)**
- `references/task_prompts/task_php_asset_identification.md` - PHP 전용 자산 식별 절차 (라우터 없음 — 웹루트 `.php` 파일 전수 나열)
- `references/task_prompts/task_php_baseline.md` - Auto-Scan(후보 태깅) 실행 절차
- `references/task_prompts/task_php_llm_review.md` - PHP LLM 수동진단 절차 (candidate_type별 판정기준)
- `references/php_diagnosis_criteria.md` - PHP 특화 취약 패턴 ↔ `vuln_taxonomy.md` 카테고리 매핑

**공유 (shared/)**
- `shared/references/workflow.md` - Phase/Task 실행 맵, 보안 정책
- `shared/references/output_schemas.md` - JSON 출력 스키마
- `shared/references/vuln_taxonomy.md` - Section 1/2/4 (Injection/XSS/Data) category/cwe_id/owasp_category 표준값 + 코드 인젝션(CWE-95) 행
- `shared/references/severity_criteria.md` - 위험도 매핑
- `shared/references/manual_review_prompt.md` - LLM 수동진단 페르소나, 진단기준, 답변원칙
- `shared/references/finding_writing_guide.md` - finding 품질 기준 (code_snippet 필수, 한국어 설명)
- `shared/references/tooling.md` - 코드 브라우저 도구 (rg/ctags)
- `shared/references/unsupported_lang_targets.md` - PHP 지원 현황 (본 skill로 갱신됨)

### ⚠️ 사전 필수 — 소스코드 Clone

> testbed/ 에 소스코드가 없으면 진단을 시작할 수 없다.
> **WSL에서 직접 아래 명령을 실행한다.** clone_repo.py가 자동으로 PowerShell(Windows git)을 경유하여 Bitbucket에 접근한다.

```bash
# WSL(Ubuntu) 터미널에서 실행
python3 tools/clone_repo.py <PROJECT> <REPO>
# 예: python3 tools/clone_repo.py OCB-THP ocb_game_biz_matgo
```

실행 결과로 출력되는 `state/<repo>/php/<YYYYMMDD_HHMM>/` 경로를 skill 실행 시 입력할 것.

testbed/ 에 소스코드가 없으면 **위 명령을 직접 실행하고 clone 완료 후 진단을 이어서 진행**한다.

---

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주 (Autonomous Execution)**: 실행 중에는
> "do you want to proceed?", "계속할까요?", "다음 단계로 진행할까요?" 등
> **어떠한 확인 질문도 하지 않는다.**
>
> - 자산 식별 → Auto-Scan(후보 태깅) → LLM-Check(전량 수동진단) 전 구간을 중단 없이 진행한다.
> - 스크립트 실패·파일 없음 등 예상 범위 내 오류는 fallback을 자동 적용하고 계속 진행한다.
> - 예외: 토큰/자격증명 누락처럼 사람만 해결할 수 있는 blocking 오류 발생 시에만 보고 후 대기한다.
> - **이 skill은 프레임워크 없는 raw PHP 전용**이다. Laravel/CodeIgniter 등 프레임워크가 확인되면
>   `php_diagnosis_criteria.md`의 "프레임워크 PHP 확인 시" 절차에 따라 범위를 재검토하고 진행한다.

### Step 2: Execute tasks

**Phase 1 — 자산 식별 (Asset Identification)**
- `references/task_prompts/task_php_asset_identification.md` 절차 실행
- **주의**: 공용 `task_11_asset_identification.md`의 "PHP 판정" 분기(Auto-Scan skip)를 따르지
  않는다 — 이 skill은 그 분기가 skip하도록 만든 대상을 정면으로 진단하기 위한 것이다.
- 웹루트 하위 `.php` 파일 전수 나열 (vendor/JS 번들 등 비-PHP 자산 제외), 프레임워크 유무 확인

**Auto-Scan Phase — PHP 취약 패턴 후보 태깅 (판정 없음)**

```bash
python3 shared/scripts/scan_php_baseline.py <src>/ocb_php \
    -o state/<prefix>/php.json
```

태깅 항목 (전부 `result: "정보"`, `needs_review: true` — TP/FP 판정 아님):
- **SQLI_CANDIDATE**: `mysql_query`/`mysqli_query` 등에 변수 인자 포함
- **CMD_INJECTION_CANDIDATE**: `system`/`exec`/`shell_exec`/`passthru`/백틱 연산자에 변수 인자
- **LFI_RFI_CANDIDATE**: `include`/`require`(`_once`) 인자에 변수 포함(리터럴 아님)
- **XSS_CANDIDATE**: `echo`/`print`가 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`를 `htmlspecialchars`/`htmlentities` 경유 없이 직접 출력
- **HARDCODED_SECRET_CANDIDATE**: `pass`/`password`/`secret`/`apikey`/`token` 등 변수·배열키에 리터럴 문자열 대입
- **WEAK_CRYPTO_CANDIDATE**: `md5()`/`sha1()` 호출
- **PATH_TRAVERSAL_CANDIDATE**: `fopen`/`file_get_contents`/`readfile`/`unlink` 인자에 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` 직접 전달
- **EVAL_CANDIDATE**: `eval`/`assert`/`create_function` 인자에 변수 포함
- **INSECURE_TLS_CLIENT_CANDIDATE**: `CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST`를 `false`/`0`으로 설정
  (2026-09-16 ocb_game_biz PHP-010 추가진단으로 신설 — 결제 연동 curl 요청에서 TLS 인증서 검증이 비활성화된
  패턴이 기존 8종에 없어 원본 스캔 단계에서부터 누락됐던 것을 보완)

출력: `state/<prefix>/php.json` (`candidates[]` — 전량 판정 대기, `findings[]`는 항상 빈 배열)

**LLM-Check Phase — 전량 수동 심층진단 (LLM)**
- 대상: `php.json`의 `candidates[]` 전체 (Auto-Scan이 취약 판정을 하지 않으므로 교차검증 단계 없음)
- 절차: `references/task_prompts/task_php_llm_review.md` — candidate_type별 그룹으로 순회하며
  실제 실행 경로(웹에서 직접 호출 가능한지, wrapper 함수 내부 추적) + sink/source 데이터 흐름 확인
- `manual_review_prompt.md` 페르소나 재사용
- 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note` + 최종
  `category`(`vuln_taxonomy.md` 표준값)/`severity`/`result`(`"취약"`/`"정보"`, FP는 findings에서 제외)

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.
- `findings_php.json`의 각 finding은 `category`가 `vuln_taxonomy.md` 표준값
  (`SQL인젝션`/`OS Command Injection`/`코드 인젝션`/`Reflected XSS`/`HARDCODED_SECRET`/
  `WEAK_CRYPTO`/`파일 다운로드 경로 조작`/`원격 파일 포함`) 중 하나인지 확인 —
  Auto-Scan 단계의 `candidate_type`(`*_CANDIDATE`)을 그대로 category에 남기지 말 것.

### Step 4: Summary 출력

LLM-Check Phase 완료 후 `state/<prefix>/summary_php.md` 를 생성한다.

**읽을 파일**:
- `state/<prefix>/php.json` — Auto-Scan 후보 태깅 결과
- LLM-Check 결과 (`task_php_llm.json` 등)

**출력 형식**:

```markdown
# PHP 취약점 진단 결과 요약 — <repo명>

진단일: YYYY-MM-DD | 대상: <source_repo_url> | LLM 검증: 완료

## 결과 통계

| 카테고리 | 취약 | 정보 | 양호 |
|---|---|---|---|
| SQL인젝션 | N | N | N |
| OS Command Injection | N | N | N |
| 코드 인젝션 | N | N | N |
| Reflected XSS | N | N | N |
| HARDCODED_SECRET | N | N | N |
| WEAK_CRYPTO | N | N | N |
| 파일 다운로드 경로 조작 | N | N | N |
| 원격 파일 포함 | N | N | N |
| **합계** | **N** | **N** | **N** |

## Finding 목록

| ID | 제목 | 위험도 | 카테고리 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|---|
| PHP-001 | 하드코딩된 Redis 비밀번호 | 4 고위험 | HARDCODED_SECRET | ocb_php/channelcheck.php:19 | 취약 | 수동진단(LLM) |

> 양호 항목은 목록에서 제외. 취약·정보만 기재.

## 소스 파일
- `state/<prefix>/php.json`
```

**작성 규칙**:
- Finding 목록은 심각도 내림차순 (Critical → High → Medium → Low → Info)
- `evidence.file` + `evidence.lines` 에서 파일:라인 추출
- 양호는 통계에만 포함, 목록에는 미기재

### Step 4-1: LLM-Check 완료 확인 — 업로드 전 필수 게이트

> **HARD RULE**: `task_php_llm.json` 미존재 상태로 업로드 금지.
> 이 skill은 Auto-Scan이 판정을 하지 않으므로(전량 `needs_review: true`) LLM 교차검증 없는
> 업로드는 **모든 candidate가 미판정 상태로 리포트에 유입**되는 것과 같다.
> `findings_php.json` 생성 시 반드시 `llm_checked: true` 설정.

업로드 전 확인:
```bash
python3 -c "
import pathlib, sys
prefix = 'state/<prefix>'
has_llm = pathlib.Path(f'{prefix}/task_php_llm.json').exists()
findings = pathlib.Path(f'{prefix}/findings_php.json')
if not has_llm:
    print('[BLOCK] task_php_llm.json 없음 — LLM-Check 먼저 수행', file=sys.stderr); sys.exit(1)
if findings.exists():
    import json
    d = json.loads(findings.read_text())
    if not d.get('llm_checked', False):
        print('[BLOCK] findings_php.json llm_checked=false', file=sys.stderr); sys.exit(1)
print('[OK] LLM-Check 완료 확인')
"
```

통과 조건 충족 후 Phase C-1을 수행한다.

### Step 4-2: 사람 판정 필드 침범 금지 (HARD RULE)

> **HARD RULE**: 이 skill(Auto-Scan/LLM-Check 어느 단계도)은 `reviewed`/`review_status` 필드를 직접 설정하지 않는다.
> 이 두 필드는 `/sec-review` §4의 사람 판정에서만 부여되며, `tools/audit_utils.py log-review` 호출로 `state/audit_log.json`에 기록되는 것만이 유효한 판정 경로다.
> LLM-Check가 TP로 확정한 finding이라도 `llm_verdict: "TP"` / `manual_review_note` 까지만 기록하고 `reviewed`/`review_status`는 미기재 상태로 남겨, 예외 없이 `/sec-review`를 거치도록 한다.
> (2026-08-03 displayadmin_server XSS-001 — LLM-Check 판정이 사람 판정 필드에 유출되어 `/sec-review`를 우회한 채 보고서에 반영된 사고 재발 방지.)

---

### Step C: Phase C-1 — LLM 데이터 접근 로그 업데이트

> **정책**: `shared/references/llm_data_cleansing_policy.md` | **절차**: `shared/references/phase_c_cleansing.md`

LLM-Check 완료 직후 수행. **testbed는 이 단계에서 삭제하지 않는다.**
testbed 삭제 + Confluence 등록은 `/sec-review` 완료 시 Phase C-2에서 수행.

**수행**:

1. 이 세션에서 `testbed/<repo>/` 경로를 Read 도구로 접근한 파일 목록 정리 (Phase 1 / Phase 3 구분)
2. `state/<repo>/llm_data_access_log.json` 생성(없으면) 또는 `skills[]` 배열에 php 항목 append:
   ```json
   {
     "skill": "php",
     "scan_dir": "state/<repo>/php/<YYYYMMDD_HHMM>",
     "scanned_at": "<진단 시작 ISO8601 +09:00>",
     "llm_accessed_files": [
       { "phase": "Phase 1 - Asset Identification", "purpose": "자산 식별", "files": ["testbed/<repo>/ocb_php/...", "..."] },
       { "phase": "Phase 3 - LLM-Check", "purpose": "수동진단", "files": ["testbed/<repo>/ocb_php/..."] }
     ]
   }
   ```
3. 신규 생성 시 `project`는 `state/<repo>/20*/scan_meta.json`의 `bb_project` 값 사용 (없으면 `"?"`)
4. `cleansing_completed: false` 유지

**완료 출력**:
```
[Phase C-1] llm_data_access_log.json 업데이트 완료
  skill  : php
  접근파일: N건 (Phase 1: N / Phase 3: N)
  로그   : state/<repo>/llm_data_access_log.json
  [다음] /sec-review 완료 시 testbed 삭제 + Confluence 레지스트리 등록 수행
```

### Step C-1b: 전사 진단현황 위키 갱신 (필수 — 매 skill 완료마다)

> **정책**: 야간 배치뿐 아니라 주간 인터랙티브 세션에서 `/sec-scan-php`를 실행한 경우도
> 예외 없이 이 단계를 수행한다. 두 스크립트 모두 `state/`(및 `docs/ocb_scan_plan.md`
> 체크리스트)를 다시 읽어 재계산하는 읽기 전용 집계이므로 `/sec-review` 판정 완료
> 여부와 무관하게 즉시 실행 가능하다 ([[feedback_wiki_refresh_every_scan.md]] — 5개
> `/sec-scan-*`에는 이 단계가 있었으나 `/sec-scan-php`에는 누락되어 있어, PHP 레포를
> 5개 skill의 자동위임 없이 `/sec-scan-php` 단독으로 실행한 경우(예: P3-F: OTH 배치)
> 위키가 갱신되지 않는 사각지대가 있었다 — 2026-09-10 수정).

> **⚠️ 두 페이지 모두 갱신 필수 — 하나만 갱신하면 안 됨**:
> - `docs/ocb_scan_plan.md` → Confluence pageId `750459063` — **실제 진단현황 갱신·추적이
>   진행되는 정책상 원본(authoritative) 페이지**. `update_ocb_plan.py --auto`가 `state/`를
>   스캔해 `findings_php.json` 존재를 확인하고, 이 레포의 **INJ/XSS/FILE/DATA 4개 컬럼을
>   동시에** `✅ YYYY-MM-DD (PHP)`로 갱신한다 — `/sec-scan-php`가 이 4개 skill 범위를
>   단일 진단으로 커버하기 때문이다(SCA/auth 컬럼은 대상 아님).
> - `docs/system_code_scan_status.md` → Confluence pageId `771074589` — 전사 297개
>   시스템코드 단위의 더 넓은 집계 뷰. `750459063`의 체크리스트를 우선(sticky) 참조하므로
>   반드시 **`update_ocb_plan.py --auto`를 먼저 실행한 뒤** 재생성해야 최신 상태가 반영된다.

**수행 (반드시 이 순서로)**:

```bash
python3 tools/update_ocb_plan.py --auto
python3 tools/build_system_code_scan_status.py
python3 tools/publish_confluence.py docs/system_code_scan_status.md
```

- Confluence 접근 실패(네트워크/토큰)는 non-blocking — 에러 출력 후 계속 진행. 단
  `CONFLUENCE_TOKEN` 자체 누락처럼 사람만 해결 가능한 경우만 보고 후 대기.

**완료 출력**:
```
[Step C-1b] 전사 진단현황 위키 갱신 완료
  체크리스트 : docs/ocb_scan_plan.md → pageId 750459063 (INJ/XSS/FILE/DATA (PHP) 갱신)
  전사집계   : docs/system_code_scan_status.md → pageId 771074589
```

Step C-1b 완료 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다.

## Resources

### 로컬 (이 skill 폴더 내)
- `references/task_prompts/task_php_asset_identification.md`
- `references/task_prompts/task_php_baseline.md`
- `references/task_prompts/task_php_llm_review.md`
- `references/php_diagnosis_criteria.md`

### 공유 (shared/references/)
#### Workflow & Policy
- `workflow.md`, `output_schemas.md`, `severity_criteria.md`, `vuln_taxonomy.md`

#### Diagnosis Criteria
- `manual_review_prompt.md`

#### Tooling & Rules
- `tooling.md`
- `unsupported_lang_targets.md`

### 스크립트
- `shared/scripts/scan_php_baseline.py` — PHP 취약 패턴 후보 태깅 (판정 없음, 이 skill 전용, 소스 디렉터리 직접 순회)
