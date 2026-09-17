# sec-scan-php — 개요 및 절차

작성일: 2026-09-11 | 대상 독자: 보안진단실 Auditor | 레포: `palantir` (`sec-scan-php/`)

## 1. 개요

`/sec-scan-php`는 **라우터/프레임워크가 없는 레거시 raw PHP**(1 `.php` 파일 = 1 웹
엔드포인트 구조) 진단만을 전담하는 독립 SAST skill입니다. 2026-09-03 신설되었습니다.

**신설 배경**: 기존 5개 `/sec-scan-*`(injection/xss/file/data/auth)은 Phase 1 자산
식별에서 PHP를 감지하면 Auto-Scan을 전량 skip하도록 되어 있어, OCB-THP 산하 6개
레거시 PHP 레포가 지금까지 SAST 사각지대였습니다. `sec-scan-php`는 이 공백을 메우기
위해 만들어졌습니다.

**다른 5개 skill과의 핵심 차이 — 정적분석기 자체가 없음**: PHP는 라우터가 없어
파일 자체가 웹 진입점이므로, Java/Kotlin 대상 `scan_api.py`처럼 프레임워크 애노테이션을
파싱해 엔드포인트를 추출할 방법이 없습니다. 대신 `sec-scan-auth`와 동일한 패턴을
채택합니다 — Auto-Scan은 **판정 없는 후보 태깅(candidate tagging)** 만 수행하고
(전량 `result: "정보"`, `needs_review: true`), category/severity/TP·FP 최종 판정은
**LLM-Check(전량 수동진단)** 가 전담합니다.

## 2. 대상 레포

OCB-THP 프로젝트 산하 6개 레거시 PHP 레포가 현재 진단 대상으로 식별되어 있습니다.

| 레포 | 비고 |
|---|---|
| `ocb_fun_real` | |
| `ocb_game_biz` | |
| `ocb_game_biz_admin` | |
| `ocb_game_biz_matgo` | |
| `ocb_game_biz_matgo_php_real` | |
| `ocb_game_bluemarble` | system_code `C001753`, 서비스명 "OCB-부루마블" |

> 6개 레포에 대한 실제 진단 실행 여부는 `docs/ocb_scan_plan.md`(pageId 750459063)
> 체크리스트에서 확인합니다. skill 자체의 신설/배선과 실제 진단 실행은 별개 작업입니다.

## 3. 진단 항목 (Candidate 9종 → 표준 카테고리 매핑)

Auto-Scan(`scan_php_baseline.py`)이 태깅하는 9종 후보와, LLM-Check가 최종 확정하는
`vuln_taxonomy.md` 표준 카테고리의 매핑은 다음과 같습니다(2026-09-16 `INSECURE_TLS_CLIENT_CANDIDATE`
추가 전까지는 8종이었습니다).

| candidate_type | 탐지 패턴 | 최종 category (LLM 확정) | CWE |
|---|---|---|---|
| `SQLI_CANDIDATE` | `mysql_query`/`mysqli_query` 등에 변수 인자 | SQL인젝션 | CWE-89 |
| `CMD_INJECTION_CANDIDATE` | `system`/`exec`/`shell_exec`/`passthru`/백틱에 변수 인자 | OS Command Injection | CWE-78 |
| `LFI_RFI_CANDIDATE` | `include`/`require`(`_once`) 인자에 변수(리터럴 아님) | 파일 다운로드 경로 조작(LFI) / 원격 파일 포함(RFI) | CWE-22 / CWE-918 |
| `XSS_CANDIDATE` | `echo`/`print`가 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`를 살균 없이 직접 출력 | Reflected XSS | CWE-79 |
| `HARDCODED_SECRET_CANDIDATE` | `pass`/`password`/`secret`/`apikey`/`token` 변수·배열키에 리터럴 대입 | HARDCODED_SECRET | CWE-798 |
| `WEAK_CRYPTO_CANDIDATE` | `md5()`/`sha1()` 호출 | WEAK_CRYPTO | CWE-327 |
| `PATH_TRAVERSAL_CANDIDATE` | `fopen`/`file_get_contents`/`readfile`/`unlink` 인자에 사용자 입력 직접 전달 | 파일 다운로드 경로 조작 | CWE-22 |
| `EVAL_CANDIDATE` | `eval`/`assert`/`create_function` 인자에 변수 포함 | **코드 인젝션** (신규 taxonomy, 2026-09-03 추가) | CWE-95 |
| `INSECURE_TLS_CLIENT_CANDIDATE` | `CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST`를 `false`/`0`으로 설정 | INSECURE_TLS_CLIENT (2026-09-16 ocb_game_biz PHP-010 사후발견으로 편입) | CWE-295 |

> `코드 인젝션`(CWE-95, `A03:2021 Injection`, 기본 Critical)은 이 skill을 위해
> `vuln_taxonomy.md` §1에 신규 추가된 카테고리입니다. 문자열→코드 실행
> (`eval()`, 문자열 인자 `assert()`, `create_function()`)을 커버하며, 기존
> SQL/OS Command/SSTI 어느 카테고리에도 맞지 않아 별도 신설되었습니다.

## 4. 아키텍처 — 2단계 파이프라인

```
Auto-Scan (scan_php_baseline.py)          LLM-Check (task_php_llm_review.md)
────────────────────────────────    →    ─────────────────────────────────
정규식 기반 9종 candidate 태깅만          candidate_type별 그룹 순회
result: "정보" (전량, 판정 아님)          실제 실행경로 추적 (웹 직접 호출 가능?
needs_review: true (전량)                  wrapper 함수 내부 추적, sink/source 흐름)
                                           TP/FP + category + severity 최종 확정
                                           findings: "취약"/"정보"만 남음 (FP 제외)
```

Auto-Scan은 취약 여부를 판정하지 않으므로(다른 5개 skill처럼 Auto-Scan 결과를
LLM이 교차검증하는 단계가 없음), **LLM-Check가 유일한 판정 주체**입니다.

## 5. 실행 절차 (Workflow)

### Step 0. 사전 필수 — 소스코드 Clone

```bash
python3 tools/clone_repo.py <PROJECT> <REPO>
# 예: python3 tools/clone_repo.py OCB-THP ocb_game_biz_matgo
```

### Step 1. 참조 문서 로드

- `references/task_prompts/task_php_asset_identification.md` — PHP 전용 자산 식별
- `references/task_prompts/task_php_baseline.md` — Auto-Scan 실행 절차
- `references/task_prompts/task_php_llm_review.md` — candidate_type별 LLM 판정 기준
- `references/php_diagnosis_criteria.md` — PHP 패턴 ↔ `vuln_taxonomy.md` 매핑
- 공유 `shared/references/`: `workflow.md`, `output_schemas.md`, `vuln_taxonomy.md`, `severity_criteria.md`, `manual_review_prompt.md`, `finding_writing_guide.md`, `tooling.md`, `unsupported_lang_targets.md`

### Step 2. Phase 1 — 자산 식별

- 웹루트 하위 `.php` 파일 전수 나열(vendor/JS 번들 등 비-PHP 자산 제외)
- 프레임워크 유무 확인 — Laravel/CodeIgniter 등 프레임워크 확인 시 `php_diagnosis_criteria.md`의 "프레임워크 PHP 확인 시" 절차로 범위 재검토

### Step 3. Auto-Scan — 후보 태깅 (판정 없음)

```bash
python3 shared/scripts/scan_php_baseline.py <src>/ocb_php \
    -o state/<prefix>/php.json
```

출력: `candidates[]`(전량 판정 대기) / `findings[]`(항상 빈 배열)

### Step 4. LLM-Check — 전량 수동 심층진단

- 대상: `php.json`의 `candidates[]` 전체
- candidate_type별 그룹 순회, 실제 실행 경로 + sink/source 데이터 흐름 확인
- 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note` + 최종 `category`/`severity`/`result`

### Step 5. 산출물 검증 게이트 (Step 4-1, HARD RULE)

`task_php_llm.json` 미존재 상태에서 업로드 금지. `findings_php.json`에 반드시
`llm_checked: true` 설정 — 이 조건 미충족 시 모든 candidate가 미판정 상태로
리포트에 유입되는 것과 동일하므로 업로드 전 스크립트로 자동 검증합니다.

### Step 6. Summary 생성

`state/<prefix>/summary_php.md` — 카테고리별 결과 통계 표 + Finding 목록(취약·정보만).

### Step 7. Step C-1 — LLM 데이터 접근 로그 갱신

`state/<repo>/llm_data_access_log.json`에 `php` skill 항목 append.
testbed는 이 단계에서 삭제하지 않음(삭제는 `/sec-review` 완료 시 Phase C-2).

### Step 8. Step C-1b — 전사 진단현황 위키 자동 갱신 (필수)

```bash
python3 tools/update_ocb_plan.py --auto
python3 tools/build_system_code_scan_status.py
python3 tools/publish_confluence.py docs/system_code_scan_status.md
```

`findings_php.json` 존재 확인 시 해당 레포의 **INJ/XSS/FILE/DATA 4개 컬럼을 동시에**
`✅ YYYY-MM-DD (PHP)`로 갱신합니다 — `/sec-scan-php` 1회 진단이 이 4개 skill 범위를
전부 커버하기 때문입니다(SCA/auth 컬럼은 대상 아님).

### Step 9. `/sec-review`로 인터랙티브 정탐/오탐 판정

Step C-1b 완료 후 통상적인 `/sec-review <repo>` 절차로 인계됩니다.

## 6. 사람 판정 필드 침범 금지 (Step 4-2, HARD RULE)

Auto-Scan/LLM-Check 어느 단계도 `reviewed`/`review_status` 필드를 직접 설정하지
않습니다. 이 두 필드는 `/sec-review`의 사람 판정에서만 부여되며, `tools/audit_utils.py
log-review` 호출로 `state/audit_log.json`에 기록되는 것만이 유효한 판정 경로입니다.
LLM-Check가 TP로 확정한 finding이라도 `llm_verdict: "TP"` / `manual_review_note`까지만
기록하고 `reviewed`/`review_status`는 미기재 상태로 남겨, 예외 없이 `/sec-review`를
거치도록 합니다.

> 2026-08-03 displayadmin_server XSS-001 사고(LLM-Check 판정이 사람 판정 필드에
> 유출되어 `/sec-review`를 우회한 채 보고서에 반영됨) 재발 방지 조치입니다.

## 7. 5개 `/sec-scan-*` → 자동 위임 구조

2026-09-03부터, 기존 5개 `/sec-scan-*`(injection/xss/file/data/auth)이 Phase 1
자산식별에서 대상 레포를 PHP로 판별하면 `/sec-scan-php`가 아직 실행되지 않은 경우
그 전체 절차(Phase1→Auto-Scan→LLM-Check)를 **인라인으로 자율 완주 위임 실행**합니다.

| 항목 | 내용 |
|---|---|
| 구현 위치 | `shared/references/task_prompts/task_11_asset_identification.md` §1-5 (5개 skill이 공통 참조하는 단일 지점) |
| Idempotency 판단 | `state/<repo>/php/*/findings_php.json` 존재 + `llm_checked: true` 여부. 이미 있으면 재실행하지 않음 |
| 다중 레포 인수 | 레포 단위로 독립 판단 (한 레포가 PHP라도 다른 레포는 영향받지 않음) |
| CLAUDE.md 근거 | BOUNDARY RULE "1. Skill 간 자동 연결 금지"의 2026-09-03 신규 예외 — "완료 후 다음 단계로 자동 이행"이 아니라 "이 skill이 애초에 이 언어를 다룰 수단이 없어 유일하게 다루는 skill로 위임"하는 것이므로 일반 규칙과 성격이 다름 |

`/sec-scan-php`를 이 위임 경로 없이 **직접 호출**해도 동일하게 동작하며, 이미 위임
실행된 결과가 있으면 그대로 재사용합니다.

## 8. 파이프라인 연동 현황

- `SKILL_ORDER`에 `"php"`가 `auth`와 `sca` 사이에 삽입되어 있습니다
  (`tools/generate_final_report.py`, `.claude/commands/sec-review.md`).
- `/sec-review`는 php findings도 auth와 동일하게(SCA와 달리) **건별 정탐/오탐
  판정 대상**입니다.
- Step C-1b(위키 갱신)는 5개 `/sec-scan-*`뿐 아니라 `/sec-scan-php` 단독 실행 시에도
  동일하게 수행됩니다(2026-09-10 보완 — 최초에는 `/sec-scan-php` SKILL.md에
  이 단계가 누락되어 있어, 자동위임 없이 단독 실행한 배치에서 위키가 갱신되지
  않는 사각지대가 있었습니다).

## 9. 산출물 파일 구조

```
state/<repo>/php/<YYYYMMDD_HHMM>/
├── php.json              # Auto-Scan 후보 태깅 결과 (candidates[], findings는 항상 빈 배열)
├── task_php_llm.json     # LLM-Check 원본 판정 결과
├── findings_php.json     # 최종 확정 findings (llm_checked: true 필수)
└── summary_php.md        # 카테고리별 결과 통계 + Finding 목록
```

## 10. 관련 문서

- `sec-scan-php/SKILL.md` — 이 문서의 원본 절차 정의
- `sec-scan-php/references/php_diagnosis_criteria.md`
- `sec-scan-php/references/task_prompts/{task_php_asset_identification,task_php_baseline,task_php_llm_review}.md`
- `shared/references/task_prompts/task_11_asset_identification.md` §1-5 — 5개 skill의 자동 위임 로직
- `shared/references/unsupported_lang_targets.md` — PHP 지원 현황
- `docs/ocb_scan_plan.md` (pageId 750459063) — 레포별 진단현황 체크리스트
