---
name: sec-scan-data
description: Modularized SAST skill for Data Protection diagnosis — CORS misconfiguration, hardcoded Secrets, JWT vulnerabilities, Cryptography weaknesses, PII Logging, and API Response PII exposure. Runs scan_data_protection.py then LLM cross-verification. Use when asked to run data protection scan, 데이터 보호 진단, or CORS/Secrets/JWT/암호화/API응답PII 취약점 분석 on a target in testbed/. Part of the broader sec-audit-static pipeline; future updates will include Jira integration.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Scan Data

## Overview
이 skill은 `sec-audit-static` 전체 파이프라인에서 **데이터 보호(CORS / Secrets / JWT / Cryptography / PII Logging)** 진단만을 담당하는 모듈입니다.

독립 실행 가능: `sec-scan-data/` + `shared/scripts/scan_data_protection.py`

향후 Jira 연동 기능이 추가될 예정입니다.

## Workflow

### Step 1: Load references

**로컬 (이 skill 전용)**
- `shared/references/task_prompts/task_11_asset_identification.md` - 자산 식별 절차
- `references/task_prompts/task_25_data_protection.md` - 데이터 보호 LLM 검토 절차 (CORS/Secrets/JWT/Crypto/PII 판정기준)

**공유 (shared/)**
- `shared/references/workflow.md` - Phase/Task 실행 맵, 보안 정책
- `shared/references/output_schemas.md` - JSON 출력 스키마
- `shared/references/severity_criteria.md` - 위험도 매핑
- `shared/references/cross_verification.md` - Phase 3-1 교차검증 + Phase 3-2 LLM 수동 심층진단 절차
- `shared/references/manual_review_prompt.md` - LLM 수동진단 페르소나, 진단기준, 답변원칙
- `shared/references/secret_scanning.md` - Gitleaks 기반 시크릿 감지
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
python3 tools/new_scan.py <repo> --skill data --clone <PROJECT> <REPO>
# 예: python3 tools/new_scan.py ocb-community-api --skill data --clone OCBWEBVIEW ocb-community-api
```

실행 결과로 출력되는 `state/<repo>/data/<YYYYMMDD_HHMM>/` 경로를 skill 실행 시 입력할 것.

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
- frontend/backend 판별, 언어/프레임워크 확인, 설정 파일 위치(`application.yml`, `.env`) 식별
- PHP 등 미지원 언어이면 Auto-Scan Phase skip 후 기록

**Phase 1 → Auto-Scan 분기 결정**

| 레포 유형 | 판별 기준 | Auto-Scan 동작 |
|-----------|-----------|----------------|
| 순수 백엔드 (Java/Kotlin) | `.java`/`.kt` ≥ 5개, `package.json` 없음 | 기존 Java 스캔 실행 (Secrets/Logging/Crypto/JWT/DTO/CORS/Header) |
| 순수 프론트엔드 (TS/JS) | `.java`/`.kt` < 5개 + `package.json` 존재 | `scan_frontend_data_exposure()` 실행 (console PII/localStorage/하드코딩 시크릿/NEXT_PUBLIC_) |
| 풀스택 (Java + TS) | `.java`/`.kt` ≥ 5개 + `package.json` 존재 | Java 스캔 실행 (현재) — 추후 양쪽 스캔으로 확장 예정 |
| PHP / 미지원 언어 | `.php` 주요 파일 존재 | Auto-Scan skip, LLM 수동 진단으로 전환 |

> **스크립트 자동 감지**: `_is_frontend_repo()` 함수가 Java/Kotlin 파일 수와 `package.json` 존재 여부를 자동 판별하므로 `scan_data_protection.py` 실행 시 별도 플래그 불필요.

**Auto-Scan Phase — 데이터 보호 정적 분석 (Python 스크립트)**

```bash
python3 shared/scripts/scan_data_protection.py <src> \
    -o state/<prefix>/data.json
```

> **API 인벤토리 불필요**: 설정 파일, 소스코드, `.env` 파일 등을 직접 탐색하므로
> `scan_api.py` 선행 실행 없이 단독 실행 가능합니다.
> (선택적으로 `--api-inventory`를 지정하면 DTO 노출 진단의 엔드포인트 역추적이 강화됩니다.)

진단 항목 (백엔드 모드 — Java/Kotlin):
- **CORS**: `Access-Control-Allow-Origin: *`, 동적 Origin 반영 여부
- **Secrets**: 하드코딩된 API 키/비밀번호/토큰 (내장 패턴 탐지 — `_redact_snippet()`으로 code_snippet 자동 마스킹)
- **JWT**: 알고리즘 검증 누락, 약한 시크릿, `none` 알고리즘 허용
- **Cryptography**: 약한 알고리즘(MD5/SHA1/DES/ECB), 고정 IV/Salt
- **PII Logging**: `logger.*`에 개인식별정보 포함 여부
- **API_RESPONSE_PII**: 서비스 레이어에서 userInfo PII 필드(mdn/userName/birthDate/ciNo 등)를 마스킹 없이 응답 DTO에 직접 할당하는 패턴 — CWE-359
- **DTO_EXPOSURE (@ToString PII)**: `@ToString`/`@Data` 클래스 내 PII 필드(mbrId/userId/email 등)가 `@ToString.Exclude` 없이 포함 — CWE-532

진단 항목 (프론트엔드 모드 — TS/JS/TSX/JSX/Vue):
- **console PII**: `console.log/debug/warn/error()` 내 PII 변수 출력 (운영=High, debug=Medium)
- **localStorage 민감정보**: `localStorage.setItem('token'/..., ...)` — High
- **sessionStorage 민감정보**: `sessionStorage.setItem('token'/..., ...)` — Medium
- **API 응답 통째 로그**: `console.log(response/res/data)` — Medium
- **하드코딩 시크릿**: `const apiKey = "..."` 형태 직접 할당 — High
- **NEXT_PUBLIC_ 번들 노출**: 시크릿이 `NEXT_PUBLIC_` 접두사로 클라이언트 번들에 포함 — Medium

> **DTO_EXPOSURE 기본 심각도 정책**
> - HTTP 직렬화 경로(엔드포인트 매핑) 없이 `@ToString`만 있는 경우: **기본 Medium / 정보(Informational)**
>   — toString() 호출 조건, 로그 저장 여부, 로그 접근 통제가 실현 여부를 결정하므로 직접적 취약점이 아닌 잠재적 조건으로 분류
> - `취약`으로 상향 판단은 `/sec-review` 시 리뷰어가 직접 결정 (예: 배치 로그에서 실제 toString() 호출 확인, 로그가 중앙 수집되고 비개발자 접근 가능한 환경)

출력: `state/<prefix>/data.json`

LLM 검토 절차는 `references/task_prompts/task_25_data_protection.md` 전체 절차 준수.

**LLM-Check Phase — 교차검증 + 수동 심층진단 (LLM)**
- **LLM-Check Phase 1** (자동판정 "취약" 건): `shared/references/cross_verification.md` LLM-Check Phase 1 절차
  - CORS 정책 실제 적용 범위 확인, JWT 라이브러리 설정값 검증
  - FP는 `diagnosis_method: "교차검증(수동)"` 으로 재분류
- **LLM-Check Phase 2** ("정보/수동검토" 건): `shared/references/cross_verification.md` LLM-Check Phase 2 + `manual_review_prompt.md`
  - 대상: `result: "정보"` + `needs_review: true`, `taint_confirmed: null`
  - 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note`

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.

### Step 4: Summary 출력

LLM-Check Phase 완료 후 `state/<prefix>/summary_data.md` 를 생성한다.

**읽을 파일**:
- `state/<prefix>/data.json` — 스크립트 자동 판정 결과

**출력 형식**:

```markdown
# 데이터 보호 취약점 진단 결과 요약 — <repo명>

진단일: YYYY-MM-DD | 대상: <source_repo_url> | LLM 검증: 완료

## 결과 통계

| 카테고리 | 취약 | 정보 | 양호 |
|---|---|---|---|
| CORS | N | N | N |
| Secrets (하드코딩) | N | N | N |
| JWT | N | N | N |
| Cryptography | N | N | N |
| PII Logging | N | N | N |
| **합계** | **N** | **N** | **N** |

## Finding 목록

| ID | 제목 | 위험도 | 카테고리 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|---|
| DATA-001 | CORS — 동적 Origin 반영 | 3 중간위험 | CORS | src/.../WebConfig.java:30 | 취약 | 자동스캔(SAST) |

> 양호 항목은 목록에서 제외. 취약·정보만 기재.

## 소스 파일
- `state/<prefix>/data.json`
```

**작성 규칙**:
- Finding 목록은 심각도 내림차순 (Critical → High → Medium → Low → Info)
- 카테고리는 CORS / Secrets / JWT / Cryptography / PII Logging 으로 구분
- `evidence.file` + `evidence.lines` 에서 파일:라인 추출
- 양호는 통계에만 포함, 목록에는 미기재

### Step 4-1: LLM-Check 완료 확인 — 업로드 전 필수 게이트

> **HARD RULE**: `task25_llm.json` 미존재 상태로 업로드 금지.
> CORS/Secrets/JWT/Cryptography/PII 항목은 LLM 교차검증 없이 FP율이 높다.
> `findings_DATA.json` 생성 시 반드시 `llm_checked: true` 설정.

업로드 전 확인:
```bash
python3 -c "
import pathlib, sys
prefix = 'state/<prefix>'
has_llm = pathlib.Path(f'{prefix}/task25_llm.json').exists()
findings = pathlib.Path(f'{prefix}/findings_DATA.json')
if not has_llm:
    print('[BLOCK] task25_llm.json 없음 — LLM-Check 먼저 수행', file=sys.stderr); sys.exit(1)
if findings.exists():
    import json
    d = json.loads(findings.read_text())
    if not d.get('llm_checked', False):
        print('[BLOCK] findings_DATA.json llm_checked=false', file=sys.stderr); sys.exit(1)
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
2. `state/<repo>/llm_data_access_log.json` 생성(없으면) 또는 `skills[]` 배열에 data 항목 append:
   ```json
   {
     "skill": "data",
     "scan_dir": "state/<repo>/data/<YYYYMMDD_HHMM>",
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
  skill  : data
  접근파일: N건 (Phase 1: N / Phase 3: N)
  로그   : state/<repo>/llm_data_access_log.json
  [다음] /sec-review 완료 시 testbed 삭제 + Confluence 레지스트리 등록 수행
```

Phase C-1 완료 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다.

## Resources

### 로컬 (이 skill 폴더 내)
- `shared/references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_25_data_protection.md`

### 공유 (shared/references/)
#### Workflow & Policy
- `workflow.md`, `output_schemas.md`, `severity_criteria.md`

#### Diagnosis Criteria
- `cross_verification.md`, `manual_review_prompt.md`, `secret_scanning.md`

#### Tooling & Rules
- `tooling.md`, `seed_usage.md`
- `large_repo_multi_module.md`, `unsupported_lang_targets.md`
- `rules/semgrep/config-hardcoded-secrets.yaml`
- `rules/semgrep/properties-hardcoded-secrets.yaml`
- `rules/semgrep/ssl-client-bypass.yaml`
- `rules/semgrep/redis-template-default-serializer.yaml`
- `rules/semgrep/grpc-plaintext-channel.yaml`
- `rules/joern/pcona-console-taint.sc`
