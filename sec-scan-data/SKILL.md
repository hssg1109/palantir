---
name: sec-scan-data
description: Modularized SAST skill for Data Protection diagnosis — CORS misconfiguration, hardcoded Secrets, JWT vulnerabilities, Cryptography weaknesses, and PII Logging. Runs scan_data_protection.py then LLM cross-verification. Use when asked to run data protection scan, 데이터 보호 진단, or CORS/Secrets/JWT/암호화 취약점 분석 on a target in testbed/. Part of the broader sec-audit-static pipeline; future updates will include Jira integration.
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
- `shared/references/poc_policy.md` - PoC 생성 규칙
- `shared/references/large_repo_multi_module.md` - 대형 repo / 멀티 모듈 진단 전략
- `shared/references/unsupported_lang_targets.md` - 자동 스캔 미지원 언어 (PHP 등)

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주 (Autonomous Execution)**: 실행 중에는
> "do you want to proceed?", "계속할까요?", "다음 단계로 진행할까요?" 등
> **어떠한 확인 질문도 하지 않는다.**
>
> - Phase 1 → Phase 2 → Phase 3 전 구간을 중단 없이 진행한다.
> - 스크립트 실패·빌드 오류·파일 없음 등 예상 범위 내 오류는 fallback을 자동 적용하고 계속 진행한다.
> - 예외: 토큰/자격증명 누락처럼 사람만 해결할 수 있는 blocking 오류 발생 시에만 보고 후 대기한다.

### Step 2: Execute tasks

**Phase 1**: 자산 식별.
- `shared/references/task_prompts/task_11_asset_identification.md` 절차 실행
- frontend/backend 판별, 언어/프레임워크 확인, 설정 파일 위치(`application.yml`, `.env`) 식별
- PHP 등 미지원 언어이면 Phase 2 skip 후 기록

**Phase 2**: 데이터 보호 정적 분석.

```bash
python3 shared/scripts/scan_data_protection.py <src> \
    -o state/<prefix>/data.json
```

> **API 인벤토리 불필요**: 설정 파일, 소스코드, `.env` 파일 등을 직접 탐색하므로
> `scan_api.py` 선행 실행 없이 단독 실행 가능합니다.
> (선택적으로 `--api-inventory`를 지정하면 DTO 노출 진단의 엔드포인트 역추적이 강화됩니다.)

진단 항목:
- **CORS**: `Access-Control-Allow-Origin: *`, 동적 Origin 반영 여부
- **Secrets**: 하드코딩된 API 키/비밀번호/토큰 (Gitleaks 연계, `secret_scanning.md` 참조)
- **JWT**: 알고리즘 검증 누락, 약한 시크릿, `none` 알고리즘 허용
- **Cryptography**: 약한 알고리즘(MD5/SHA1/DES/ECB), 고정 IV/Salt
- **PII Logging**: `logger.*` / `console.log`에 개인식별정보 포함 여부

출력: `state/<prefix>/data.json`

LLM 검토 절차는 `references/task_prompts/task_25_data_protection.md` 전체 절차 준수.

**Phase 3**: 교차검증 + LLM 수동 심층진단.
- **Phase 3-1** (자동판정 "취약" 건): `shared/references/cross_verification.md` Phase 3-1 절차
  - CORS 정책 실제 적용 범위 확인, JWT 라이브러리 설정값 검증
  - FP는 `diagnosis_method: "교차검증(수동)"` 으로 재분류
- **Phase 3-2** ("정보/수동검토" 건): `shared/references/cross_verification.md` Phase 3-2 + `manual_review_prompt.md`
  - 대상: `result: "정보"` + `needs_review: true`, `taint_confirmed: null`
  - 출력: `diagnosis_method: "수동진단(LLM)"` + `manual_review_note`

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.

### Step 4: Summary 출력

Phase 3 완료 후 `state/<prefix>/summary_data.md` 를 생성한다.

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

| ID | 제목 | 심각도 | 카테고리 | 파일:라인 | 판정 | 진단방법 |
|---|---|---|---|---|---|---|
| DATA-001 | CORS — 동적 Origin 반영 | High | CORS | src/.../WebConfig.java:30 | 취약 | 자동스캔(SAST) |

> 양호 항목은 목록에서 제외. 취약·정보만 기재.

## 소스 파일
- `state/<prefix>/data.json`
```

**작성 규칙**:
- Finding 목록은 심각도 내림차순 (Critical → High → Medium → Low → Info)
- 카테고리는 CORS / Secrets / JWT / Cryptography / PII Logging 으로 구분
- `evidence.file` + `evidence.lines` 에서 파일:라인 추출
- 양호는 통계에만 포함, 목록에는 미기재

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
- `tooling.md`, `seed_usage.md`, `poc_policy.md`
- `large_repo_multi_module.md`, `unsupported_lang_targets.md`
- `rules/semgrep/config-hardcoded-secrets.yaml`
- `rules/semgrep/properties-hardcoded-secrets.yaml`
- `rules/semgrep/ssl-client-bypass.yaml`
- `rules/semgrep/redis-template-default-serializer.yaml`
- `rules/semgrep/grpc-plaintext-channel.yaml`
- `rules/joern/pcona-console-taint.sc`
