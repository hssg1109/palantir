---
name: sec-scan-sca
description: Modularized SAST skill for Software Composition Analysis (SCA) — open source library vulnerability detection, CVE lookup, and relevance verification for Gradle/npm projects. Runs scan_sca_gradle_tree.py then LLM CVE relevance review. Use when asked to run SCA scan, 오픈소스 취약점 진단, or 의존성/CVE 분석 on a target in testbed/. Part of the broader sec-audit-static pipeline; future updates will include Jira integration.
tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
---

# Sec Scan SCA

## Overview
이 skill은 `sec-audit-static` 전체 파이프라인에서 **SCA(Software Composition Analysis) — 오픈소스 라이브러리 취약점(CVE)** 진단만을 담당하는 모듈입니다.
Gradle / npm 프로젝트를 모두 지원하며, CVE 탐지 후 LLM이 소스코드와 교차검증하여 관련성을 판정합니다.

독립 실행 가능: `sec-scan-sca/` + `shared/scripts/scan_sca_gradle_tree.py`

향후 Jira 연동 기능이 추가될 예정입니다.

## Workflow

### Step 1: Load references

**로컬 (이 skill 전용)**
- `shared/references/task_prompts/task_11_asset_identification.md` - 자산 식별 절차 (빌드 시스템 판별 포함)
- `references/task_prompts/task_sca.md` - SCA 진단 절차 (의존성 추출 → CVE 조회 → 관련성 검증 → 보고서)
- `references/task_prompts/task_sca_llm_review.md` - Phase 3-SCA LLM 관련성 검토 (4단계: grep/발생조건/판정/한국어설명)

**공유 (shared/)**
- `shared/references/workflow.md` - Phase/Task 실행 맵, 보안 정책
- `shared/references/output_schemas.md` - JSON 출력 스키마
- `shared/references/severity_criteria.md` - 위험도 매핑
- `shared/references/finding_writing_guide.md` - finding 품질 기준 (code_snippet 필수, 한국어 설명)
- `shared/references/tooling.md` - 코드 브라우저 도구 (rg/ctags)
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

**Phase 1**: 자산 식별 (빌드 시스템 판별 목적).
- `shared/references/task_prompts/task_11_asset_identification.md` 절차 실행
- 빌드 시스템 판별: `build.gradle` / `build.gradle.kts` (Gradle) vs `package-lock.json` / `yarn.lock` (npm)
- 멀티 모듈인 경우 루트 `build.gradle` 위치 및 서브모듈 목록 확인

**Phase 2**: SCA 의존성 스캔.

`references/task_prompts/task_sca.md` 전체 절차 준수.

```bash
# Gradle / npm 모두 동일한 스크립트로 자동 감지
python3 shared/scripts/scan_sca_gradle_tree.py <src> \
    --project <name> \
    -o state/<prefix>/sca.json
```

- Gradle: `gradle dependencies` 트리 파싱 → 의존성 목록 추출 → CVE 조회
- npm: `package-lock.json` 파싱 → 의존성 목록 추출 → CVE 조회
- 출력: `state/<prefix>/sca.json`

**Phase 3-SCA**: LLM CVE 관련성 검토.

`references/task_prompts/task_sca_llm_review.md` 전체 절차 준수.

각 CVE finding에 대해 4단계 검토:
1. 소스코드 실사용 grep (라이브러리 API 호출 확인)
2. 발생 조건 코드 확인 (취약한 파라미터/설정 경로)
3. 관련성 판정 (관련/무관/검토필요)
4. 한국어 CVE 설명 작성

출력: `state/<prefix>/sca_llm.json`

### Step 3: Output validation
- 모든 task 출력에 `metadata.source_repo_url`, `metadata.source_repo_path`, `metadata.source_modules` 포함 필수.
- JSON을 `shared/references/output_schemas.md` 스키마로 검증.

### Step 4: Summary 출력

Phase 3-SCA 완료 후 `state/<prefix>/summary_sca.md` 를 생성한다.

**읽을 파일**:
- `state/<prefix>/sca.json` — 스크립트 CVE 탐지 결과
- `state/<prefix>/sca_llm.json` — LLM 관련성 검토 결과

**출력 형식**:

```markdown
# SCA 취약점 진단 결과 요약 — <repo명>

진단일: YYYY-MM-DD | 대상: <source_repo_url> | LLM 관련성 검토: 완료

## 결과 통계

| 판정 | 건수 |
|---|---|
| 관련 (실제 영향) | N |
| 검토필요 | N |
| 무관 (FP) | N |
| **탐지된 CVE 전체** | **N** |

라이브러리 전체: N개 / 취약 버전 포함: N개

## Finding 목록 (관련·검토필요만)

| CVE ID | 라이브러리 | 버전 | CVSS | 관련성 | 한줄 설명 |
|---|---|---|---|---|---|
| CVE-2021-44228 | log4j-core | 2.14.1 | 10.0 | 관련 | RCE — JNDI lookup 호출 확인됨 |

> 무관(FP) 판정 항목은 목록에서 제외.

## 소스 파일
- `state/<prefix>/sca.json`
- `state/<prefix>/sca_llm.json`
```

**작성 규칙**:
- Finding 목록은 CVSS 점수 내림차순
- `sca_llm.json`의 관련성 판정(관련/검토필요/무관)을 우선 적용; 없으면 `sca.json`의 탐지 결과 사용
- 한줄 설명은 `sca_llm.json`의 한국어 CVE 설명에서 첫 문장 추출
- 무관(FP)은 통계에만 포함, 목록에는 미기재

## Resources

### 로컬 (이 skill 폴더 내)
- `shared/references/task_prompts/task_11_asset_identification.md`
- `references/task_prompts/task_sca.md`
- `references/task_prompts/task_sca_llm_review.md`

### 공유 (shared/references/)
#### Workflow & Policy
- `workflow.md`, `output_schemas.md`, `severity_criteria.md`

#### Tooling
- `tooling.md`, `large_repo_multi_module.md`, `unsupported_lang_targets.md`
