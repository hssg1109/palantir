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

### ⚠️ 사전 필수 — 소스코드 Clone

> testbed/ 에 소스코드가 없으면 진단을 시작할 수 없다.
> **WSL에서 직접 아래 명령을 실행한다.** clone_repo.py가 자동으로 PowerShell(Windows git)을 경유하여 Bitbucket에 접근한다.

```bash
# WSL(Ubuntu) 터미널에서 실행
python3 tools/new_scan.py <repo> --skill sca --clone <PROJECT> <REPO>
# 예: python3 tools/new_scan.py ocb-community-api --skill sca --clone OCBWEBVIEW ocb-community-api
```

실행 결과로 출력되는 `state/<repo>/sca/<YYYYMMDD_HHMM>/` 경로를 skill 실행 시 입력할 것.

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
- 빌드 시스템 판별 우선순위:
  1. `build.gradle` / `build.gradle.kts` / `gradlew` 존재 → **Gradle** (pom.xml 공존 무시)
  2. `package-lock.json` / `yarn.lock` 존재 → **npm**
  3. `pom.xml` 단독 존재 (Gradle 파일 없음) → **Maven**
  > **⚠️ pom.xml + build.gradle 공존 시 반드시 Gradle 우선**: Spring Boot 등 Gradle 프로젝트가 Maven Central 배포용으로 pom.xml을 함께 갖는 경우가 있음. pom.xml만 파싱하면 직접 의존성 32건만 추출되고 전이적 의존성 180+건이 누락된다.
- 멀티 모듈인 경우 루트 `build.gradle` 위치 및 서브모듈 목록 확인

**Auto-Scan Phase — SCA 의존성 스캔 (Python 스크립트)**

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

**LLM-Check Phase (SCA)**: LLM CVE 관련성 검토.

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

---

### Step 4-2: SCA Tier 분류 기준 — findings_SCA.json 생성 시 적용

> **⚠️ 유일한 승인된 예외**: 아래 Tier 분류는 이 skill(LLM-Check) 단계에서 `review_status`를 직접 설정하는
> **SCA 전용의 유일한 예외**다 (`~/.claude/.../memory/feedback_sca_review_policy.md` 참조).
> `/sec-review`는 `state/<repo>/sca/` 디렉터리를 애초에 수집 대상에서 제외하므로(§1 참조) SCA findings는
> `/sec-review`의 사람 판정을 거치지 않는다 — 대신 `approve_report.py`/`generate_final_report.py`의
> `--include-sca` 플래그를 **사람이 명시적으로 지정**하는 것이 SCA에 한정된 유효한 승인 게이트다
> (미지정 시 기본적으로 보고서에서 제외됨 — `feedback_sca_default_exclude.md`).
> 이 예외 패턴을 다른 skill(injection/xss/file/data)에 복제하지 말 것 — 그 4개 skill은
> `reviewed`/`review_status`를 직접 설정하지 않고 반드시 `/sec-review`를 거쳐야 한다(각 skill SKILL.md Step 4-2 HARD RULE 참조).

LLM-Check의 `relevance_status`와 CVSS를 조합하여 **3-Tier**로 분류한다.  
이 기준은 `--include-sca` 지정 시 보고서 포함 여부에 직접 영향을 미친다.

| Tier | 조건 | result | 처리 |
|------|------|--------|------|
| **Tier 1 — 취약** | `relevance_status = "적용"` | `취약` | 보고서 취약 포함, 즉시 패치 필요 |
| **Tier 2 — 정보** | `relevance_status = "제한적"` + CVSS ≥ 9.0 (Critical) | `정보` | 보고서 정보 포함, 공격 조건 추가 필요 명시 |
| **Tier 3 — BOM 통합** | `relevance_status = "제한적"` + CVSS < 9.0 | `정보` (개별) → BOM finding 통합 | 개별 finding 오탐 처리 + BOM 통합 finding 1건 생성 |
| **제외** | `relevance_status = "조건미충족"` 또는 `"확인불가"` | `양호(FP)` | 보고서 제외 |

#### BOM 통합 Finding 생성 규칙

Tier 3 대상 finding이 1건 이상이면 **`SCA-BOM-001`** finding을 자동 생성한다.

**BOM 통합 finding 구조:**
```json
{
  "finding_id": "SCA-BOM-001",
  "title": "오픈소스 BOM 업그레이드 권고 — <N>개 라이브러리 간접 취약 ({BOM} 업그레이드로 일괄 해결)",
  "severity": "<Tier3 건 중 최고 severity>",
  "category": "SCA/CVE",
  "result": "정보",
  "review_status": "정탐",
  "review_result": "정보",
  "bom_type": "spring-boot|npm|gradle-bom",
  "bom_target_version": "<auditor 확정 BOM 버전>",
  "bom_members": [
    {"finding_id": "SCA-008", "package": "mysql:mysql-connector-java", "version": "8.0.30", "cvss": 8.3}
  ]
}
```

**BOM 통합 finding의 권고 버전 결정 절차 (BLOCKING INPUT):**

BOM 통합 finding 생성 전 반드시 아래 입력을 받는다:

```
=== BOM 통합 권고 버전 확인 ===
아래 {N}개 라이브러리가 BOM 업그레이드로 일괄 해결 가능합니다.

라이브러리 목록:
  [1] mysql:mysql-connector-java 8.0.30  (스캐너 rv: 미확인)
  [2] org.hibernate:hibernate-core 5.6.9.Final  (스캐너 rv: 미확인)
  ...
  
⚠️ 주의사항: Spring Boot major 버전 업그레이드는 Java 버전/namespace 변경이 수반될 수 있습니다.
  현재 BOM: Spring Boot 2.6.9 / Java 8
  Spring Boot 3.x: Java 17 필수, javax → jakarta namespace 변경 필요
  Spring Boot 2.7.x 최신 패치: 일부 CVE만 해결 가능

BOM 권고 버전을 입력하세요:
  형식: "spring-boot 3.3.13" 또는 "spring-boot 2.7.x 최신" 또는 직접 입력
  [BOM 권고 버전 입력]:
```

**BOM 권고 버전 확인 방법 (auditor 참조):**

Spring Boot BOM POM 파일에서 라이브러리별 관리 버전 직접 확인:
```
https://repo.maven.apache.org/maven2/org/springframework/boot/
  spring-boot-dependencies/{버전}/spring-boot-dependencies-{버전}.pom
→ <properties> 섹션에서 각 라이브러리 관리 버전 확인
```

**BOM 적용 가능 여부 사전 판단 (BLOCKING INPUT 전 필수):**

BOM 통합 finding 생성 전 아래 기준으로 먼저 판단한다:

| 조건 | 처리 |
|------|------|
| 권고 BOM이 현재와 **같은 major** (예: Spring Boot 2.6→2.7) | BOM 통합 finding 생성 + BOM 버전 BLOCKING INPUT 진행 |
| 권고 BOM이 **major 업그레이드** + Java 버전 제약 존재 | BOM finding 미생성 → "장기 마이그레이션 계획 권고" 정보 finding 1건으로 대체 |
| npm BOM (package.json) | package-lock.json 최신 버전 기준 직접 확인 |

**BOM 버전 입력 처리:**
- `spring-boot X.Y.Z` 형식 → BOM finding title에 명시, recommendation에 마이그레이션 주의사항 자동 포함
- 입력 버전이 현재보다 major 버전이 높은 경우 → "major 업그레이드 필요, Java/namespace 확인 필수" 자동 추가
- BOM에 포함되지 않는 라이브러리(예: mysql-connector-java → Spring Boot 3.x부터 패키지명 변경)는 별도 조치 명시

**정합성 검증 체크리스트:**
```
□ Tier 3 개별 finding: review_status="오탐", result="양호(BOM통합)" 으로 변경
□ SCA-BOM-001: bom_members에 모든 Tier3 finding_id 포함 여부 확인
□ Tier1 + Tier2 + BOM통합 1건 + 제외 = 전체 finding 수 일치 확인
□ bom_target_version이 rv_auditor_confirmed와 동일 기준으로 저장됨
□ 보고서 생성 시 BOM finding이 SCA 섹션 마지막에 위치
```

---

### Step 4-1: LLM-Check 완료 확인 — sec-review 전 필수 게이트

> **HARD RULE**: `sca_llm.json` 미존재 상태로 sec-review 진행 금지.
> CVE 관련성 검토(LLM-Check) 없이는 FP CVE가 그대로 리뷰 대상에 포함된다.
> `findings_SCA.json` 생성 시 반드시 `llm_checked: true` 설정.

확인 스크립트:
```bash
python3 -c "
import pathlib, sys
prefix = 'state/<prefix>'
has_llm = pathlib.Path(f'{prefix}/sca_llm.json').exists()
findings = pathlib.Path(f'{prefix}/findings_SCA.json')
if not has_llm:
    print('[BLOCK] sca_llm.json 없음 — LLM CVE 관련성 검토 먼저 수행', file=sys.stderr); sys.exit(1)
if findings.exists():
    import json
    d = json.loads(findings.read_text())
    if not d.get('llm_checked', False):
        print('[BLOCK] findings_SCA.json llm_checked=false', file=sys.stderr); sys.exit(1)
print('[OK] LLM-Check 완료 확인')
"
```

통과 조건 충족 후 Phase C-1을 수행한다.

---

### Step C: Phase C-1 — LLM 데이터 접근 로그 업데이트

> **정책**: `shared/references/llm_data_cleansing_policy.md` | **절차**: `shared/references/phase_c_cleansing.md`

LLM-Check 완료 직후 수행. SCA는 통상 마지막 skill이므로, testbed 삭제는 `/sec-review` Phase C-2에서 수행.

**수행**:

1. 이 세션에서 `testbed/<repo>/` 경로를 Read 도구로 접근한 파일 목록 정리 (Phase 1 / Phase 3 구분)  
   SCA는 LLM-Check에서 `build.gradle`, `settings.gradle`, `dep_tree.log` 등을 주로 접근함
2. `state/<repo>/llm_data_access_log.json` 생성(없으면) 또는 `skills[]` 배열에 sca 항목 append:
   ```json
   {
     "skill": "sca",
     "scan_dir": "state/<repo>/sca/<YYYYMMDD_HHMM>",
     "scanned_at": "<진단 시작 ISO8601 +09:00>",
     "llm_accessed_files": [
       { "phase": "Phase 1 - Asset Identification", "purpose": "자산 식별", "files": ["testbed/<repo>/build.gradle", "..."] },
       { "phase": "Phase 3 - LLM-Check (SCA)", "purpose": "CVE 관련성 검토 (grep/코드 확인)", "files": ["testbed/<repo>/build.gradle", "..."] }
     ]
   }
   ```
3. 신규 생성 시 `project`는 `state/<repo>/20*/scan_meta.json`의 `bb_project` 값 사용 (없으면 `"?"`)
4. `cleansing_completed: false` 유지

**완료 출력**:
```
[Phase C-1] llm_data_access_log.json 업데이트 완료
  skill  : sca
  접근파일: N건 (Phase 1: N / Phase 3: N)
  로그   : state/<repo>/llm_data_access_log.json
  [다음] /sec-review 완료 시 testbed 삭제 + Confluence 레지스트리 등록 수행
```

Phase C-1 완료 후 `/sec-review` 로 인터랙티브 정/오탐 판정을 진행한다.

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
