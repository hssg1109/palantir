## Task: 1-1 자산 식별 (Asset Identification)

**역할**: 당신은 보안 진단 전문가입니다.
**입력**: 로컬 소스코드 (`testbed/<project>/`)
**출력 파일**: `state/<prefix>/task11.json`

---

### 컨텍스트
보안 진단의 첫 단계로, **소스코드만을 기반으로** 진단 대상 자산을 식별합니다.
이 결과는 이후 Auto-Scan Phase 스캔 방식(스크립트 선택, 모듈 분리, 미지원 언어 판정)을 결정합니다.

---

### Step 1: 소스코드 분석

#### 1-1. 프로젝트 구조 파악

```bash
# 최상위 디렉토리 구조 확인
ls testbed/<project>/

# 빌드 파일 위치 확인
find testbed/<project>/ -maxdepth 3 \
  -name "build.gradle" -o -name "build.gradle.kts" \
  -o -name "pom.xml" \
  -o -name "package.json" \
  -o -name "package-lock.json" \
  -o -name "yarn.lock" \
  | sort
```

#### 1-2. Frontend / Backend 판별

| 조건 | 판정 |
|---|---|
| `package.json` 존재 + `.java` / `.kt` 파일 0건 | **프론트엔드 repo** |
| `build.gradle` / `pom.xml` 존재 + `.java` / `.kt` 파일 1건 이상 | **백엔드 repo** |
| 두 조건 동시 충족 | **풀스택 — 모듈 분리 필요** |

```bash
# Java/Kotlin 파일 수 확인
find testbed/<project>/ -name "*.java" -o -name "*.kt" | wc -l

# 주요 소스 언어 확인
find testbed/<project>/ \( -name "*.java" -o -name "*.kt" -o -name "*.ts" -o -name "*.tsx" -o -name "*.php" \) \
  | sed 's/.*\.//' | sort | uniq -c | sort -rn
```

#### 1-3. 기술 스택 확인

빌드 파일에서 프레임워크 및 의존성을 확인합니다:

```bash
# Spring Boot 버전 확인 (Gradle)
grep -A2 "org.springframework.boot" testbed/<project>/build.gradle 2>/dev/null | head -5

# 주요 의존성 확인
grep -E "(implementation|compile|runtimeOnly|api)\s+['\"]" testbed/<project>/build.gradle 2>/dev/null | head -20

# 설정 파일에서 DB 연결 정보 확인 (값 아닌 키만)
grep -E "^(spring\.datasource|spring\.jpa|mybatis)" testbed/<project>/src/main/resources/application.yml 2>/dev/null
```

확인 항목:
- 프레임워크: Spring Boot / Spring MVC / Spring WebFlux / React / Vue / Next.js 등
- ORM/DB: MyBatis / JPA(Hibernate) / JDBC / R2DBC / Kotlin Exposed 등
- 언어: Java / Kotlin / TypeScript / JavaScript / PHP
- 빌드 도구: Gradle / Maven / npm / yarn

#### 1-4. 멀티 모듈 여부 확인

```bash
# Gradle 멀티 모듈 확인
cat testbed/<project>/settings.gradle 2>/dev/null | grep "include"

# 서브 모듈 목록
find testbed/<project>/ -maxdepth 2 -name "build.gradle" | grep -v "^testbed/<project>/build.gradle"
```

멀티 모듈이고 endpoints > 1,000 또는 Fortify build_target ≥ 2인 경우:
→ `skills/sec-audit-static/references/large_repo_multi_module.md` 절차에 따라 `--modules` 분리 스캔 적용

#### 1-5. PHP / 미지원 언어 판정

PHP 파일이 주 언어인 경우 (단, `/sec-scan-php` 실행 시에는 이 분기 대신
`sec-scan-php/references/task_prompts/task_php_asset_identification.md` 절차를 따른다):

**1) idempotency 체크** — `/sec-scan-php`가 이미 이 레포에 대해 실행되었는지 먼저 확인한다:

```bash
ls state/<repo>/php/*/findings_php.json 2>/dev/null | sort | tail -1
```

- 파일이 존재하고 그 안의 finding 중 하나 이상이 `llm_checked: true`이면
  → 이미 `/sec-scan-php`로 진단 완료된 것으로 간주, **재실행하지 않는다** (아래 3번으로).
- 파일이 없으면 → 아래 2번 실행.

**2) 미실행 상태면 `/sec-scan-php`를 인라인으로 위임 실행** (자율 완주, 확인 질문 없이):

`sec-scan-php/SKILL.md` 전체를 읽고, 그 안의 Step 1(참조 로드) → Phase 1
(`task_php_asset_identification.md`) → Auto-Scan(`task_php_baseline.md`,
`scan_php_baseline.py`) → LLM-Check(`task_php_llm_review.md`) → Step 3/4를 현재
세션에서 그대로 따라 자율 완주한다. `testbed/<repo>`는 현재 실행 중인 skill이 이미
그 레포를 대상으로 시작했으므로 재-clone하지 않는다. 완료 후
`state/<repo>/php/<RUN_ID>/findings_php.json`이 생성된다.

**3) 현재 skill의 Phase 1 출력** — 위임 실행 여부와 무관하게 기존과 동일하게
`unsupported_lang: true`로 기록하고, 이 skill 자신의 Auto-Scan/LLM-Check는 그대로
skip한다. `findings[].note`(또는 자유 필드)에 아래처럼 위임 상태를 남긴다:

- 방금 위임 실행함 → `"PHP — /sec-scan-php로 위임 실행 완료 (state/<repo>/php/<RUN_ID>/findings_php.json)"`
- 이미 실행되어 있었음 → `"PHP — /sec-scan-php로 이미 진단 완료, 이 skill 해당없음"`

**4) 다중 레포 처리** — `$ARGUMENTS`에 레포가 여러 개면 이 판단은 레포 단위로 독립
적용한다 (한 레포가 PHP라고 다른 레포까지 이 분기를 타지 않는다).

#### 1-6. Python 판정

`manage.py`, `requirements.txt`, `Pipfile`, `pyproject.toml` 존재 또는 `.py` 파일이
주 언어인 경우:

```bash
find testbed/<project>/ -maxdepth 3 -iname "manage.py" -o -iname "requirements*.txt" \
  -o -iname "Pipfile" -o -iname "pyproject.toml"
find testbed/<project>/ -name "*.py" | wc -l
```

Python은 PHP와 달리 **전담 위임 skill이 없다** — `scan_python_baseline.py` 같은
후보 태깅 스크립트 자체가 존재하지 않으므로 `/sec-scan-php`식 인라인 전체 위임을
수행하지 않는다. 대신:

**1) 이 skill의 Phase 1 출력**: `unsupported_lang: true`로 기록하고, 이 skill 자신의
Auto-Scan Phase는 skip한다 (LLM-Check는 아래 2번 방식으로 대체 수행).

**2) 이 skill이 담당하는 카테고리만 직접 수동 진단**: `shared/references/
python_diagnosis_criteria.md`를 읽고, 그 문서의 §2(기존 5개 카테고리 매핑) 중 **현재
실행 중인 skill에 해당하는 절만** 적용해 API 리스팅(§1)부터 진단까지 LLM이 직접
수행한다 — 예: `/sec-scan-injection` 실행 중이면 §2-1(Injection) 행만, `/sec-scan-xss`면
§2-2(XSS)만. 다른 카테고리는 손대지 않는다 (각 skill이 독립적으로 자기 몫만 진단 —
PHP처럼 한 skill이 4개 도메인을 전부 대신하지 않는다).

**3) §3 신규 발견 항목(설정 하이진/CORS/JWT/역직렬화/SSTI/하드코딩 인증우회) 귀속**:
`python_diagnosis_criteria.md` §5 실행 모델에 따라 `/sec-scan-data`가 1차 담당이다.
단, 다른 도메인 skill이 먼저 실행되며 해당 패턴을 발견하면 findings에 포함하고
`note`에 "§3 신규 발견 — 타 skill 중복 확인 불필요"를 남겨 후속 skill의 중복 진단을
막는다.

**4) findings 저장**: 기존 skill과 동일한 `findings_<SKILL>.json` 스키마를 그대로
사용한다 — Python이라고 별도 파일 포맷을 쓰지 않는다. `findings[].note`에 아래 템플릿을
남긴다:

- `"Python — python_diagnosis_criteria.md §2-<N> 기준 LLM 수동 진단 완료 (Auto-Scan 미지원)"`

**5) 다중 레포 처리**: 1-5와 동일하게 레포 단위로 독립 적용한다.

---

### Step 2: Git 메타데이터 수집

보고서 서비스 개요 표에 기재할 정보를 수집합니다.

```bash
# Branch / Commit 정보
git -C testbed/<project>/ log -1 --format="%H %an %ae %ad %s" --date=short

# 원격 저장소 URL
git -C testbed/<project>/ remote get-url origin 2>/dev/null || echo "remote not set"

# 최근 기여자 목록 (shallow clone이면 1명만 나올 수 있음)
git -C testbed/<project>/ log --format="%an %ae" -20 | sort | uniq -c | sort -rn | head -5
```

---

### Step 3: 출력

```json
{
  "task_id": "1-1",
  "status": "completed",
  "findings": [
    {
      "asset_type": "Web Application (Backend)",
      "repo_type": "backend",
      "tech_stack": ["Spring Boot 3.x", "Kotlin", "MyBatis", "PostgreSQL"],
      "framework": "Spring Boot",
      "build_tool": "Gradle",
      "language": "Kotlin",
      "multi_module": false,
      "modules": [],
      "unsupported_lang": false,
      "source_code_path": "testbed/<project>/"
    }
  ],
  "metadata": {
    "source_repo_url": "http://code.example.com/projects/PROJ/repos/repo-name",
    "branch": "master",
    "commit": "5ca54f5",
    "commit_date": "2026-03-18",
    "commit_message": "TICKET-001 - 최종 커밋 메시지",
    "responsible_person": "미확인 (최종 커밋: 홍길동)"
  },
  "executed_at": "",
  "claude_session": ""
}
```

**`repo_type` 값**: `backend` / `frontend` / `fullstack`
**`unsupported_lang: true`** 이면 Auto-Scan Phase skip 후 진단 결과에 기록

---

### 금지사항
- Excel 파일, 고객 제공 문서 없이도 실행 가능해야 함 (소스코드만 사용)
- 추측으로 자산 추가 금지 (소스코드에서 확인된 것만)
- 민감정보(API 키, 시크릿, 비밀번호) 포함 금지
