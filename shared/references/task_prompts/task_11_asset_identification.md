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

PHP 파일이 주 언어인 경우:
→ `skills/sec-audit-static/references/unsupported_lang_targets.md` 확인
→ Auto-Scan Phase skip, 해당 없음으로 기록

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
