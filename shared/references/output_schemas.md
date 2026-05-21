# Output Schemas

모든 태스크 결과는 아래 스키마를 준수해야 합니다.

## Task Output Schema (task_output_schema.json)

일반 태스크 결과용 (task_11, task_21).

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Task Output Schema",
  "type": "object",
  "required": ["task_id", "status", "findings"],
  "properties": {
    "task_id": { "type": "string", "enum": ["injection", "xss", "file", "data", "sca", "frontend", "asset"] },
    "status": { "type": "string", "enum": ["completed", "failed", "partial"] },
    "findings": { "type": "array", "items": { "type": "object" } },
    "executed_at": { "type": "string", "format": "date-time" },
    "claude_session": { "type": "string" },
    "notes": { "type": "string" },
    "errors": { "type": "array" },
    "metadata": { "type": "object" }
  },
  "additionalProperties": false
}
```

## Finding Schema (finding_schema.json)

취약점 발견 결과용 (task_22, task_23, task_24, task_25).

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Security Finding Schema",
  "type": "object",
  "required": ["task_id", "status", "findings"],
  "properties": {
    "task_id": { "type": "string", "enum": ["injection", "xss", "file", "data", "sca", "frontend", "asset"] },
    "status": { "type": "string", "enum": ["completed", "failed", "partial"] },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "title", "severity", "category", "description"],
        "properties": {
          "id": { "type": "string", "description": "취약점 고유 ID (예: VULN-001)" },
          "title": { "type": "string" },
          "severity": { "type": "string", "enum": ["Critical", "High", "Medium", "Low", "Informational"] },
          "category": { "type": "string", "description": "예: SQL Injection, XSS, File Upload" },
          "description": { "type": "string" },
          "affected_endpoint": { "type": "string" },
          "affected_file": { "type": "string" },
          "evidence": { "type": ["string", "object"] },
          "recommendation": { "type": "string" },
          "cwe_id": { "type": "string", "pattern": "^CWE-[0-9]+$" },
          "owasp_category": { "type": "string" }
        }
      }
    },
    "summary": {
      "type": "object",
      "properties": {
        "total": { "type": "integer" },
        "critical": { "type": "integer" },
        "high": { "type": "integer" },
        "medium": { "type": "integer" },
        "low": { "type": "integer" },
        "info": { "type": "integer" }
      }
    },
    "executed_at": { "type": "string", "format": "date-time" },
    "claude_session": { "type": "string" },
    "notes": { "type": "string" },
    "metadata": { "type": "object" }
  },
  "additionalProperties": false
}
```

## task22_llm.json Schema (LLM 수동분석 — SQL Injection)

`sqli_endpoint_review` 블록 구조. `publish_confluence.py` 렌더러 및 `generate_finding_report.py`가 이 구조를 파싱한다.

```json
{
  "task_id": "injection",
  "status": "completed",
  "sqli_endpoint_review": {
    "total_endpoints": 221,
    "total_info_endpoints": 64,
    "overall_sqli_judgment": "양호",
    "group_judgments": [
      {
        "group": "자동 판정 불가 → 양호 (62건)",
        "root_cause": "스캐너 추적 실패 원인 (필수)",
        "judgment": "양호 | 정보 | 취약 | 해당없음(DB접근없음)",
        "llm_resolution_method": "LLM이 코드를 어떻게 검토하고 판정했는지 (필수, 빈 문자열 금지)",
        "endpoints_reviewed": ["실제 분석한 endpoint 목록 (빈 배열 [] 금지)"],
        "services_reviewed": [],
        "daos_reviewed": []
      }
    ],
    "endpoint_verdicts": []
  },
  "findings": [],
  "endpoint_summary": {
    "total": 221,
    "취약": 0,
    "정보": 0,
    "양호": 221,
    "scanner_fp_corrected": 4,
    "llm_info_to_safe": 64
  },
  "executed_at": "2026-04-07T10:00:00+09:00"
}
```

### group_judgments 필수 규칙

| 필드 | 필수 | 설명 |
|---|---|---|
| `group` | ✅ | **injection.json의 `diagnosis_type` 값을 부분문자열로 포함해야 함** (generate_finding_report.py 매칭 조건) |
| `root_cause` | ✅ | 스캐너 추적 실패 근본 원인 |
| `judgment` | ✅ | 양호 / 정보 / 취약 / 해당없음(DB접근없음) |
| `llm_resolution_method` | ✅ | LLM 검토 방법 및 근거 (빈 문자열 금지) |
| `endpoints_reviewed` | ✅ | 실제 분석한 endpoint 목록 (빈 배열 [] 금지) |

**매칭 가능한 `group` 명칭 예시** (diagnosis_type 값 포함 필수):
- `"자동 판정 불가 → 양호 (62건)"` ← "자동 판정 불가" 포함 ✅
- `"DB 접근 미확인 → 양호 (1건)"` ← "DB 접근 미확인" 포함 ✅
- `"추적 불가 → 양호 (1건)"` ← "추적 불가" 포함 ✅
- `"XML 미발견 패턴 추정 → 양호 (1건)"` ← "XML 미발견 패턴 추정" 포함 ✅
- `"정보→양호 LLM 재검토 (2건)"` ← diagnosis_type 미포함 ❌

## task23_llm.json Schema (LLM 수동분석 — XSS)

`xss_endpoint_review` 블록 구조. `endpoint_summary`는 `xss_endpoint_review` **내부**에 위치해야 한다.

```json
{
  "task_id": "xss",
  "status": "completed",
  "xss_endpoint_review": {
    "total_endpoints": 221,
    "endpoint_summary": {
      "total": 221,
      "취약": 0,
      "정보": 110,
      "양호": 111,
      "scanner_fp_corrected": 108
    },
    "group_judgments": [
      {
        "group": "그룹명",
        "root_cause": "스캐너 추적 실패 원인 (필수)",
        "judgment": "양호 | 정보 | 취약",
        "llm_resolution_method": "LLM 검토 방법 (필수)",
        "reason": "판정 이유",
        "endpoints_reviewed": [],
        "controllers_reviewed": []
      }
    ]
  },
  "findings": [],
  "executed_at": "..."
}
```

## Enhanced Injection Output (scan_injection_enhanced.py)

endpoint별 진단 결과 확장 포맷. `endpoint_diagnoses` 키로 자동 식별.

필수 필드: `task_id`, `status`, `scan_metadata`, `endpoint_diagnoses`, `global_findings`, `summary`

---

## findings_\<skill\>.json — 정규화 Finding 스키마

> **목적**: 각 skill의 진단 결과를 취약점 1건 = JSON 객체 1개 형태로 정규화.
> Auto-Scan 원본(`injection.json` 등)과 LLM-Check 원본(`task22_llm.json` 등)은 그대로 보존(증적).
>
> **생성 시점**: LLM-Check Phase 완료 후 LLM이 직접 작성.
> Auto-Scan Phase만 완료된 경우 스크립트가 `auto_findings[]`를 기반으로 임시 생성 가능(LLM 미검토 표시).
>
> **파일명 규칙**: `findings_{task_id}.json` (예: `findings_injection.json`)

### 최상위 구조

```json
{
  "task_id": "injection",
  "prefix": "pcona",
  "generated_at": "2026-04-14T10:00:00+09:00",
  "llm_checked": true,

  "scan_coverage": {
    "total_scanned": 221,
    "result_breakdown": { "취약": 3, "정보": 12, "양호": 206 },
    "fn_disclaimer": "양호 판정 항목은 정적 분석 기반으로 런타임 F/N 가능성 존재. 증적은 injection.json 참조.",
    "source_files": ["injection.json", "task22_llm.json"]
  },

  "summary": {
    "total_findings": 5,
    "by_severity":  { "Critical": 2, "High": 1, "Medium": 2, "Low": 0, "Informational": 0 },
    "by_result":    { "취약": 3, "정보": 2 },
    "by_source":    { "auto-scan": 2, "llm-check": 3 },
    "fp_corrected": 1,
    "fn_detected":  0
  },

  "findings": [ ],

  "evidence_trail": [ ]
}
```

### findings[] — Finding 객체 스키마

취약·정보 판정 항목만 포함. 양호는 포함하지 않는다.

```json
{
  "finding_id": "INJ-001",
  "title": "SQL Injection — MyBatis ${} 동적 바인딩",
  "severity": "Critical",
  "risk_level": 5,
  "category": "SQL Injection",
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021 Injection",

  "result": "취약",
  "diagnosis_method": "교차검증(수동)",
  "source": "llm-check",
  "fn_detected": false,
  "fp_corrected": false,

  "llm_verdict": "TP",
  "llm_reviewed_at": "2026-04-29T10:00:00+09:00",
  "manual_review_note": "판정 근거 요약 — 코드 경로, FP 이유, 또는 수동 확인 내용",

  "scope": {
    "type": "endpoint",
    "endpoint": "GET /api/search",
    "handler": "SearchController.search()",
    "affected_file": "src/main/java/.../SearchRepository.java",
    "affected_line": 120
  },

  "description": "외부 입력 파라미터 keyword가 MyBatis ${keyword} 구문으로 SQL에 직접 삽입됩니다.",
  "recommendation": "#{keyword} 바인딩으로 교체하여 PreparedStatement를 적용하세요.",
  "evidence": {
    "file":  "src/main/java/.../SearchRepository.java",
    "lines": "120-122",
    "code_snippet": "SELECT * FROM items WHERE name LIKE '%${keyword}%'",
    "taint_flow": {
      "source": "GET /api/search?keyword= (@RequestParam String keyword)",
      "sink": "mapper.search(${keyword})",
      "sanitized": false,
      "hops": 2,
      "call_chain": [
        "SearchController.search(@RequestParam keyword)",
        "SearchService.search(keyword)",
        "SearchMapper.search(${keyword})"
      ]
    },
    "taint_evidence": [
      {
        "title": "Taint Path — Controller → Service → Mapper",
        "controller_file": "src/main/java/.../SearchController.java",
        "controller_lines": "30-38",
        "controller_snippet": "/* Read 툴로 읽은 실제 Controller 코드 */",
        "service_file": "src/main/java/.../SearchService.java",
        "service_lines": "20-28",
        "service_snippet": "/* 실제 Service 코드 */",
        "repository_file": "src/main/java/.../SearchMapper.java",
        "repository_lines": "10",
        "repository_snippet": "/* 실제 Mapper 코드 */"
      }
    ]
  },
  "needs_review": false
}
```

#### findings[] 필드 정의

| 필드 | 필수 | 타입 | 설명 |
|------|:---:|------|------|
| `finding_id` | ✅ | string | skill 접두어 + 3자리 순번. 예: `INJ-001`, `XSS-003`, `FILE-002`, `DATA-007`, `SCA-001` |
| `title` | ✅ | string | `[카테고리] — [구체적 원인]` 형식 |
| `severity` | ✅ | enum | `Critical` / `High` / `Medium` / `Low` / `Informational` |
| `severity_rationale` | | string | severity 등급 근거 (기본값에서 하향/상향 조정 시 필수). 예: "IP ACL로 내부망 접근만 가능 — High→Medium 하향", "인증 없는 공개 API — Medium→High 상향" |
| `risk_level` | ✅ | integer | 1~5 숫자 등급. `severity_criteria.md` 매핑 기준 (Critical=5, High=4, Medium=3, Low=2, Informational=1). **보고서 위험도 컬럼에 `N 명칭` 형식으로 출력됨 — 반드시 포함** |
| `category` | ✅ | string | 취약점 분류명. 예: `SQL Injection`, `Persistent XSS`, `File Upload`, `Hardcoded Secret` |
| `cwe_id` | | string | `CWE-[0-9]+` 형식 |
| `owasp_category` | | string | OWASP Top 10 분류. 예: `A03:2021 Injection` |
| `result` | ✅ | enum | `취약` / `정보` — `llm_verdict: "needs_review"` 시에도 반드시 `"정보"` 사용 (`"수동검토필요"` 등 비표준 값 금지). 진단 시점에 고정됨 |
| `review_result` | | enum | `취약` / `정보` — `/sec-review` 에서 리뷰어가 확정한 최종 결과. 보고서 출력 시 `result` 보다 우선 적용. 스킵 시 필드 없음 |
| `diagnosis_method` | ✅ | enum | `자동스캔(SAST)` / `교차검증(수동)` / `수동진단(LLM)` |
| `source` | ✅ | enum | `auto-scan` / `llm-check` / `llm-check(fn-detected)` |
| `fn_detected` | ✅ | boolean | Auto-Scan이 양호로 판정했으나 LLM이 취약으로 재판정한 경우 `true` |
| `fp_corrected` | ✅ | boolean | LLM이 Auto-Scan 취약 판정을 FP로 재분류한 경우 `true` |
| `llm_verdict` | ✅ | enum | `"TP"` / `"FP"` / `"needs_review"` — LLM 최종 판정. auto-scan only 항목은 `null` |
| `llm_reviewed_at` | | string | LLM 검토 시각 (ISO8601). LLM 미검토 시 `null` |
| `manual_review_note` | | string | LLM 판정 근거 요약. 코드 경로, FP 이유, 확인 내용. LLM 검토 항목은 필수 |
| `scope` | ✅ | object | 취약점 영향 범위 (아래 scope 스키마 참조) |
| `description` | ✅ | string | 취약점 설명 (한국어) |
| `recommendation` | ✅ | string | 조치 방법 |
| `evidence` | ✅ | object | 파일 경로·라인·코드·taint 흐름 증적 (아래 evidence 스키마 참조) |
| `needs_review` | ✅ | boolean | 추가 수동 검토 필요 여부 |

#### evidence 객체 스키마

> **⚠️ taint_flow는 반드시 `evidence` 안에 포함한다.** finding 최상위 레벨에 두지 않는다.

| 필드 | 필수 | 설명 |
|------|:---:|------|
| `file` | ✅ | 취약 코드 파일 경로 (디렉토리 금지 — 실제 파일명까지 명시) |
| `lines` | | 취약 라인 번호 또는 범위 (`"120"` / `"120-125"`) |
| `code_snippet` | ✅ | Read 툴로 직접 읽은 실제 취약 코드. 생성/추측 금지. 미확인 시 `needs_review: true` |
| `taint_flow` | | Taint 흐름 요약 객체 (DB 저장·렌더링 경로 확인된 경우 필수) |
| `taint_evidence` | | Controller→Service→Repository 계층별 실제 코드 스니펫 배열 |
| `bb_url` | | Bitbucket 파일 직접 링크 (업로드 시 자동 주입) |

**taint_flow 객체 구조:**
```json
"taint_flow": {
  "source": "HTTP @RequestParam keyword (사용자 입력)",
  "sink": "mapper.search(${keyword}) — MyBatis 동적 SQL",
  "sanitized": false,
  "hops": 2,
  "call_chain": [
    "SearchController.search(@RequestParam keyword)",
    "SearchService.search(keyword)",
    "SearchMapper.search(${keyword})"
  ]
}
```

**taint_evidence 배열 구조 (계층별 실제 코드):**
```json
"taint_evidence": [
  {
    "title": "Taint Path — Controller → Service → Repository",
    "controller_file": "실제 경로/Controller.java",
    "controller_lines": "30-38",
    "controller_snippet": "/* Read 툴로 읽은 실제 코드 */",
    "service_file": "실제 경로/Service.java",
    "service_lines": "20-28",
    "service_snippet": "/* 실제 Service 코드 */",
    "repository_file": "실제 경로/Repository.java",
    "repository_lines": "10",
    "repository_snippet": "/* 실제 Repository/Mapper 코드 */"
  }
]
```

#### scope 객체 — type별 필드

`scope.type`은 취약점 성격에 따라 아래 5종 중 하나.

| type | 적용 | 주요 필드 |
|------|------|---------|
| `endpoint` | API endpoint에 연결된 취약점 (SQLi, XSS, File Upload/Download 등) | `endpoint`, `handler`, `affected_file`, `affected_line` |
| `file` | 특정 소스코드 파일:라인의 코드 문제 (하드코딩 시크릿, OS Command, 약한 암호 등) | `affected_file`, `affected_line` |
| `config` | 설정 파일 오설정 (CORS, JWT, 보안 헤더 등) | `affected_file`, `config_key` |
| `dependency` | 외부 라이브러리 CVE (SCA) | `package`, `version`, `cve_id` |
| `global` | 전역 스캔 결과, endpoint 무관 (DOM XSS, SSI Injection 등) | `affected_file`, `affected_line` |

```json
{ "type": "endpoint",    "endpoint": "GET /api/search", "handler": "SearchController.search()", "affected_file": "src/.../SearchRepo.java", "affected_line": 120 }
{ "type": "file",        "affected_file": "src/.../FileUtils.java", "affected_line": 45 }
{ "type": "config",      "affected_file": "src/main/resources/application.yml", "config_key": "cors.allowed-origins" }
{ "type": "dependency",  "package": "log4j-core", "version": "2.14.1", "cve_id": "CVE-2021-44228" }
{ "type": "global",      "affected_file": "src/main/webapp/js/search.js", "affected_line": 88 }
```

#### affected_files[] — 동일 취약점의 복수 파일/API 명시

동일한 취약점이 여러 파일 또는 API에 걸쳐 나타날 경우, `scope` 내에 `affected_files[]` 배열을 추가한다.  
`affected_file` / `affected_line` 단일 필드는 **첫 번째 항목**을 가리키며 하위 호환성을 유지한다.

```json
"scope": {
  "type": "endpoint",
  "endpoint": "GET /api/search",
  "handler": "SearchController.search()",
  "affected_file": "src/.../SearchRepository.java",
  "affected_line": 120,

  "affected_files": [
    {
      "file": "src/.../SearchRepository.java",
      "line": 120,
      "endpoint": "GET /api/search",
      "handler": "SearchController.search()",
      "note": "주요 취약 지점"
    },
    {
      "file": "src/.../ProductRepository.java",
      "line": 88,
      "endpoint": "POST /api/items",
      "handler": "ItemController.create()"
    }
  ]
}
```

**`affected_files` 항목 필드 정의**

| 필드 | 필수 | 설명 |
|------|:---:|------|
| `file` | ✅ | 소스코드 파일 경로 |
| `line` | | 취약 라인 번호 (단일 라인 또는 `"120-125"` 범위) |
| `endpoint` | | 관련 API endpoint (scope.type이 endpoint인 경우) |
| `handler` | | Controller/Handler 메서드 시그니처 |
| `note` | | 해당 항목에 대한 추가 설명 |

---

#### finding 그룹핑 기준 — 1건 vs 복수 건 분리

**단일 finding에 `affected_files[]`로 묶는 경우** (같은 취약점, 여러 위치):

| 조건 | 예시 |
|------|------|
| 동일 CWE + 동일 근본 원인 | MyBatis `${}` 패턴이 여러 Mapper 파일에 반복 사용 |
| 조치 방법이 동일 | 동일한 hardcoded secret이 여러 config 파일에 존재 |
| 동일 설정 오류 | CORS wildcard가 `application.yml` + `CorsConfig.java` 양쪽에 선언 |
| 동일 CVE 라이브러리 (SCA) | log4j 2.14.1 — 한 프로젝트 내 복수 모듈이 동일 버전 의존 |
| 동일 약한 암호 알고리즘 | `MD5` 사용이 여러 Util 클래스에 분산 |

**별개 finding으로 분리하는 경우** (파일 1건 : finding 1건):

| 조건 | 예시 |
|------|------|
| 근본 원인이 다른 경우 | SQLi-A는 `${}` 바인딩, SQLi-B는 문자열 직접 연결 → 조치 방법 상이 |
| 취약점 유형이 다른 경우 | 파일 업로드 검증 누락 vs. Path Traversal → 별도 CWE |
| Severity가 다른 경우 | 동일 패턴이지만 한쪽은 인증 없는 공개 API (Critical), 다른쪽은 내부 API (Medium) |
| 서로 독립적인 taint flow | 입력→출력 경로가 완전히 다른 XSS 지점 |
| 파일 업로드 각 endpoint | 검증 로직이 endpoint별로 다름 → 각 endpoint 1건 finding |

### evidence_trail[] — 양호 항목 증적 스키마

양호 판정 항목 및 LLM이 FP로 재분류한 항목을 감사 추적용으로 보존.
파일에 포함되어 보안 감사·재검토 시 참조 가능.

```json
{
  "trail_id": "TRAIL-001",
  "result": "양호",
  "source": "auto-scan",
  "fp_corrected": false,

  "scope": {
    "type": "endpoint",
    "endpoint": "GET /api/users/{id}",
    "handler": "UserController.getUser()"
  },

  "diagnosis_method": "자동스캔(SAST)",
  "diagnosis_detail": "JPA findById() 사용 — PreparedStatement 자동 바인딩 확인",
  "finding_id": null
}
```

FP 재분류된 경우 (auto-scan이 취약으로 판정 → LLM이 양호로 재판정):

```json
{
  "trail_id": "TRAIL-045",
  "result": "양호",
  "source": "auto-scan",
  "fp_corrected": true,

  "scope": {
    "type": "endpoint",
    "endpoint": "POST /api/order",
    "handler": "OrderController.createOrder()"
  },

  "diagnosis_method": "교차검증(수동)",
  "diagnosis_detail": "auto-scan이 취약으로 판정했으나, Integer 타입 파라미터만 사용하여 SQL 삽입 불가 확인",
  "finding_id": "INJ-AUTO-012",
  "original_severity": "High"
}
```

#### evidence_trail[] 필드 정의

| 필드 | 필수 | 설명 |
|------|:---:|------|
| `trail_id` | ✅ | `TRAIL-NNN` 형식 |
| `result` | ✅ | `양호` 고정 (취약/정보는 findings[]에 있음) |
| `source` | ✅ | `auto-scan` / `llm-check` |
| `fp_corrected` | ✅ | Auto-Scan 취약 판정을 LLM이 양호로 재분류한 경우 `true` |
| `scope` | ✅ | findings[]와 동일 scope 객체 |
| `diagnosis_method` | ✅ | 최종 판정 방법 |
| `diagnosis_detail` | ✅ | 양호 판정 근거 (빈 문자열 금지) |
| `finding_id` | | FP 재분류 시 auto-scan이 부여했던 임시 ID |
| `original_severity` | | FP 재분류 시 auto-scan의 원래 severity |

### llm_checked 정책 — sec-review 전 필수 확인

`findings_*.json`의 최상위 `llm_checked` 필드 값이 **`true`인 파일만 sec-review 대상**이다.

| `llm_checked` | 의미 | sec-review 가능 |
|:---:|---|:---:|
| `true` | Auto-Scan + LLM-Check 완료, 검증된 finding | ✅ |
| `false` | Auto-Scan Phase만 완료, LLM 미검증 임시 draft | ❌ |
| 없음(미생성) | 해당 파일 없음 | ❌ |

---

### finding_id 부여 규칙

| skill | 접두어 | 예시 |
|-------|--------|------|
| sec-scan-injection | `INJ` | `INJ-001` |
| sec-scan-xss | `XSS` | `XSS-003` |
| sec-scan-file | `FILE` | `FILE-002` |
| sec-scan-data | `DATA` | `DATA-007` |
| sec-scan-sca | `SCA` | `SCA-001` |

- Auto-Scan이 임시 부여한 ID: `INJ-AUTO-NNN` (LLM-Check 완료 후 정식 ID로 교체)
- 번호는 severity 내림차순 정렬 후 부여 (Critical부터 `001`)

### source 필드 의미

| source | 의미 |
|--------|------|
| `auto-scan` | Auto-Scan Phase 스크립트가 식별. LLM 미검토 또는 LLM이 그대로 인정 |
| `llm-check` | LLM-Check Phase가 신규 식별하거나 auto-scan 결과를 검증·보완 |
| `llm-check(fn-detected)` | Auto-Scan이 양호로 판정했으나 LLM이 실제 취약으로 재판정 (F/N 탐지) |

### 생성 절차 (LLM-Check Phase 수행 기준)

```
1. Auto-Scan 원본 파일 읽기 (injection.json 등)
2. auto_findings[] (취약·정보) → findings 후보로 적재 (source: "auto-scan")
3. LLM 교차검증:
   a. 후보 중 FP 확인된 항목 → findings에서 제거, evidence_trail[]로 이동 (fp_corrected: true)
   b. 양호 endpoint 중 F/N 탐지 → findings에 추가 (source: "llm-check(fn-detected)", fn_detected: true)
4. LLM 신규 발굴 취약점 → findings에 추가 (source: "llm-check")
5. findings[] severity 내림차순 정렬 후 finding_id 부여 (INJ-001, INJ-002, ...)
6. evidence_trail[]에 전체 양호 항목 기록 (trail_id: TRAIL-001, ...)
7. findings_injection.json 저장
```

### Auto-Scan Phase 단독 실행 시 임시 파일

LLM-Check 완료 전 임시 파일이 필요한 경우, 스크립트가 `findings_{task_id}_draft.json`을 생성.
`llm_checked: false`로 표시하며, LLM-Check 완료 후 `findings_{task_id}.json`으로 대체됨.

```json
{
  "task_id": "injection",
  "llm_checked": false,
  "generated_at": "...",
  "findings": [ /* auto_findings[]에서 취약·정보 항목만 */ ],
  "evidence_trail": [ /* 양호 항목 */ ]
}
```

---

## llm_data_access_log.json Schema (LLM 데이터 접근 및 클렌징 기록)

> **목적**: Phase 3 LLM-Check 완료 후 LLM이 접근한 고객사 소스코드 파일 목록 및 클렌징 수행 내역을 기록.  
> **생성 시점**: Phase C (클렌징) 단계에서 Claude가 자동 생성.  
> **저장 위치**: `state/<prefix>/llm_data_access_log.json`  
> **정책 문서**: `shared/references/llm_data_cleansing_policy.md`

```json
{
  "scan_id": "ocb-community-api_20260430_1400",
  "repo": "ocb-community-api",
  "project": "OCBWEBVIEW",
  "skill": "injection",
  "provider": "claude-cli",
  "scanned_at": "2026-04-30T14:00:00+09:00",
  "cleansing_completed": true,
  "cleansing_completed_at": "2026-04-30T16:30:00+09:00",

  "llm_accessed_files": [
    {
      "phase": "Phase 1 - Asset Identification",
      "purpose": "자산 식별 (프레임워크, 기술스택, 빌드 구조 확인)",
      "files": [
        "testbed/ocb-community-api/build.gradle",
        "testbed/ocb-community-api/settings.gradle",
        "testbed/ocb-community-api/src/main/resources/application.yml"
      ]
    },
    {
      "phase": "Phase 3 - LLM-Check",
      "purpose": "교차검증 (Taint 흐름 추적 — Controller → Service → Repository)",
      "files": [
        "testbed/ocb-community-api/src/main/java/.../CommunityController.java",
        "testbed/ocb-community-api/src/main/java/.../CommunityService.java",
        "testbed/ocb-community-api/src/main/resources/mapper/CommunityMapper.xml"
      ]
    }
  ],

  "cleansing_actions": [
    {
      "action": "testbed_deletion",
      "target": "testbed/ocb-community-api/",
      "confirmed": true,
      "confirmed_at": "2026-04-30T16:28:00+09:00"
    },
    {
      "action": "state_snippet_audit",
      "description": "state/ 내 소스코드 전체 파일 복사 없음 확인 — findings의 code_snippet/taint_evidence만 존재",
      "confirmed": true,
      "confirmed_at": "2026-04-30T16:29:00+09:00"
    },
    {
      "action": "gitleaks_redact_check",
      "description": "seed_gitleaks.json --redact 적용 여부 확인",
      "confirmed": true,
      "confirmed_at": "2026-04-30T16:29:00+09:00"
    },
    {
      "action": "claude_session_closure",
      "description": "진단 완료 후 LLM 세션 종료 예정 — 운영자가 새 세션 시작으로 컨텍스트 만료 처리",
      "confirmed": false,
      "note": "운영자 수동 수행 필요"
    }
  ],

  "notes": ""
}
```

### llm_data_access_log.json 필드 정의

| 필드 | 필수 | 설명 |
|---|:---:|---|
| `scan_id` | ✅ | `<repo>_<YYYYMMDD_HHMM>` 형식 (state prefix와 동일) |
| `repo` | ✅ | 진단 대상 레포 이름 |
| `project` | ✅ | Bitbucket 프로젝트 키 |
| `skill` | ✅ | 실행된 skill 이름 (injection / xss / file / data / sca) |
| `provider` | ✅ | LLM provider (claude-cli / anthropic-api) |
| `scanned_at` | ✅ | 진단 시작 시각 (ISO8601) |
| `cleansing_completed` | ✅ | 클렌징 전체 완료 여부 (`true` / `false`) |
| `cleansing_completed_at` | | 클렌징 완료 시각 (ISO8601) |
| `llm_accessed_files` | ✅ | Phase별 LLM이 Read 도구로 접근한 파일 목록 배열 |
| `cleansing_actions` | ✅ | 수행된 클렌징 액션 목록 (testbed_deletion 필수) |
| `notes` | | 특이사항 (클렌징 불가 사유 등) |

### cleansing_actions — 고정 항목

| action | 설명 | 수행 주체 |
|---|---|---|
| `testbed_deletion` | `testbed/<repo>/` 삭제 | Claude (자동) |
| `state_snippet_audit` | state/ 내 원본 소스코드 파일 복사 없음 확인 | Claude (자동) |
| `gitleaks_redact_check` | seed_gitleaks.json `--redact` 적용 확인 | Claude (자동) |
| `claude_session_closure` | 진단 세션 종료 — 새 세션 시작으로 컨텍스트 만료 | 운영자 (수동) |
