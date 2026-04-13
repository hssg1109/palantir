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
    "task_id": { "type": "string", "pattern": "^[0-9]+-[0-9]+$" },
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
    "task_id": { "type": "string", "pattern": "^[0-9]+-[0-9]+$" },
    "status": { "type": "string", "enum": ["completed", "failed", "partial"] },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "title", "severity", "category", "description"],
        "properties": {
          "id": { "type": "string", "description": "취약점 고유 ID (예: VULN-001)" },
          "title": { "type": "string" },
          "severity": { "type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"] },
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
  "task_id": "2-2",
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
  "task_id": "2-3",
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
