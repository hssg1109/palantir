# Phase C — LLM 데이터 클렌징 절차

**버전**: 1.1  
**정책 문서**: `shared/references/llm_data_cleansing_policy.md`  
**스키마**: `shared/references/output_schemas.md` → `llm_data_access_log.json Schema`

---

## 역할 분리

Phase C는 두 단계로 나뉜다.

| 단계 | 시점 | 수행 주체 | 내용 |
|---|---|---|---|
| **C-1: 로그 업데이트** | 각 skill Step 4-1 직후 | 각 SKILL.md | llm_data_access_log.json 생성/append |
| **C-2: 클렌징 완료** | `/sec-review` 완료 직후 | sec-review.md | testbed 삭제 + 감사 + Confluence 등록 |

> **이유**: 5개 skill이 순차 실행되는 동안 testbed를 삭제하면 다음 skill 진단이 불가능하다.  
> testbed 삭제는 모든 skill 완료 후 `/sec-review` 시점에 1회 수행한다.

---

## C-1: 로그 업데이트 (각 skill 완료 시)

### 수행 위치

각 skill SKILL.md의 **Step 4-1 직후**.

### 수행 내용

1. **이 세션에서 `testbed/<repo>/` 경로 파일을 Read 도구로 접근한 목록 정리**
   - Phase 1(자산 식별)에서 읽은 파일
   - Phase 3(LLM-Check)에서 읽은 파일
   - 각 파일은 `testbed/<repo>/...` 전체 경로로 기록

2. **`state/<repo>/llm_data_access_log.json` 생성 또는 업데이트**

   - 파일 없음 → 신규 생성 (repo 레벨 통합 로그)
   - 파일 있음 → `skills[]` 배열에 이 skill 항목 append

   추가할 skill 항목:
   ```json
   {
     "skill": "<skill_name>",
     "scan_dir": "state/<repo>/<skill>/<YYYYMMDD_HHMM>",
     "scanned_at": "<진단 시작 ISO8601 +09:00>",
     "llm_accessed_files": [
       {
         "phase": "Phase 1 - Asset Identification",
         "purpose": "자산 식별 (프레임워크·빌드 구조·설정 파일 확인)",
         "files": [
           "testbed/<repo>/build.gradle",
           "testbed/<repo>/settings.gradle"
         ]
       },
       {
         "phase": "Phase 3 - LLM-Check",
         "purpose": "교차검증 (Taint 흐름 추적)",
         "files": [
           "testbed/<repo>/src/main/java/.../Controller.java"
         ]
       }
     ]
   }
   ```

3. **신규 생성 시 파일 전체 구조** (스키마 전문은 `output_schemas.md` 참조):
   ```json
   {
     "repo": "<repo>",
     "project": "<bb_project>",
     "provider": "claude-cli",
     "retroactive": false,
     "cleansing_completed": false,
     "cleansing_completed_at": null,
     "skills": [ <이번 skill 항목> ],
     "cleansing_actions": [
       { "action": "testbed_deletion",    "target": "testbed/<repo>/", "confirmed": false, "confirmed_at": null },
       { "action": "state_snippet_audit", "description": "state/ 내 소스코드 전체 파일 복사 없음 확인", "confirmed": false },
       { "action": "scan_script_redact", "description": "scan_data_protection.py _redact_snippet() 자동 적용 확인", "confirmed": false, "note": "" },
       { "action": "claude_session_closure", "description": "LLM 세션 종료", "confirmed": false, "note": "운영자 수동 수행 필요" }
     ],
     "notes": ""
   }
   ```
   - `project`는 `state/<repo>/20*/scan_meta.json`의 `bb_project` 값; 없으면 `"?"` 로 기입

4. **cleansing_completed: false 유지** — testbed 삭제 전까지 false.

### 완료 출력 형식

```
[Phase C-1] llm_data_access_log.json 업데이트 완료
  skill  : <skill_name>
  접근파일: <N>건 (Phase 1: N / Phase 3: N)
  로그   : state/<repo>/llm_data_access_log.json
  [안내] testbed 삭제·Confluence 등록 → /sec-review 완료 시 수행
```

---

## C-2: 클렌징 완료 (sec-review 완료 시)

### 수행 위치

`/sec-review` 의 **Step 5c(Audit 세션 종료) 직후**, 완료 요약 출력 전.

### 수행 내용

1. **`state/<repo>/llm_data_access_log.json` 로드**
   - 파일이 없는 경우 → skills[] 없이 repo 레벨 기본 구조만 생성 후 진행

2. **testbed 삭제**
   ```bash
   rm -rf testbed/<repo>/
   ```
   - 삭제 성공 → `cleansing_actions[testbed_deletion].confirmed = true`, `confirmed_at = <ISO8601>`
   - 이미 삭제됨 → `confirmed = true`, `note = "이미 삭제됨"`

3. **state/ 소스코드 감사**
   ```bash
   find state/<repo>/ -name "*.java" -o -name "*.kt" -o -name "*.xml" -o -name "*.py" \
     | grep -v "__pycache__" | head -5
   ```
   - 0건 → `state_snippet_audit.confirmed = true`
   - 1건 이상 → 파일 목록 출력 + `note = "주의: 소스 파일 N건 발견"`, `confirmed = false`

4. **스캔 redact 확인**
   - `sec-scan-data` skill 실행 여부 확인 (data skill이 있으면 `scan_data_protection.py`의 `_redact_snippet()`이 자동 적용됨)
   - data skill 실행됨 → `scan_script_redact.confirmed = true`, `note = "scan_data_protection.py _redact_snippet() 자동 적용"`
   - data skill 미실행 → `scan_script_redact.confirmed = false`, `note = "data skill 미실행"`

5. **`cleansing_completed` 갱신**
   - `testbed_deletion.confirmed == true` AND `state_snippet_audit.confirmed == true` → `cleansing_completed = true`, `cleansing_completed_at = <ISO8601>`
   - 이외 → `cleansing_completed = false`, `notes`에 미완료 사유 기록

6. **Confluence 레지스트리 행 추가** (page ID: `<YOUR_REGISTRY_PAGE_ID>`)

   레지스트리 한 행 (레포당 1행):

   | 필드 | 값 |
   |---|---|
   | 진단일 | 마지막 skill scanned_at 날짜 |
   | 고객사/프로젝트 | `<project>` |
   | 레포 | `<repo>` |
   | Skill | `all (injection/xss/file/data/sca)` |
   | LLM 접근 파일 수 | skills[] 전체 llm_accessed_files 파일 합산 |
   | testbed 삭제 | ✅ 또는 ⚠️ |
   | state 감사 | ✅ 또는 ⚠️ |
   | 스캔 redact | ✅ 또는 ⚠️ |
   | 세션 종료 | 🔲 (운영자 수동) |
   | 완료 | 🔲 (세션 종료 대기) |
   | 로그 위치 | `state/<repo>/llm_data_access_log.json` |

   Confluence REST API 호출은 `tools/publish_confluence.py` 또는 curl을 사용한다.  
   `.env`의 `CONFLUENCE_TOKEN`(Bearer) 사용 필수.

7. **`llm_data_access_log.json` 최종 저장**

### 완료 출력 형식

```
[Phase C-2] 클렌징 완료 처리
  testbed 삭제   : ✅ testbed/<repo>/ 삭제
  state 감사     : ✅ 소스 파일 0건
  스캔 redact    : ✅
  Confluence     : ✅ 레지스트리 행 추가 완료
  로그           : state/<repo>/llm_data_access_log.json
  [운영자] LLM 세션을 종료하고 새 세션을 시작하세요.
```

---

## 예외 처리

| 상황 | 처리 방법 |
|---|---|
| testbed가 이미 없음 | `confirmed = true`, `note = "이미 삭제됨"` 기록 후 계속 |
| llm_data_access_log.json 없음 (C-2 시점) | 빈 skills[] 로 신규 생성 후 cleansing_actions만 기록 |
| state/ 소스 파일 발견 | 파일 목록 출력, `confirmed = false`, `notes`에 기록, 계속 진행 |
| Confluence API 실패 | `notes`에 API 오류 기록 후 계속 진행 (나중에 수동 등록) |
