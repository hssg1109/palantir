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
   - ⚠️ **주의**: `testbed/<repo>/.clone_info.json`(Bitbucket 프로젝트/브랜치/커밋/담당자)은 이 삭제로 함께 사라진다.
     `clone_repo.py`가 clone 시점에 `state/<repo>/repo_meta.json`에 동일 내용을 영속 저장하므로,
     이 파일이 이미 존재하는 정상 clone 레포는 testbed 삭제 후에도 `generate_final_report.py`가
     메타데이터를 정상 로드한다. `state/<repo>/repo_meta.json`이 없는 상태로 testbed부터 삭제하면
     보고서의 "Bitbucket 프로젝트/저장소/브랜치/커밋 해시/담당자" 5개 필드가 전부 `—`로 누락되니,
     삭제 전 `state/<repo>/repo_meta.json` 존재 여부를 확인한다 (없으면 `clone_repo.py`를 먼저 재실행).

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
   | testbed 삭제 | ✅ 또는 ⚠️ |
   | state 감사 | ✅ 또는 ⚠️ |
   | 스캔 redact | ✅ 또는 ⚠️ |
   | 세션 종료 | 🔲 (운영자 수동) |
   | 완료 | 🔲 (세션 종료 대기) |
   | 로그 위치 | `state/<repo>/llm_data_access_log.json` |

   Confluence REST API 호출은 `tools/publish_confluence.py` 또는 curl을 사용한다.  
   `.env`의 `CONFLUENCE_TOKEN`(Bearer) 사용 필수.

   **⚠️ 삽입 위치 anchor 주의**: 레지스트리 페이지에는 `</tbody></table>`가 2개 이상 존재한다 ("클렌징 이력" 표 + "열 설명" 표). 문서 내 **마지막** `</tbody></table>` 앞에 무조건 삽입하는 방식(rfind 등)은 금지 — "클렌징 이력" 표가 "열 설명" 표보다 앞에 있어 새 행이 엉뚱한 표("열 설명")에 삽입되는 사고가 실제 발생했다(2026-07-13, v75/v76). 반드시 **표 제목(`<h2>클렌징 이력</h2>`) 또는 헤더 행(`<tr><th>진단일</th>...`)을 anchor로 표를 특정**한 뒤, 그 표의 마지막 `<tr>...</tr>` 직후에 새 행을 삽입할 것. 삽입 후에는 새 행이 올바른 표 안에 들어갔는지 (헤더 열 개수 일치 등으로) 반드시 확인한다.

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
