# palantir 보안 진단 보고서 생성 파이프라인 가이드

> **목적**: 위키 보고서(Confluence) 및 Jira 티켓 본문이 어떤 데이터·로직으로 생성되는지 정리한 내부 공유 문서.  
> **대상**: 보고서 품질 개선, 템플릿 수정, 또는 파이프라인 이해가 필요한 담당자.  
> **작성일**: 2026-06-26

---

## 1. 전체 파이프라인 흐름

```
[1단계] SAST 스캔  (sec-scan-injection / xss / file / data / sca)
          ↓
    state/<repo>/<skill>/<RUN_ID>/findings_*.json  ← 취약점 데이터 원본

[2단계] 인터랙티브 리뷰  (/sec-review)
          ↓
    findings_*.json 에 reviewed, review_status, review_result,
    review_note, report_expand 필드 추가

[3단계] 최종 보고서 생성 + 게시  (approve_report.py --publish)
          ├─ generate_report.py        → logs/report_final_*.md     (1차 내부 보고서)
          ├─ generate_final_report.py  → logs/final_*.md            (Confluence 게시본)
          │        └─ publish_confluence.py  → Confluence 페이지 PUT
          └─ POST /api/pending         → jira-gateway 티켓 대기 등록
```

**관련 파일 위치**

| 역할 | 파일 |
|---|---|
| 최종 보고서 생성기 | `tools/generate_final_report.py` |
| 보고서 승인·게시 오케스트레이터 | `tools/approve_report.py` |
| MD → Jira Wiki markup 변환기 | `palantir-jira-gateway/lambda/converter.py` |
| Finding 작성 기준 | `shared/references/finding_writing_guide.md` |
| Finding JSON 스키마 | `shared/references/output_schemas.md` |

---

## 2. 입력 데이터 소스

보고서 생성 시 읽어오는 외부 파일 목록.

| 소스 파일 | 데이터 내용 | 사용 위치 |
|---|---|---|
| `state/<repo>/<skill>/<RUN_ID>/findings_*.json` | 취약점 전체 (제목·위험도·코드스니펫·설명·조치권고) | 섹션 2, 3 전체 |
| `testbed/<repo>/.clone_info.json` | 진단 브랜치·커밋해시·clone URL·마지막 커밋 작성자 | 섹션 1 진단 개요 표 |
| `state/<repo>/review_meta.json` | 서비스 특징 문장, 추가진단 필요여부 | 섹션 1 진단 개요 표 |
| `docs/service_inventory.json` | 대외 / 대내 / 대내외 노출 분류 | 섹션 1 `서비스 유형` 셀 |
| `docs/.confluence_pages.json` | 기존 Confluence page_id 레지스트리 | UPDATE vs CREATE 분기 판단 |

---

## 3. findings_*.json 핵심 스키마

보고서의 모든 취약점 데이터는 아래 구조에서 읽어온다.

```json
{
  "task_id": "injection",
  "llm_checked": true,
  "findings": [
    {
      "finding_id": "INJ-001",
      "title": "SQL Injection — MyBatis ${} 동적 바인딩",
      "severity": "Critical",
      "risk_level": 5,
      "category": "SQL Injection",
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021 Injection",
      "result": "취약",
      "review_result": "취약",
      "scope": {
        "type": "endpoint",
        "endpoint": "GET /api/search",
        "handler": "SearchController.search()",
        "affected_file": "src/main/java/.../SearchRepository.java",
        "affected_line": 120
      },
      "description": "외부 입력 파라미터 keyword가 MyBatis ${keyword} 구문으로 SQL에 직접 삽입됩니다...",
      "recommendation": "1. #{keyword} 바인딩으로 교체하세요.\n2. 입력 검증 로직을 추가하세요.",
      "evidence": {
        "file": "src/main/java/.../SearchRepository.java",
        "lines": "120-122",
        "code_snippet": "SELECT * FROM items WHERE name LIKE '%${keyword}%'",
        "taint_flow": {
          "source": "GET /api/search?keyword=",
          "sink": "mapper.search(${keyword})",
          "sanitized": false,
          "hops": 2,
          "call_chain": ["SearchController.search()", "SearchService.search()", "SearchMapper.search()"]
        }
      },
      "report_expand": "## 상세 검증 결과\n코드 직접 확인 내용...",
      "reviewed": true,
      "review_status": "정탐"
    }
  ]
}
```

**보고서에 포함되는 finding 조건**: `result` 또는 `review_result` 가 `"취약"` 또는 `"정보"` 이고, `llm_checked: true` 파일에 속한 항목만.

### finding_id 접두어 규칙

| 스킬 | 접두어 | 예시 |
|---|---|---|
| sec-scan-injection | INJ | INJ-001 |
| sec-scan-xss | XSS | XSS-003 |
| sec-scan-file | FILE | FILE-002 |
| sec-scan-data | DATA | DATA-007 |
| sec-scan-sca | SCA | SCA-001 |

### 위험도(severity) → 등급(risk_level) 매핑

| 등급 | 영문 | 보고서 표기 | 색상 |
|:---:|---|---|---|
| 5 | Critical | **5** (빨강) | `{color:red}**5**{/color}` |
| 4 | High | **4** (빨강) | `{color:red}**4**{/color}` |
| 3 | Medium | **3** (주황) | `{color:#FF8C00}**3**{/color}` |
| 2 | Low | **2** | (색상 없음) |
| 1 | Informational | **1** | (색상 없음) |

---

## 4. 보고서 섹션별 구성

보고서는 총 4개 섹션으로 구성된다. 각 섹션의 생성 방식과 데이터 출처를 기술한다.

---

### 4.1 섹션 1 — 진단 개요

**생성 방식**: 완전 자동 (구조 데이터 직접 삽입)  
**코드 위치**: `generate_final_report.py` L941-965

```markdown
| 항목 | 데이터 출처 |
|---|---|
| 진단 대상 | --repo 인자 (repo 슬러그) |
| 서비스 유형 | docs/service_inventory.json → exposure_ko (대외/대내/대내외 + 아이콘) |
| Bitbucket 프로젝트 | .clone_info.json → project |
| 소스코드 저장소 | .clone_info.json → clone_url |
| 진단 브랜치 | .clone_info.json → branch |
| 커밋 해시 | .clone_info.json → commit_hash (앞 12자 truncate, 코드 포맷) |
| *담당자 | .clone_info.json → last_commit_author (git 커밋 작성자 raw값) |
| 보고서 생성일 | datetime.now() 실행 시점 |
| RUN_ID | --run-id 인자 (코드 포맷) |
| 진단 유형 | 고정 문자열 "SAST (정적 분석) + LLM 교차검증" |
| 진단 도구 | 고정 문자열 "palantir (Claude Code 기반)" |
| 전체 발견 건수 | findings[] 배열 len() |
| 추가진단 필요여부 | review_meta.json → additional_diagnosis_needed (boolean → 필요/불필요) |
```

> **주의**: `담당자` 셀의 원본은 `git clone` 시 기록된 마지막 커밋 작성자(`.clone_info.json`)를 그대로 삽입한다. git 계정명 설정에 따라 `이름(영문)/팀/SKP <email>`, `1000690 <email>`, `[SKP] 이름 <email>` 등 형식이 불일치하는 문제가 있으며, 보고서 게시 후 수동 또는 Jira API 조회를 통해 표준화(`이름(영문)/팀/SKP/사번 <email>`)해야 한다.

---

### 4.2 섹션 2.1 — 취약점 개요

**생성 방식**: **Claude CLI 자동 생성 (유일한 자유 텍스트 AI 작성 섹션)**  
**코드 위치**: `generate_final_report.py` L432-539, L968-991

#### 프롬프트 구성

```
당신은 보안 전문가입니다. 아래 SAST 진단 결과를 바탕으로 취약점 개요 문단을 작성해주세요.

## 진단 대상
- 레포: {repo}
- 서비스 유형: {exposure_type}
- 위험도별 현황: 고위험(High) N건, 중간위험(Medium) N건, ...

## 즉시 조치 필요 취약점 목록 (결과: 취약)
1. [High] 제목
   분류: SQL_INJECTION
   설명: 설명 앞 120자...
...

## 작성 요청
1. 대상 독자는 해당 서비스를 개발한 개발자입니다.
2. 위험도 높은 주요 취약점 현황을 간략히 언급하고...
3. 마지막에 한 문장으로 조치 방향 추가.
4. 분량: 2~3문장. 짧고 명확하게.
5. 존댓말(합쇼체).
6. 취약점이 없는 경우 '이번 진단에서 취약 항목이 발견되지 않았습니다.'로 시작.
7. @ToString/@Data DTO 노출 / DoS 전용 SCA CVE / 디버그 로그 제외.

출력 형식: 완성된 개요 문단만 출력 (제목·목록 없이 산문체).
```

**프롬프트 입력 필터링 규칙**:
- `result == "취약"` 인 findings만 전달 (정보/양호 제외)
- DoS 전용 CVE (OOM/StackOverflow/Welcome Page 키워드 포함)는 후순위 배치
- 최대 15건까지 표시
- `subprocess.run(["claude", "-p", prompt])` 로 실행 (실패 시 수동 작성 placeholder 삽입)

---

### 4.3 섹션 2.2 — 취약점 요약 표

**생성 방식**: 완전 자동 (findings 데이터 구조화)  
**코드 위치**: `generate_final_report.py` L1021-1041

```
| Sub_No | 결과 | 위험도 | 제목 | 분류 | 파일:라인 | 조치 요약 |
```

**정렬 순서**: 스킬 순(injection → xss → file → data → sca) → 결과 순(취약 우선) → 위험도 내림차순

**각 셀 생성 규칙**:

| 컬럼 | 생성 규칙 |
|---|---|
| Sub_No | `{스킬순번}-{finding순번}` (예: 1-1, 1-2, 2-1) |
| 결과 | `취약` → `{color:red}취약{/color}`, `정보` → `{color:#FF8C00}정보{/color}` |
| 위험도 | Critical/High=빨강 bold 숫자, Medium=주황 bold 숫자 |
| 제목 | `_clean_title()` 적용 (SCA 재포맷 + verbose suffix 제거) |
| 분류 | finding.category 그대로 |
| 파일:라인 | `scope.affected_file:affected_line` (testbed/ 경로 prefix 제거) |
| 조치 요약 | `_recom_summary()` — 첫 문장 한 문장, 80자 한도 |

---

### 4.4 섹션 3 — 취약점 상세

**생성 방식**: 완전 자동 (finding 데이터 블록 렌더링)  
**코드 위치**: `generate_final_report.py` L817-907

finding 1건당 아래 블록 구조로 렌더링:

```markdown
#### {Sub_No} {title}                     ← _clean_title() 적용

| 항목 | 내용 |
|---|---|
| 결과 | {색상 마커 적용} |
| 위험도 | {색상 마커 적용} |
| 분류 | {category} |
| 엔드포인트 | `{scope.endpoint}` |         ← scope에 endpoint 있을 때만 출력
| 핸들러 | `{scope.handler}` |              ← scope에 handler 있을 때만 출력
| 영향 파일 | `{affected_file:line}` |      ← scope에 파일 있을 때만 출력

**설명**
{description 또는 manual_review_note}     ← _normalize_desc() 어미 정제 후 삽입

**조치 권고**
{recommendation}                          ← 번호 목록은 Confluence 렌더러 호환 처리

**증거 코드** — `파일명`
```{lang}
{evidence.code_snippet}
```

:::expand 상세 검증 결과 (코드 직접 확인)
{report_expand 또는 review_note}          ← /sec-review 단계에서 LLM이 작성한 내용
:::

:::expand Taint Flow 상세 (참조용)
{evidence.taint_flow + taint_evidence}    ← Source/Sink/Hops/call_chain 표 + 계층별 코드
:::

---
```

**언어 자동 감지 (코드 블록 하이라이팅)**:

| 확장자 | lang |
|---|---|
| .kt | kotlin |
| .java | java |
| .js .ts .tsx .jsx | javascript |
| .py | python |
| .php | php |
| .xml .yaml .yml | xml |
| 기타 | java (기본값) |

**HARDCODED_SECRET / SECRET_EXPOSURE 자동 마스킹**:  
`:::expand` 블록 내 실제 자격증명 값을 자동으로 `[REDACTED]` 처리.  
마스킹 대상: `password=`, `secret=`, `token=`, 32자+ hex 문자열, UUID 형식, sk-proj- 토큰.

---

### 4.5 섹션 4 — 면책 사항

**생성 방식**: 고정 문자열 (모든 보고서 동일)

```
본 보고서는 자동화 스크립트 및 LLM AI 에이전트를 통한 1차 분석 후,
보안 진단 인력이 직접 검토한 결과입니다.
소스코드 정적 분석(SAST) 도구의 특성상, 인증/결제 로직의 결함이나
시스템 아키텍처 구조에 기인한 심층적인 취약점은 현재 보고서에 반영되지 않았으며,
해당 영역은 추후 별도의 동적 진단(DAST) 또는 아키텍처 리뷰를 통해 리포팅될 예정입니다.
...
```

---

## 5. 데이터 정제 함수 목록

보고서 생성 중 데이터 가공에 사용되는 주요 내부 함수.

| 함수 | 위치 | 역할 |
|---|---|---|
| `_clean_title(title)` | L169-199 | SCA 제목 재포맷, verbose suffix 제거 (위험도·건수·클래스명 괄호 등) |
| `_normalize_desc(text)` | L131-137 | 명사형 어미 → 합쇼체 변환 (`됨.`→`됩니다.`, `있음.`→`있습니다.` 등 12개 패턴) |
| `_recom_summary(recom)` | L542-575 | 조치 권고 첫 문장 추출, 80자 한도로 절단 |
| `_result_colored(result)` | L412-419 | `취약` → red 색상 마커, `정보` → orange 색상 마커 |
| `_sev_colored(sev)` | L104-113 | severity → 숫자(1~5) + Critical/High=red, Medium=주황 |
| `_split_desc_threat(desc)` | L421-429 | description을 현황(첫 문장)과 보안위협(나머지)으로 분리 (요약표 셀용) |
| `_to_relative_path(path)` | L317-323 | `testbed/<repo>/` prefix 제거 → 상대 경로 |
| `_sanitize_secret_expand(text)` | L711-729 | 자격증명 값 마스킹 (SECRET_EXPOSURE 카테고리 한정) |
| `_recom_for_confluence(text)` | L595-640 | 번호 목록 내 코드 블록을 인라인 백틱으로 변환 (Confluence `ol` 끊김 방지) |

---

## 6. AI 생성 vs 구조 데이터 구분

| 섹션 | 생성 주체 | 비고 |
|---|---|---|
| 1. 진단 개요 표 | 자동 (구조 데이터) | clone_info + review_meta 직접 삽입 |
| **2.1 취약점 개요** | **Claude CLI (AI)** | 유일한 자유 텍스트 자동 생성 구간 |
| 2.2 취약점 요약 표 | 자동 (구조 데이터) | findings[] 정렬·포맷팅 |
| 3. finding 메타 표 (결과·위험도·분류 등) | 자동 (구조 데이터) | |
| 3. description (설명) | **스캔 단계 LLM 생성** | `_normalize_desc()`로 어미만 정제 후 그대로 삽입 |
| 3. recommendation (조치 권고) | **스캔 단계 LLM 생성** | 번호 목록 형식 권장, 그대로 삽입 |
| 3. 증거 코드 | 자동 (구조 데이터) | `evidence.code_snippet` 그대로 삽입 |
| 3. :::expand 상세 검증 | **리뷰 단계 LLM 생성** | `/sec-review` 시 작성된 `report_expand` 또는 `review_note` |
| 3. Taint Flow expand | 자동 (구조 데이터) | `evidence.taint_flow / taint_evidence` 표로 렌더링 |
| 4. 면책 사항 | 고정 문자열 | 모든 보고서 동일 |

---

## 7. Jira 티켓 본문 구성

`approve_report.py` 가 게시 완료 후 jira-gateway로 MD 보고서를 POST하면, `converter.py`가 Jira Wiki markup으로 변환한다.

**변환 흐름**: MD → Jira Wiki markup (Markdown 헤더·표·코드블록 변환)

**Jira 본문 최종 구성**:

```
[섹션 1: 진단 개요 표]
  (Jira wiki 표 형식)
----
h2. [{color:red}*요청사항*{color}] 보안진단 결과 조치 및 티켓 처리 안내
  취약점 상세 내용: [위키 보고서|Confluence URL] 또는 첨부(pdf)

  {panel} 처리 안내 (5단계 고정 가이드)
  ┌─────────────────────────────────────────────────────────┐
  │ (1) 담당자가 아닐 경우 comment에 담당 매니저 기재       │
  │ (2) "조치시작" 상태 변경 + 조치기한 + 조치계획 comment  │
  │ (3) 예외처리: 보안진단 담당자와 협의 후 현업부서장 승인  │
  │ (4) 취약점 상세는 첨부 보고서 참조                      │
  │ (5) 조치 완료 시 "이행 점검 요청" 상태로 변경           │
  └─────────────────────────────────────────────────────────┘
----
[섹션 2: 취약점 요약 표]
  (조치계획 / 조치일자 빈 열 자동 추가)
----
h4. 참조 — 진단 절차
  !진단절차.png|width=900!   ← 이미지 첨부파일
```

**Confluence 보고서 vs Jira 티켓 포함 범위 비교**:

| 내용 | Confluence 위키 | Jira 티켓 |
|---|:---:|:---:|
| 섹션 1 진단 개요 | ✅ | ✅ |
| 섹션 2.1 취약점 개요 | ✅ | ✅ (섹션2 포함) |
| 섹션 2.2 요약 표 | ✅ | ✅ (조치계획·일자 열 추가) |
| 섹션 3 취약점 상세 + 코드 | ✅ | ❌ (링크만 제공) |
| 섹션 4 면책 사항 | ✅ | ❌ |
| 처리 안내 5단계 가이드 | ❌ | ✅ |
| 진단 절차 이미지 | ❌ | ✅ (첨부) |
| Confluence PDF | ❌ | ✅ (첨부) |

---

## 8. 보고서 생성 실행 명령어 참조

```bash
# 보고서 생성만 (Confluence 게시 없이)
python3 tools/approve_report.py --repo <repo> --run-id <RUN_ID>

# 보고서 생성 + Confluence 게시 + Jira 게이트웨이 전송 (전체)
python3 tools/approve_report.py --repo <repo> --run-id <RUN_ID> --publish

# SCA findings 제외 모드
python3 tools/approve_report.py --repo <repo> --run-id <RUN_ID> --publish --skip-sca

# /sec-review 미완료 상태 강제 통과 (긴급 시에만)
python3 tools/approve_report.py --repo <repo> --run-id <RUN_ID> --publish --force
```

**실행 순서 (approve_report.py 내부)**:
1. `/sec-review` 완료 여부 게이트 검증 (미판정 finding 존재 시 차단)
2. 오탐 판정 반영 (`review_status: "오탐"` → `result: "양호"` 변환)
3. `generate_report.py` → 1차 보고서 생성 + palantir-reports 커밋
4. `generate_final_report.py --publish` → 최종 보고서 + Confluence PUT
5. Jira 게이트웨이 POST (`/api/pending`)
6. `push_audit_result.py` → 진단 이력 업로드
7. `audit_utils.py` → vuln_registry / service_meta / audit_log 갱신

---

## 9. 주요 개선 포인트

### P0 — 담당자 표준화 자동화

**현황**: `last_commit_author` 를 raw 그대로 삽입 → `[SKP] 이름`, `1000690 <email>`, 외부 gmail 계정 등 형식 혼재  
**개선 방향**: clone 단계 또는 보고서 생성 단계에서 Jira API로 사번 조회 → `이름(영문)/팀/SKP/사번 <email>` 형식으로 자동 표준화

### P1 — 2.1 취약점 개요의 AI 문체 개선

**현황**: `claude -p` 로 생성된 2~3문장을 그대로 삽입. `"...이 발견되었습니다. ...에 노출될 수 있습니다. 조치가 필요합니다."` 패턴이 반복되어 AI 작성 티가 남.  
**개선 방향**: 프롬프트에 금지 패턴 예시 추가, 서비스 특징(`service_characteristics`)을 맥락으로 함께 전달, 생성 후 후처리 규칙 적용

### P2 — description / recommendation 원문 품질

**현황**: 스캔 단계에서 LLM이 생성한 문장이 보고서에 직접 노출됨. 명사 나열·짧고 기계적인 표현이 일부 잔존하며 `_normalize_desc()` (12개 어미 패턴)만으로는 한계가 있음.  
**개선 방향**: `finding_writing_guide.md` 의 작성 기준(현황+위협+평가 3단 구성, 구어체)이 스캔 단계 프롬프트에 더 엄격히 반영되도록 강화; 보고서 생성 시 재작성 후처리 단계 선택적 추가 검토

### P3 — 면책 사항 커스터마이징

**현황**: 모든 보고서에 동일한 고정 문자열 삽입  
**개선 방향**: `review_meta.json` 의 `additional_diagnosis_needed` 또는 서비스 유형(대외/대내)에 따라 동적으로 면책 문구 분기

### P4 — SCA 항목 보고서 표현 개선

**현황**: SCA CVE 제목이 `[SCA] group:artifact ver — CVE-XXXX-XXXX (설명)` 형식으로 raw하게 출력되는 경우가 있음. `_clean_title()` 이 처리하지만 포맷 불일치 시 그대로 노출됨.  
**개선 방향**: SCA 항목 전용 요약 표 분리 또는 CVE 원문 링크 추가

---

*palantir 보안진단팀 내부 문서 — 2026-06-26*
