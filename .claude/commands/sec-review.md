---
allowed-tools: Read, Glob, Grep, Bash, Edit, Write
description: 1차 보고서 오탐/정탐 인터랙티브 리뷰 — findings_*.json 내 각 finding을 순서대로 제시, 사용자 판정 입력 받아 review_status 기록
---

# Sec Review

인수: `$ARGUMENTS`  
형식 A: `<RUN_ID> <repo>` (예: `20260506_1430 ocb-webview-api`) — 공통 RUN_ID 모드  
형식 B: `<repo>` 만 (예: `ocb-webview-api`) — 레포 단위 모드 (skill별 최신 RUN_ID 자동 선택)

## 실행 절차

### 0. 인수 파싱

`$ARGUMENTS` 토큰을 분석한다:

- 토큰이 2개이고 첫 번째가 `YYYYMMDD_HHMM` 형식 → **RUN_ID 모드**: `run_id=토큰1`, `repo=토큰2`
- 토큰이 1개 → **레포 단위 모드**: `run_id=None`, `repo=토큰1`
- 토큰이 없으면 아래와 같이 안내하고 대기:

```
사용법:
  /sec-review <repo>                     # 레포 단위 모드 (레거시 state 데이터)
  /sec-review <RUN_ID> <repo>            # RUN_ID 모드 (새 파이프라인)
예시:
  /sec-review ocb-webview-api
  /sec-review 20260506_1430 ocb-webview-api
```

### 0b. Audit 세션 초기화

findings 수집 전, 아래 명령으로 리뷰 세션을 audit_log에 등록하고 SESSION_ID를 확보한다:

```bash
SESSION_ID=$(python3 tools/audit_utils.py init-session \
  --repo <repo> \
  [--run-id <run_id>])
```

- run_id가 없는 레포 단위 모드에서는 `--run-id` 인수 생략
- 출력된 SESSION_ID 문자열을 이 리뷰 세션 전체에서 사용한다
- 명령 실패 시 SESSION_ID="" 로 설정하고 리뷰를 계속 진행 (audit 기록은 생략됨)

### 0c. 판정 기준 파일 로드 ⚠️ 필수 — 세션 시작마다 반드시 실행

> **목적**: compact / 세션 중단 후 재실행 시에도 판정 기준이 컨텍스트 상위에 확보되도록 한다.
> 이 단계를 건너뛰면 기준이 MEMORY.md 한 줄 요약에만 의존하게 되어 엣지케이스 판단이 흔들린다.

아래 4개 파일을 Read 도구로 순서대로 읽는다:

1. `~/.claude/projects/-home-geunsolo-palantir/memory/feedback_conservative_security_policy.md`  
   → Proxy XSS / SQL `${}` / SpEL StandardEvaluationContext / 전역 XSS 필터 부재 → 입력 경로(또는 개별 XSS 확인 여부) 무관 취약/High
2. `~/.claude/projects/-home-geunsolo-palantir/memory/feedback_hardcoded_credential_severity.md`  
   → 운영 동일 자격증명=취약/High, 별도 자격증명=취약/Medium
3. `~/.claude/projects/-home-geunsolo-palantir/memory/feedback_log_dto_severity_standard.md`  
   → 운영LOG=취약/High, debugLOG=정보/Medium, @ToString=정보/Medium
4. `~/.claude/projects/-home-geunsolo-palantir/memory/feedback_severity_reporting_policy.md`  
   → Informational(위험도 1) finding → 리포팅 불필요, 정탐 처리 시 최소 Medium 이상

로드 후 아래 한 줄을 출력한다:
```
[기준 로드] 판정 기준 4개 파일 로드 완료 — conservative_policy / credential_severity / log_dto / severity_policy
```

### 0d. 세션 재개 감지 (compact / 세션 중단 후 재실행)

> **목적**: 이전 세션에서 리뷰가 진행된 상태로 재실행된 경우, 중단 지점부터 재개하고 판정 기준을 재확인한다.

Step 1 findings 수집 직후, `reviewed: true` 건수를 집계한다:

- **0건**: 신규 세션 → 정상 진행
- **1건 이상**: 이전 세션 중단 감지 → 아래를 출력하고 판정 기준 파일(0c)을 **재로드**한다

```
=== 이전 세션 재개 감지 ===
판정 완료  : {N}건 (정탐: {정탐수} / 오탐: {오탐수})
미판정 대기 : {M}건
판정 기준 재로드 완료 (0c 기준 파일 4개)
미판정 finding부터 리뷰를 재개합니다.
==========================
```

- 재로드 순서: 0c와 동일 (4개 파일을 다시 Read)
- 이미 `reviewed: true` 인 finding은 건너뜀, 미판정 finding부터 §4 진행

### 1. findings 수집

**RUN_ID 모드**: `state/<repo>/*/<RUN_ID>/findings_*.json` 패턴으로 수집.

**레포 단위 모드**: `state/<repo>/*/` 하위 모든 RUN_ID 디렉터리를 탐색하여
skill별로 RUN_ID 내림차순(최신) 파일 하나씩 선택:
- `state/<repo>/<skill>/*/findings_*.json` — skill별 최신 파일
- 수집 후 어떤 RUN_ID를 사용했는지 skill별로 출력

**SCA 스킬 제외**: `state/<repo>/sca/` 디렉터리는 수집 대상에서 제외한다 (SCA 진단은 별도 검증 후 진행 예정 — `feedback_sca_review_policy.md`에 따라 LLM-Check 완료 SCA는 `/sec-review` 건별 판정 없이 일괄 처리되는 유일한 승인된 예외).

**⚠️ 고정 순서 (필수)**: 파일시스템 glob은 알파벳순(`data, file, injection, xss`)으로 반환되지만, 이 순서를 그대로 쓰지 않는다. 수집 직후 skill별로 findings를 묶어 아래 고정 순서로 재정렬한다:

```
SKILL_ORDER = ["injection", "xss", "file", "data", "auth", "php", "sca"]
```

이 순서는 `tools/generate_final_report.py`의 `SKILL_ORDER` 상수와 동일하며, 최종 보고서 생성 시 이미 이 순서가 강제되므로 §2(개요 테이블)·§4(인터랙티브 판정)도 동일 순서를 따라야 보고서와 일관성이 유지된다. 0건인 skill은 순서상 건너뛴다.

#### 1a. Audit 정합성 검증 ⚠️ 필수 — `reviewed: true` 항목의 사람 판정 여부 확인

> **목적**: `reviewed`/`review_status`는 오직 본 skill(`/sec-review`) §4의 판정(사람 또는 자동, 어느 쪽이든 audit_log 기록 존재)에서만 부여되는 필드다.
> 그런데 스캔/LLM-Check 단계(예: 이전 세션의 수동 편집, 스킬 지시사항 오해 등)에서 이 필드가 audit 기록 없이 직접 기록되는 사고가 실제로 발생한 바 있다(2026-08-03 displayadmin_server XSS-001 사례 — §4 판정 없이 `reviewed:true`가 설정돼 리뷰를 거치지 않고 `approve_report.py`로 그대로 보고서에 반영됨).
> 이 필드를 맹목적으로 신뢰하면 §4를 실제로 거치지 않은 finding이 조용히 보고서에 포함될 수 있다.

수집된 finding 중 `reviewed: true` 인 항목 각각에 대해:

1. `state/audit_log.json`을 로드하여 `event_type == "finding_reviewed"` AND `repo == <repo>` AND `finding_id == <해당 finding_id>` 인 항목이 존재하는지 확인
2. **존재하지 않으면** → 이 finding은 §4 판정을 거친 적이 없는 것으로 간주하고, `reviewed: false` 인 것처럼 취급하여 리뷰 대상 목록에 **포함**시킨다 (JSON 파일 자체는 아직 수정하지 않음 — §4 판정 시 정상적으로 재확정 후 저장)
3. 아래와 같이 콘솔에 경고를 출력한다:
   ```
   [AUDIT GAP] {finding_id} — reviewed=true 이나 audit_log에 판정 기록 없음 → 리뷰 대상에 재포함
   ```
4. `event_type == "finding_reviewed"` 항목이 존재하면 정상적으로 §0d 재개 로직에 따라 건너뜀

각 파일에서 (위 1a 검증을 통과한) `reviewed` 가 `true` 가 아닌 finding 중 `result` 가 아래 **제외 목록에 없는** 항목을 리뷰 대상으로 추린다.

**제외 목록** (evidence_trail 전용 또는 정상): `"양호"`, `"양호(FP)"`, `"해당없음"`, `"safe"`

`"취약"`, `"정보"` 는 물론, 비표준 값(`"수동검토필요"`, `"정보(수동검토필요)"` 등 스캐너 버그로 발생)도 리뷰 대상에 포함한다.

> **참고**: 서비스 특징 분석 및 추가 진단(동적 진단/모의해킹) 필요 여부 판단은 §5d로 이동했다 — 모든 finding 판정과 review_note 작성이 끝난 뒤, 클렌징(§5e) 전에 진행한다 (근거: 판단 시점에 review_note·정탐 findings 상세를 참조해 PoC 가능성을 종합해야 하므로, finding 리뷰 전 단계에서는 근거가 부족하다).

#### 1b. 저영향 정보성 카테고리 자동 제외 ⚠️ §2 개요 출력 전 필수 실행

> **목적**: `state/audit_log.json` 767건 정탐/정보 판정 이력 분석 결과, 아래 3개 카테고리는
> 반복적으로 나타나지만 정탐 확정 사례가 없거나 극히 드물어 서비스 영향도가 낮다고
> 판단되었다(2026-09-08 사용자 명시적 지시, [[feedback_low_impact_category_exclusion]]).
> 이 카테고리에 매치되는 finding은 §2 개요/§4 인터랙티브 판정 대상에서 아예 제외하고
> 이 단계에서 즉시 자동 처리한다 — 리뷰어가 매번 반복적으로 오탐 처리하는 부담을 없앤다.

1a 검증을 통과한 리뷰 대상 finding 각각에 대해, 아래 3개 카테고리 매치 여부를 먼저 확인한다:

| # | 매치 조건 | 처리 |
|---|-----------|------|
| 1 | `category`가 `DTO_LOGGING`/`SENSITIVE_LOGGING` 계열이고 title/description/evidence에 `@ToString`, `ToString`, `Lombok`, `@Data` 중 하나가 포함 (즉 로그 노출이 아니라 Lombok이 생성한 toString()에 PII 필드가 포함되는 패턴) | 전체 제외 |
| 2 | `category == "SECURITY_HEADER"` 이거나 title/description에 `X-Frame-Options`, `CSP`, `Content-Security-Policy`, `HSTS`, `Strict-Transport-Security`, `X-Content-Type-Options`, `보안 헤더` 중 하나가 포함 | 전체 제외 |
| 3 | 파일 업로드 관련 finding(`category`가 `파일 업로드 취약점`/`FileProcessing/UPLOAD` 계열)이고 title/description/evidence가 MIME·매직바이트 검증 부재만을 지적 | **조건부 제외** — 아래 3-a/3-b 참조 |

**3번(MIME) 조건부 판정** — [[feedback_mime_validation_severity]]의 기존 구분을 그대로 적용:

- **3-a (제외 대상)**: evidence/description에 업로드된 파일이 실제로 실행되거나(웹쉘 등) 렌더링되는(브라우저에서 직접 열람 가능한 정적 경로로 그대로 서빙되는 등) 체이닝이 코드상 확인되지 **않는** 경우 → 전체 제외
- **3-b (제외하지 않음, 기존 취약/정탐 그대로 유지)**: 업로드 경로가 웹 루트 하위에 그대로 저장되어 직접 접근 가능하거나, 확장자 우회로 실행 가능한 경로에 저장되는 등 실행·렌더링 체이닝이 코드로 **확인되는** 경우 → 제외하지 않고 정상적으로 §2/§4 리뷰 대상에 포함(기존 severity 유지)

**매치된 finding(1/2/3-a) 처리 절차**:

1. 즉시 아래 값으로 확정한다 (사람 개입 없음):
   ```json
   {
     "reviewed": true,
     "review_status": "오탐",
     "review_result": "양호",
     "result": "양호",
     "review_note": "[AUTO-EXCLUDED-LOWIMPACT] 저영향 정보성 카테고리 자동 제외 — <매치된 조건 1/2/3-a 중 하나 명시>. 근거: feedback_low_impact_category_exclusion.md (2026-09-08 사용자 지시, audit_log 이력상 해당 카테고리 정탐 확정 사례 없음/극히 드묾)"
   }
   ```
2. `findings_*.json`에 즉시 저장한다.
3. §4c와 동일한 형식으로 audit_log에 기록한다:
   ```bash
   python3 tools/audit_utils.py log-review \
     --session-id  "$SESSION_ID" \
     --repo        "<repo>" \
     --run-id      "<run_id>" \
     --skill       "<skill>" \
     --finding-id  "<finding_id>" \
     --finding-title "<title>" \
     --scan-severity "<판정전_원본_severity>" \
     --scan-result   "<판정전_원본_result>" \
     --decision    "오탐" \
     --decided-by  "rule" \
     --review-result "양호" \
     --review-note "<위 review_note 그대로>"
   ```
4. 이 finding은 §2 개요 테이블과 §4 인터랙티브 판정 순회 대상에서 **제외**한다 (목록에 아예 나타나지 않음).

**1b 처리 완료 후 콘솔 출력** (코드펜스로 감싸서 출력):

```text
[LOWIMPACT-AUTO] 저영향 카테고리 자동 제외: {N}건
  - ToString/Lombok PII 노출     : {n1}건
  - 보안 헤더 부재                : {n2}건
  - MIME 검증 부재(체이닝 미확인)  : {n3}건
남은 리뷰 대상: {M}건 (§2/§4 진행)
```

매치되는 finding이 0건이면 이 출력 자체를 생략한다.

### 2. 전체 취약점 개요 출력

리뷰 시작 전, 수집된 모든 finding을 아래 형식의 테이블로 **한 번에** 출력한다.
finding은 §1의 SKILL_ORDER(`injection > xss > file > data > auth > php > sca`) 순서로 나열한다.

> **⚠️ 렌더링 필수 규칙**: 아래 `=== ... ===` 배너와 `----+-----+...` 구분선을 실제 채팅 응답으로 출력할 때는
> 반드시 ` ```text ` ~ ` ``` ` 코드펜스로 감싼 채로 출력한다. 감싸지 않으면 CommonMark가 `----` 구분선을
> 직전 줄의 Setext 헤딩(H1/H2)으로 오인식하여 글씨가 비정상적으로 커지는 렌더링 오류가 발생한다
> (2026-07-24, 2026-08-11, 2026-08-13 총 3회 재발 확인됨). 이 규칙은 §2/§3/§4 및 본 문서의 모든
> `=== ... ===` 콘솔 블록에 동일하게 적용된다.

```
=== 리뷰 대상 전체 목록 ===
레포   : <repo>
대상   : <N>건

 #  | 분류      | ID               | 결과   | 위험도   | 제목 요약
----+-----------+------------------+--------+----------+-----------------------------------------------------
  1 | injection | INJ-001          | 취약   | High     | SQL Injection — userInfo 조회 파라미터 미검증
  2 | xss       | XSS-AUTO-009     | 취약   | High     | Persistent XSS — 댓글/피드 DB 저장 API 다수
...
===========================================================
```

- 제목 요약은 `title` 필드 그대로 사용 (60자 초과 시 말줄임)
- `결과` 컬럼: `result` 필드값 그대로 출력 (취약/정보 등)
- `result` 가 비표준 값(`수동검토필요` 등)이면 결과 컬럼에 `[수동검토]` 표기
- 이미 `reviewed: true` 인 항목은 목록에서 제외 (판정 완료 건은 별도 집계만)

### 3. 리뷰 시작 안내

> **⚠️ 렌더링 필수 규칙**: §2와 동일 — 아래 블록을 ` ```text ` 코드펜스로 감싸서 출력한다.

```text
=== 오탐/정탐 자동 리뷰 ===
RUN_ID : <RUN_ID>
레포   : <repo>
대상   : <N>건 (취약/정보/수동검토필요 판정 findings)

각 finding은 판정 기준 파일(0c) 우선 매치 → 과거 판정 이력(judgment_lookup.py)
조회 순으로 사람 개입 없이 자동 판정된다. 유사 이력이 없거나(confidence: none),
저신뢰(low) 하향 판단이거나, 저신뢰 상향 판단인데 precedent 전제조건이
현재 finding과 불일치/불확실한 경우는 보수적 기본값(정탐 유지)으로 처리되고
review_note에 [AUTO-LOWCONF]로 플래그된다 — 사후 표본 점검용.

판정 완료 후 클렌징 및 approve_report.py 게시까지 자동으로 이어서 진행한다.
===================================
```

> **인터랙션 방식**: 2026-09-01부로 §4/§5d는 `AskUserQuestion` 등 사람에게 묻는 어떤 호출도 사용하지 않는다 — 아래 §4/§5d에 명시된 자동 판정 로직만으로 끝까지 진행한다.

### 4. finding별 자동 판정

finding은 §1의 SKILL_ORDER(`injection > xss > file > data > auth > php > sca`) 순서로, 동일 skill 내에서는 파일 내 등장 순서로 순회한다. 임의로 알파벳순이나 심각도순으로 재정렬하지 않는다.

각 finding을 아래 형식으로 제시한다 (` ```text ` 코드펜스로 감싼다):

```text
[{순번}/{전체}] {skill} — {finding_id}
위험도 : {severity}
제목   : {title}
위치   : {scope.affected_file}:{scope.affected_line}  (또는 scope.endpoint)
설명   : {description} (첫 200자)
증거   : {evidence.snippet} (첫 300자, 있을 경우)
```

제시 직후, **사람에게 묻지 않고** 아래 순서로 판정을 확정한다. 모든 finding은 예외 없이 `reviewed: true`로 종결된다 — "스킵"/"종료" 개념은 없다.

#### 판정 절차

**1단계 — 판정 기준 파일 우선 매치**

0c에서 로드한 4개 판정 기준 파일의 조건에 finding의 category/evidence/scope가 명시적으로 해당하면 그 규칙을 즉시 적용한다 (2단계 조회 불필요):

- `feedback_conservative_security_policy.md`: SQL `${}` 삽입, SpEL StandardEvaluationContext, Proxy XSS, 전역 XSS 필터 부재 → `review_status: "정탐"`, `severity: "High"` (개별 XSS 확인 여부 무관)
- `feedback_hardcoded_credential_severity.md`: 하드코딩 자격증명 — 운영 동일 → `severity: "High"`, 별도 자격증명 → `severity: "Medium"` (Critical 상한 없음)
- `feedback_log_dto_severity_standard.md`: 운영 LOG PII 노출 → `severity: "High"`, debug LOG/`@ToString` → `review_result: "정보"`, `severity: "Medium"`
- `feedback_severity_reporting_policy.md`: 정탐 처리 시 **최종 `review_result`가 `"정보"`이면서 `severity`가 `Low`/`Informational`인 경우** (스캐너 원판정 라벨이 무엇이었든) `"Medium"`으로 상향 — 문자열이 정확히 `"Informational"`인 경우만 좁게 보지 말 것(2026-09-04 locker-webview-front XSS-004: 원판정 `severity: "Low"`라 이 규칙이 누락된 사례 발생, [[project_severity_floor_pipeline_fix_20260904]])

규칙 매치로 판정한 경우 §4c 기록 시 `decided_by: "rule"` 사용.

**2단계 — 규칙 미매치 시 과거 판정 이력 조회**

finding 객체를 임시 JSON(`/tmp/<finding_id>.json` 등, 세션 스크래치 경로 사용)으로 저장한 뒤 호출:

```bash
python3 tools/judgment_lookup.py --finding-json /tmp/<finding_id>.json --top-k 3
```

반환된 `matches[]`(각 `precedent_id`/`score`/`decision`/`review_result`/`severity_after`/`review_note`/`precedent_count`)와 `confidence`(`high`/`low`/`none`)를 아래 기준으로 적용한다. `precedent_count`는 해당 precedent가 (2026-09-08부터) `state/precedent_index.json` 압축 배치로 대표되는 클러스터 내 발생 건수 — 판정 채택 시 review_note에 "과거 유사 판정 N건 대표 사례" 형태로 근거를 덧붙이는 데 참고한다(N=1이면 압축 미반영 최신 raw 건).

| 판단 방향 | 조건 | 적용 |
|---|---|---|
| 위험도를 **낮춤** (오탐 판정, 또는 severity/result 하향) | `confidence == "high"` | top match의 `review_status`/`severity_after`를 채택 |
| 위험도를 낮춤 | `confidence`가 `low`/`none` | **적용 안 함** → 3단계 보수적 기본값으로 폴백 |
| 위험도를 **유지·상향** (정탐 유지, severity 상향 등) | `confidence == "high"` | top match 판정을 그대로 적용 |
| 위험도를 유지·상향 | `confidence == "low"` | 아래 **전제조건 검증** 통과 시에만 채택 — 실패/불확실 시 3단계 폴백 |
| (모든 방향) | `confidence == "none"` | **적용 안 함** → 3단계 보수적 기본값으로 폴백 (방향 무관 예외 없음) |

> **근거 (2026-09-01 leave-one-out 검증, 1,064건 중 25건 표본)**: `high` confidence 판정 일치율 11/12(92%)로 신뢰할 만한 반면, `low` 5/9(56%)·`none` 2/4(50%)는 사실상 동전 던지기 수준이었다. `low` confidence는 방향에 관계없이 무조건 신뢰할 근거가 없으므로, "유지·상향" 방향이라 해도 confidence만으로 자동 채택하지 않고 아래 전제조건 검증을 거친다.

**전제조건 검증** (위험도 유지·상향 + `confidence == "low"`인 경우에만 수행):

`judgment_lookup.py`는 표면적 텍스트 유사도만 계산하므로, top match가 실제로는 현재 finding과 상반되는 전제 위에서 내려진 판정일 수 있다 (예: precedent는 "운영 빌드에 drop_console 설정이 전혀 없어 상시 노출"을 근거로 severity를 올렸는데, 현재 finding은 `drop_console: isProd`처럼 운영 빌드에서 실제로 제거되는 구조 — 키워드는 겹치지만 결론을 뒤집는 조건이 반대인 사례가 실제로 발생함, 2026-09-01 locker-webview DATA-001 사례).

1. top match의 `review_note`에서 판정을 좌우한 핵심 조건 문장을 식별한다 (보통 "~이므로", "~하여 운영에서도" 류의 인과 서술).
2. 현재 finding의 `description`/`evidence.code_snippet`/`scope`에서 그 조건이 실제로 성립하는지 확인한다 — 필요시 `testbed/<repo>/` 관련 설정 파일(빌드 설정, 환경 분기 등)을 Read/Grep으로 직접 대조한다.
3. **조건이 명백히 상반됨** (precedent 근거의 반대 사실이 확인됨) → 채택하지 않고 3단계로 폴백, review_note에 "정밀 매치 실패 — 전제조건 불일치: <구체적 반대 사실>" 기록.
4. **조건이 명백히 일치함** (같은 전제가 현재 finding에도 성립) → 채택.
5. **코드/설명만으로 성립 여부를 판단할 수 없음** (불확실) → 채택하지 않고 3단계로 폴백 (불확실하면 보수적으로 처리).

채택 시(2단계 `high`, 또는 `low`+전제조건 검증 통과) `review_note`에는 precedent 원문을 복붙하지 않고 `precedent_id`만 인용해 근거를 서술한다 (예: `"과거 유사 판정(ocb-joy-api/DATA-003, score 0.62) 참조 — debug 로그 PII 노출로 정보/Medium 처리"`). §4c 기록 시 `decided_by: "auto"`, `auto_confidence: "<반환된 confidence>"`, `precedent_finding_ids: ["<채택한 precedent_id>", ...]`.

**3단계 — 매치 없음 / 저신뢰 시 보수적 기본값**

`confidence: "none"`이거나, 하향 판단인데 `confidence: "low"`이거나, 유지·상향 판단인데 `confidence: "low"`이면서 전제조건 검증에 실패했거나 불확실한 경우:

- `review_status: "정탐"` 유지 (스캐너 원본 판정 그대로, 자동 오탐 처리 금지)
- `severity`: 스캐너 원본값 유지 — 단 최종 `review_result`가 `"정보"`이면서 `severity`가 `Low`/`Informational`이면 `feedback_severity_reporting_policy.md`에 따라 `"Medium"`으로 상향(아래 공통 처리 참조)
- `review_note` 맨 앞에 `"[AUTO-LOWCONF] 유사 판정 이력 없음 — 수동 검토 권장: <finding 핵심 설명 1문장>"` 기록
- §4c 기록 시 `decided_by: "auto"`, `auto_confidence: "<none 또는 low>"`, `precedent_finding_ids: []` (저신뢰 매치가 있었으면 참고용으로 top match id만 기록해도 무방)

#### 공통 처리

- 모든 finding은 `reviewed: true`로 설정된다 (미판정/스킵 없음)
- `review_result`(`"취약"`/`"정보"`)는 1~3단계 판정에 값이 포함돼 있으면 그 값을, 없으면 스캔값을 그대로 유지
- **조치 불필요/감사기록성 finding → 오탐(양호) 처리, 리포팅 대상 아님 (2026-09-08 추가)**: 1~3단계 판정 결과 `review_result: "정보"`로 확정되었더라도, 최종 확정 전 아래 두 조건을 모두 만족하는지 확인한다 — 만족하면 `review_status: "오탐"`, `result: "양호"`로 재분류하고 보고서에서 제외한다 (severity 최저기준 적용 대상에서도 제외).
  - **조건①**: `description`/`recommendation`이 명시적으로 "조치 불필요"/"해당없음"/"○○ 관점에서는 성립하지 않음"으로 결론 나 있어, 리포트를 받는 개발팀이 이 finding 자체로는 실제로 취할 조치가 없음.
  - **조건②**: 그 근본 원인(대개 동일 파라미터/동일 입력 경로)이 이미 **다른 정탐 finding**(예: 같은 파라미터의 Persistent XSS)으로 완전히 커버되어, 이 finding이 남아 있어도 새로 드러나는 조치 항목이 없음(순수 중복).
  - 두 조건 중 하나라도 미충족(예: "HTTP 직렬화 경로 재확인 필요"처럼 확인 액션이 남아 있거나, 다른 정탐 finding과 연결되지 않는 독자적 발견)이면 이 규칙 적용 대상이 아니며 기존 §4 절차대로 정보/Medium으로 유지한다.
  - `review_note`에는 감사 추적을 위해 "무엇을 검토했는지 + 왜 해당없음인지 + 관련 정탐 finding_id"를 남긴다(예: `"View XSS 관점 41건 수동확인 완료, HTML 렌더링 경로 없어 해당없음 확인 — 동일 파라미터는 XSS-002(Persistent, 정탐)로 이미 커버되어 별도 조치 없음. 오탐 처리."`).
  - **근거 (2026-09-08 ocbfds XSS-004)**: `@Controller` POST 41개 엔드포인트를 View XSS 관점에서 수동확인해 "HTML 렌더링 경로 없음 → View XSS 해당없음, 조치 불필요"로 결론지었으나 동일 파라미터가 이미 XSS-002(Persistent XSS)로 정탐 처리돼 있어, 이 finding을 정보/Medium으로 남겨봐야 개발팀이 추가로 할 일이 없었다. 사용자가 "실제 조치가 필요한 finding만 리포팅"이 원칙임을 명시 — `feedback_severity_reporting_policy.md`(Informational 라벨 → 오탐 처리 권장)의 취지를 "라벨이 Informational인 경우"에서 "실질적으로 조치 불필요한 모든 경우"로 일반화한 것.
- **severity 최저기준 강제 (1~3단계 결정 경로 무관, 반드시 마지막에 재확인)**: 위 판정 절차 결과 확정된 `review_result`가 `"정보"`인데 `severity`가 `Low` 또는 `Informational`이면, 어느 단계(1/2/3단계)에서 그 값이 나왔든 관계없이 `severity: "Medium"`으로 강제 상향한다. `feedback_severity_reporting_policy.md`의 기준은 원래 스캐너 라벨이 정확히 `"Informational"`인 경우로 좁게 해석하지 않는다 — "정보성 결과는 Medium 미만으로 보고하지 않는다"는 것이 규칙의 본질이다. (이 단계를 건너뛰어 `severity: "Low"` + `review_result: "정보"` 조합이 그대로 남는 사고가 2026-09-04 locker-webview-front XSS-004에서 실제 발생 — `tools/approve_report.py`의 `apply_review_results()`에도 동일 로직이 결정론적 백스톱으로 추가돼 있으나, 여기서 먼저 잡는 것이 원칙)
- severity 변경 시 review_note 맨 앞에 `"위험도 {이전} → {이후} 조정"`을 근거 서술 앞에 추가 기록 (위 최저기준 강제로 인한 변경은 `"위험도 {이전} → Medium 조정(정보성 결과 하한 적용)"`으로 명시)
- **§4a 지시사항 자동 실행** 적용 후 최종 `review_note` 확정 (아래 그대로 유지)

#### §4a. review_note 지시사항 자동 실행

정탐 판정 시 입력한 `draft_note`(또는 기존 JSON에 이미 저장된 review_note)에 **지시사항 패턴**이 감지되면,  
즉시 `testbed/<repo>/` codebase를 탐색하여 실제 데이터로 교체한다.  
보고서에 지시사항 원문이 그대로 노출되는 것을 방지하기 위한 필수 절차다.

**지시사항으로 분류되는 패턴** (아래 중 하나라도 해당하면 자동 실행 트리거):

- `목록화 필요`, `나열 필요`, `파일 명시 필수`, `API 명시 필수`, `endpoint 명시`
- `N개 [클래스|항목|파일|API] [목록|나열|정리]` — 숫자+개 패턴 뒤에 목록/나열 키워드
- `표로 정리`, `테이블 생성`, `목록 포함 필요`, `함께 보고서 명시`
- **단, `| ... |` 마크다운 표 행이 1개 이상 포함되어 있으면 이미 실행된 것으로 간주 → 실행 생략**

**자동 실행 절차**:

1. finding의 `category` 및 `scope` 필드를 기반으로 적절한 codebase 탐색을 실행한다:

   | category 패턴 | 실행 방법 |
   |---------------|----------|
   | `LOGGING/PII` | `Grep`으로 `testbed/<repo>/` 내 `logger\.\(debug\|info\|warn\|error\|fatal\).*\(mbrId\|userId\|email\|passwd\|phone\|ci\|token\)` 패턴 탐색 → 파일·라인·로그레벨·필드별 마크다운 표 생성 |
   | `DTO_LOGGING` 또는 `@ToString` 관련 | `Bash`로 `grep -rln "@Data\|@ToString"` 실행 후 Python 클래스 경계 파싱으로 PII 필드 포함 클래스 추출 → 클래스명·파일·PII필드 표 생성 |
   | `FileProcessing/UPLOAD` | `Read`로 `scope.file` 확인 → Controller/Service에서 `@PostMapping`/`@RequestMapping` endpoint 추출, 정확한 파일·라인·API 표기 |
   | 기타 | `scope.file`을 `Read` (affected_line ±40줄) → 지시사항 내용을 코드 레벨 분석으로 충족하는 실제 데이터 구성 |

2. 실제 데이터를 마크다운 형식으로 구성한다:
   - 기존 평문 메모(지시사항 제외 부분)가 있으면 앞에 유지
   - 실제 데이터는 `## <섹션 제목>` 헤더로 시작
   - 가능하면 마크다운 표(`| 열1 | 열2 |`) 형식 사용

3. 최종 `review_note = 구성된 실제 내용` 으로 교체하여 JSON에 저장

4. 콘솔에 `[자동실행] review_note — 지시사항 → 실제 콘텐츠 교체 완료` 출력

**예시 — 변환 전/후**:

```
변환 전: "보고서에 API 명시 필수. 확장자 화이트리스트 존재하나 MIME 검증 없음."

변환 후: "확장자 화이트리스트 존재하나 MIME 검증 없음.

## API 및 검증 현황
| API | 파일 | 라인 | 검증 방식 |
|-----|------|------|----------|
| POST /file/upload | FileUploadService.java | 41 | 확장자 whitelist만, MIME 없음 |"
```

```
변환 전: "debug 로그 PII 노출 — 목록화 필요"

변환 후: "## 노출 파일 및 라인별 PII 상세 (debug 레벨)
| 파일 | 라인 | 노출 파라미터 | 비고 |
|------|------|--------------|------|
| UserService.java | 123 | userId, email | ⚠️ PII 평문 노출 |
..."
```

#### §4c. Audit 판정 기록

**log-review 실행 시점: §4a 자동 실행(소스 탐색 및 review_note 교체) 완료 후, findings_*.json 저장 직후.**

사용자가 간단한 메모만 입력했더라도 §4a가 코드베이스를 탐색하여 내용을 교체·보강했다면, log-review에는 반드시 **교체 완료 후 파일에 실제로 저장된 값**을 기록한다. 원본 메모(입력 당시 초안)가 아닌 최종 상태가 기준이다.

##### finding별 §4a 완료 후 기록

정탐/오탐 판정 → (§4a 지시사항 자동 실행 → review_note 교체) → findings_*.json 저장 → **log-review 실행**:

```bash
python3 tools/audit_utils.py log-review \
  --session-id  "$SESSION_ID" \
  --repo        "<repo>" \
  --run-id      "<run_id>" \
  --skill       "<skill>" \
  --finding-id  "<finding_id>" \
  --finding-title "<title>" \
  --scan-severity "<scan_severity_판정전_원본>" \
  --scan-result   "<scan_result_판정전_원본>" \
  --decision    "<정탐|오탐>" \
  --decided-by  "<rule|auto>" \
  [--auto-confidence "<high|low|none>"] \
  [--precedent-finding-ids '["<repo>/<finding_id>", ...]'] \
  [--review-result   "<취약|정보>"] \
  [--severity-before "<old_severity>"] \
  [--severity-after  "<new_severity>"] \
  [--review-note     "<findings_*.json에_저장된_최종_review_note>"] \
  [--code-analysis   "<§4a_탐색_및_교체_내용_요약>"]
```

인수 매핑 규칙:

| 인수 | 값 출처 | 주의 |
|------|---------|------|
| `--scan-severity` | 판정 **전** finding의 `severity` 원본값 | 위험도 조정 전 스냅샷 |
| `--scan-result` | 판정 **전** finding의 `result` 원본값 | |
| `--decision` | §4 자동 판정 결과 (정탐/오탐) | |
| `--decided-by` | §4 1단계 매치면 `rule`, 2~3단계(조회 도구 경유)면 `auto` | 사람 판정은 더 이상 발생하지 않음(`--decided-by human`은 다른 skill의 레거시 호출 하위호환용 기본값) |
| `--auto-confidence` | `decided-by auto`일 때 `judgment_lookup.py`가 반환한 `confidence` | `rule`이면 생략 가능 |
| `--precedent-finding-ids` | 2단계에서 채택한 precedent의 `precedent_id` 배열 | 3단계 보수적 기본값이면 `[]` 또는 참고용 top match id |
| `--review-result` | 정탐 후 결과 판정값 (`취약`/`정보`) | |
| `--severity-before` | 위험도 조정 전 severity (변경한 경우만) | |
| `--severity-after` | 위험도 조정 후 severity (변경한 경우만) | |
| `--review-note` | **findings_*.json에 최종 저장된 `review_note` 전체** | §4a 교체 후 값, `[AUTO-LOWCONF]` 플래그 포함 시 그대로 |
| `--code-analysis` | §4a가 수행한 탐색·교체 내용 요약 | 어떤 패턴을 탐색했는지, 몇 건을 발견했는지, 메모를 어떻게 보강했는지 1~3문장으로 기술 |

**`--code-analysis` 작성 기준** — §4a가 실행된 경우, 아래 내용을 포함한다:

- 탐색 대상 파일/패턴 (예: `grep -rn "logger.*mbrId" testbed/<repo>/`)
- 발견 건수 및 핵심 결과 (예: "17개 파일, 42줄에서 PII 로그 확인")
- review_note 교체 여부 및 교체 전/후 요약 (예: "원본: '목록화 필요' → 교체: 파일·라인·PII필드 표 42행 생성")
- §4a가 트리거되지 않았거나 소스를 찾지 못한 경우: `""` (빈 문자열)로 전달

### 5. 저장 형식

finding 객체에 아래 필드를 추가/갱신한다:

```json
{
  "reviewed": true,
  "review_status": "정탐",   // "정탐" | "오탐"
  "review_result": "취약",   // "취약" | "정보" — 정탐 시 리뷰어가 확정한 결과 (Enter 스킵 시 필드 없음)
  "review_note": ""          // 메모 / 오탐 사유 (빈 문자열 허용)
}
```

`reviewed: false` 인 스킵 건은 필드 변경 없이 원본 유지.  
판정 후 해당 finding을 `findings_*.json` 에 즉시 업데이트 (전체 파일 재쓰기).

#### review_note 보고서 반영 규칙

`review_note` 에 기록된 내용은 `generate_final_report.py` 가 Confluence 보고서의
**"상세 검증 결과 (코드 직접 확인)" `:::expand` 블록**에 포함한다.

- **평문 메모** (예: `"보고서에 API 명시 필수. 확장자 화이트리스트 존재"`) → 그대로 expand 블록에 출력
- **`## ` 마크다운 헤더 포함 시** → 첫 `## ` 헤더부터 이후 내용만 추출 (헤더 앞 내부 메타 주석 제거)
> 보고서에 특정 지시사항을 남기려면 review_note 메모에 평문으로 작성하면 된다.  
> 단, 오탐 판정 finding(`review_status: "오탐"`)은 `result` 가 `"양호"` 로 변경되어  
> 보고서 본문에서 제외되므로 review_note 도 출력되지 않는다.

> `HARDCODED_SECRET` / `SECRET_EXPOSURE` 카테고리도 review_note 는 정상 반영된다.  
> review_note 에 실제 credential 원문을 직접 쓰지 않도록 주의 — 파일 경로·키 이름은 포함 가능.

#### 위험도(severity) 상향/하향

정탐 판정 시 결과 판정 직후 **위험도 조정 프롬프트**가 자동 출력된다 (§4 입력 분기 참조).  
severity 허용 값: `"Critical"` / `"High"` / `"Medium"` / `"Low"` / `"Informational"`

자유 텍스트(의견/질문) 입력 흐름에서도 사용자가 위험도 변경 의도를 표명하면 즉시 `findings_*.json` 의 `severity` 필드를 갱신하고 review_note 에 사유를 기록한다.

#### 보고서 내 표(Table) 작성

**review_note 만으로는 표가 자동 생성되지 않는다.** 보고서 expand 블록에 표를 넣으려면 review_note 에 마크다운 표를 직접 작성해야 한다.

```
"review_note": "노출 파일 및 파라미터 목록:\n\n| 파일 | 노출 파라미터 |\n|------|----------------|\n| UserController.java | mbrId, email |\n| OrderService.java | phone |"
```

사용자가 "목록화 필요", "표로 정리" 등을 요청하면 해당 데이터를 마크다운 표로 직접 구성하여 review_note 에 포함시킨다.

### 5a. 그룹병합 검토 (동일 유형 finding 병합) ⚠️ 필수 — §4 전체 판정 완료 후, §5b 이전에 실행

> **목적**: 같은 취약점 유형이 파일/클래스별로 과도하게 쪼개져 보고서 finding 수가 부풀려지는 것을 방지한다.
> §5b(report_expand 생성)보다 먼저 실행해야 병합으로 제외될 finding에 불필요한 expand를 생성하는 낭비가 없다.
> 상세 근거·사례: `feedback_finding_group_merge_policy.md`.

**1단계 — 병합 후보 기계적 스캔**: `reviewed: true` + `review_status: "정탐"` finding을 두 기준으로 groupby한다.

- **같은 파일/클래스 병합 (기본, 전 카테고리 적용)**: `scope.file`(정확히 동일한 파일 경로) 기준 2건 이상
- **파일 간(cross-file) 동일유형 병합 (파일럿 카테고리 한정)**: 아래 2개 카테고리만, `category` + `severity`가 모두 동일한 경우 파일이 달라도 후보
  - `HARDCODED_SECRET` (설정파일 자격증명 하드코딩, env별)
  - `DTO_EXPOSURE` (Lombok `@ToString`/`@Data` PII 필드 노출)

**2단계 — 병합 경계 재확인**: 후보로 묶인 finding들의 `severity`가 모두 같은지 재확인한다. 하나라도 다르면(예: prod=High vs dev=Medium) 그 severity 경계로 그룹을 쪼갠다 — 같은 파일/카테고리라도 severity가 다르면 병합하지 않는다.

**3단계 — 병합 실행**: 후보 그룹마다 `finding_id`가 가장 앞선(사전순/번호순) finding을 대표(primary)로 선택하고 아래와 같이 갱신한다.

- **primary**: `title`/`description`/`scope.file`/`recommendation`을 병합된 전체 대상을 아우르도록 재작성하고, `group_members` 필드(흡수되는 각 finding의 `finding_id`/`file`/`line`/`summary` 배열)를 추가한다. 이미 흡수되는 finding이 자신만의 `group_members`(같은 파일 내 병합)를 갖고 있다면 flatten하여 primary에 직접 포함시킨다(체인 금지). `review_result`/`result`는 병합 전 값 그대로 유지한다(병합은 판정을 바꾸지 않는다).
- **report_expand**: primary의 `report_expand`를 직접 작성해 "## 병합된 동일 유형 발생 위치" 마크다운 표를 포함시킨다. 컬럼은 `finding | 파일 | 라인 | 대상` 이 기본이며, `DTO_EXPOSURE`처럼 `code_snippet`/코드 스니펫이 있는 카테고리는 `finding | 파일 | 라인 | 노출 필드 | 코드`로 확장한다. 원본 finding이 이미 여러 클래스/필드를 내부적으로 묶고 있었다면(예: "(N클래스 병합)" 제목), 표는 그 finding_id를 반복 표기하며 클래스/필드 단위로 행을 쪼개 실제 파일·메소드가 모두 드러나도록 한다 — primary의 `group_members`가 finding 단위 요약이어도 report_expand 표는 반드시 파일/클래스 단위 세부 목록이어야 한다(사용자가 "관련 파일·메소드 나열"을 최종 산출물로 기대함).
- **흡수되는(absorbed) finding**: `review_status: "그룹병합"`, `result: "양호"`, `group_primary_id: "<primary finding_id>"`, `review_note: "<primary id>(동일 유형 finding 대표 — 파일 간/동일 파일 병합)에 병합됨. 개별 판정 근거는 기존과 동일, 보고서 표시 단위만 통합."` 로 갱신한다. `review_result`는 변경하지 않는다(내부 판정 이력 보존, `result` 필드만 보고서 제외 트리거로 사용).
- 별도의 audit_utils.py 로그는 남기지 않는다 — 병합 대상 finding들은 이미 §4c에서 개별 판정이 audit_log에 기록되어 있고, 병합은 새로운 판정이 아니라 보고서 표시 단위 재구성이기 때문이다(2026-09 gws-user-be-api/oki-be/ocbfds 선례와 동일).

**4단계** — 병합 완료 후 findings_*.json 저장, 콘솔에 `[그룹병합] {primary_id} ← {absorbed_ids} ({N}개 파일/클래스 통합)` 출력.

**주의**: `HARDCODED_SECRET`/`DTO_EXPOSURE` 외 카테고리에서 파일 간 병합이 필요해 보이는 사례를 발견하면, 임의로 확장 적용하지 말고 우선 같은 파일/클래스 병합만 적용한 뒤 사용자에게 카테고리 확장 여부를 확인한다.

### 5b. Phase 2 — 보고서 expand 초안 자동 생성 (agent-driven)

**모든 finding 판정 완료 후** (또는 사용자가 `r`을 입력하면 즉시) 아래 Phase 2를 실행한다.

Phase 2는 `reviewed: true` + `review_status: "정탐"` 인 모든 finding에 대해 **`report_expand` 필드를 생성·저장**한다.  
`report_expand`는 `generate_final_report.py`가 Confluence `:::expand 상세 검증 결과 (코드 직접 확인)` 블록에 직접 사용하는 보고서용 콘텐츠다. 내부 메모가 아닌 **외부 공개 가능한 기술 분석 내용**이어야 한다.

**Phase 2 실행 전 판정 기준 재로드 ⚠️ 필수**

> Phase 1 §4 전체 판정 + §4a 소스코드 누적으로 컨텍스트가 길어진 상태에서 Phase 2를 시작한다.
> 이 시점에 기준 파일을 재로드하지 않으면 report_expand 서술이 판정 기준과 달라질 수 있다.

0c의 4개 파일을 **다시 Read**한다:
1. `feedback_conservative_security_policy.md` — Proxy XSS/SQL ${}/SpEL/전역 XSS 필터 부재 기준
2. `feedback_hardcoded_credential_severity.md` — prod/dev 크레덴셜 기준
3. `feedback_log_dto_severity_standard.md` — 운영LOG=High/debugLOG=Medium
4. `feedback_severity_reporting_policy.md` — 정보성 결과(review_result: "정보")는 severity 라벨(Informational/Low) 무관 최소 Medium

재로드 후 출력:
```
[P2 기준 재로드] 판정 기준 4개 파일 재로드 완료
=== Phase 2: 보고서 expand 초안 생성 ===
대상: {N}건 (reviewed=true, 정탐)
각 finding에 대해 코드 직접 확인 후 report_expand 생성
===
```

각 finding에 대해 순서대로 처리:

1. **컨텍스트 수집**:
   - finding 전체 필드(title, severity, description, scope, category, code_snippet, review_note) 읽기
   - `testbed/<repo>/<scope.file>` 을 Read 도구로 읽기 (affected_line ±30줄)
   - 파일이 없으면 `code_snippet` 만으로 진행
   - 필요 시 Grep으로 연관 패턴 추가 탐색

   > **⚠️ 주의 — 인접 취약점 혼입 금지 (2026-09-04 locker-server DATA-008 사고)**:
   > ±30줄 범위나 Grep 결과에 **현재 finding의 `category`와 무관한 별도 취약점**(예: 현재
   > finding은 `WEAK_CRYPTO`/해시 오용인데 같은 파일 인근에 하드코딩 API 키·시크릿이
   > 우연히 존재하는 경우)이 눈에 띄어도, 그 내용을 **이 finding의 `report_expand`에
   > 절대 섞지 않는다**. 같은 파일 안에 서로 다른 종류의 코드가 인접해 있으면
   > (특히 광고/외부 연동 서비스처럼 인증키+해시 로직이 한 클래스에 몰려 있는 경우)
   > 더 "눈에 띄는" 패턴 쪽으로 서술이 흘러가 전혀 다른 finding의 내용을 작성하는
   > 사고가 실제로 발생했다. 별도 취약점을 발견했다면 report_expand에 넣지 말고
   > `[P2-NEW-CANDIDATE] <파일>:<라인> — <한 줄 설명>` 형식으로 콘솔에만 출력해
   > 신규 finding 후보로 남기고, 현재 finding은 자신의 `category`/`evidence`에만
   > 엄격히 anchor한다.

2. **review_note 해석 및 실행**:
   - review_note에 담긴 리뷰어 판단(위험도 근거, 공격 경로, 특이사항)을 **이해**한다
   - 지시성 메모(파일 명시 필수, 목록화 필요, N개 클래스 등)가 있으면 codebase 탐색으로 즉시 이행한다
   - severity 변경 메모가 있으면 해당 finding의 severity 필드도 즉시 갱신한다

   **review_note가 긴 경우 (20줄 초과 또는 `## ` 헤더 포함):**
   - `## ` 헤더 이전의 평문 메모(1~5줄)를 **핵심 판단 근거**로 먼저 추출
   - 헤더 이후 테이블/목록은 report_expand의 해당 섹션에 직접 인용
   - 내용 분량이 많아도 **판정 기준 파일(0c)과의 대조를 생략하지 않는다**  
     예: review_note에 대형 표가 있어도 review_result가 "정보"이고 severity가 Informational/Low면 기준 파일에 따라 Medium으로 처리

3. **report_expand 작성** — 아래 형식으로 작성:

   ```markdown
   ## 코드 직접 확인 결과

   <취약점 존재 여부 및 코드 레벨 근거 — 1~3문장, 외부 보고서용 문체>

   ## 위험 시나리오

   <구체적 공격/오용 경로 설명 — 어떤 조건에서 어떤 피해가 발생하는지>

   ## <섹션 제목 (필요시)>

   <마크다운 표 또는 목록 — 파일·라인·파라미터 목록 등>
   ```

   - 내부 메모 언어("보고서 명시 필요", "위험도 조정" 등)는 사용 금지
   - review_note의 핵심 기술 내용은 반영하되, 리뷰어 내부 코멘트 형식을 보고서 문체로 변환
   - severity, category에 맞는 기술적 깊이 유지
   - 오탐 판정(`review_status: "오탐"`) finding은 건너뜀

3.5. **저장 전 자기일관성 검증 (self-consistency check) ⚠️ 필수**:
   - 작성한 `report_expand`가 이 finding 자신의 `evidence.code_snippet`/`scope.affected_file`에
     실제로 등장하는 식별자(클래스명·메서드명·변수명·알고리즘명 중 최소 1개)를 언급하는지 확인한다.
   - `category`가 가리키는 취약점 종류(예: `WEAK_CRYPTO`라면 해시/암호 알고리즘 이름, `HARDCODED_SECRET`이라면
     키/자격증명 관련 서술)와 report_expand 본문의 주제가 일치하는지 확인한다.
   - 위 둘 중 하나라도 불일치하면 (예: 인근에서 읽은 다른 취약점 내용이 섞여 들어간 경우)
     **저장하지 않고 3번부터 다시 작성**한다 — 이 검증을 통과하지 못한 report_expand를
     그대로 저장하는 것은 이전 사고(위 1번 주의사항)의 재발이므로 예외 없이 재작성한다.

3.6. **조치 요약(recommendation 1번 항목) 품질 검증 ⚠️ 필수 (2026-09-04 locker-frontend-admin 3-2/3-3 사례로 도입)**:

   > **배경**: 보고서 개요 표의 "조치 요약" 컬럼은 `generate_final_report.py::_recom_summary()`가
   > `recommendation` 필드의 **1번 항목만** 기계적으로 추출해 채운다(① 첫 한국어 문장 종결 지점까지,
   > ② 그 줄이 콜론(`:`)으로 끝나면 — 코드블록 예고 줄로 간주해 — 줄 전체를 그대로 채택). 이 추출
   > 로직 자체는 바꾸지 않으므로, `recommendation`을 작성/저장하는 시점에 **1번 항목이 그대로
   > 뽑혀도 말이 되도록** 만들어야 한다. locker-frontend-admin DATA-002는 1번 항목이 추상적인
   > "[아키텍처 전환] 권한 검증은 서버사이드에서 수행"이라 요약만 봐서는 무엇이 유출됐는지 알 수
   > 없었고, DATA-003은 1번 항목이 `vite.config.js에 프로덕션 빌드 설정 추가:`처럼 콜론으로 끝나
   > 코드블록 없이는 내용이 전혀 없는 반쪽 문장이 추출됐다.

   `recommendation`을 저장하기 직전(§4a 자동 실행 결과 반영 후, 또는 이 Phase 2 단계에서 기존
   recommendation을 그대로 유지하는 경우에도) 아래를 확인한다:

   1. `_recom_summary()`가 실제로 뽑아낼 텍스트를 눈으로 시뮬레이션한다 — 1번 항목의 첫 줄에서
      첫 한국어 문장 종결 마침표까지, 또는 그 줄이 `:`로 끝나면 줄 전체.
   2. 그 결과가 아래 중 하나라도 해당하면 **불합격**으로 판정한다:
      - 콜론(`:`)으로 끝나 후속 코드블록/목록 없이는 의미가 통하지 않음 (예: "~설정 추가:")
      - 이 finding의 `evidence.code_snippet`/`scope.file`에 등장하는 구체적 식별자(변수명·파일명·
        설정 키·엔드포인트 등)를 하나도 포함하지 않는 추상적 방향 제시("아키텍처 전환", "재설계",
        "보안 강화" 등)에 그침 — 표만 보고는 이 finding이 정확히 무엇에 관한 것인지 알 수 없음
   3. 불합격이면 `recommendation`의 번호 순서를 재배치하여, 항목들 중 **가장 구체적이고 즉시
      실행 가능하며 finding의 핵심 식별자를 직접 언급하는 항목**을 1번으로 옮긴다(문장 내용 자체는
      바꾸지 않고 순서만 조정하는 것을 우선한다 — 새로 지어내지 않음). 적절한 기존 항목이 없으면
      1번 항목 문장을 구체적 식별자를 포함하는 완결된 문장으로 다시 쓴다.
   4. 재배치/재작성한 `recommendation`을 `findings_*.json`에 저장하고 콘솔에 출력:
      ```
      [P2-RECOM] {finding_id} — 조치 요약 품질 검증 불합격 → recommendation 순서 재배치 완료
      ```
   5. 합격이면(이미 1번 항목이 구체적) 아무것도 변경하지 않고 다음 finding으로 진행.

4. **저장**: `findings_*.json`의 해당 finding에 `report_expand` 필드(및 3.6에서 재배치된 경우
   `recommendation` 필드) 추가 후 즉시 저장

5. **진행 출력**:
   ```
   [P2] {finding_id} — report_expand 생성 완료 ({N}줄)
   ```

**Phase 2 예시 — INJ-001**:

review_note 원문:
> "gender는 string, ageGroup은 int type에 의해 반영. 두 파라미터 모두 userinfo에서 주입이므로 사용자 입력 파라미터는 아니나 기타 UI를 통해 해당 값 조작 시 취약점 발현 가능. 위험도 4, 잠재적 취약으로 판단"

생성되는 report_expand:
```markdown
## 코드 직접 확인 결과

`ItemService.java`의 `getItemInfo()` 메서드에서 `category`(String)와 `sortOrder`(int) 파라미터가
SQL 쿼리에 직접 삽입된다. 두 파라미터 모두 인증된 사용자의 프로필 정보(`userInfo`)에서 유입되므로
일반적인 외부 직접 조작은 제한되나, UI를 통한 프로필 편집 경로에서 비정상 값이 주입될 경우
SQL Injection이 발현될 수 있다.

## 위험 시나리오

1. 공격자가 프로필 수정 API를 통해 `category` 필드에 SQL 페이로드 삽입
2. 변경된 프로필 정보가 `userInfo` 캐시/DB에 저장
3. 이후 `getItemInfo()` 호출 시 오염된 값이 SQL 쿼리에 반영되어 Injection 발현

## 취약 위치

| 파일 | 라인 | 취약 파라미터 | 타입 |
|------|------|--------------|------|
| ItemService.java | 해당라인 | category | String — SQL 직접 삽입 |
| ItemService.java | 해당라인 | sortOrder | int — 타입 제약으로 위험 낮음 |
```

### 5c. Audit 세션 종료

Phase 2 (report_expand 생성) 완료 직후, 세션 종료를 audit_log에 기록한다:

```bash
python3 tools/audit_utils.py end-session \
  --session-id "$SESSION_ID" \
  --정탐 <정탐_건수> \
  --오탐 <오탐_건수> \
  --스킵 <스킵_건수>
```

- 건수는 Phase 1~2 전체 처리 결과 집계값을 사용한다
- SESSION_ID가 없는 경우(초기화 실패) 이 단계를 생략한다

### 5d. 서비스 특징 분석 및 추가 진단(동적 진단/모의해킹) 필요 여부 판단

> **위치 근거**: 이 단계는 원래 §1b였으나, 판단에 finding 리뷰 결과(정탐 여부, review_note, 위험도 조정)와 보고서 초안(§5b) 내용이 필요하다는 사용자 지시(2026-08-25)에 따라 전체 finding 판정 + review_note 작성(§4~§5b) 완료 이후, 클렌징(§5e) 이전으로 이동했다. `testbed/<repo>/` 는 아직 삭제 전이므로 소스 참조가 가능한 마지막 시점이기도 하다.

> **2026-09-01 갱신 — BLOCKING INPUT 폐기**: 이 단계는 과거 자율 완주 규칙의 명시적 예외(사람이 반드시 `AskUserQuestion`으로 확정)로 설계됐으나, `/sec-review` 완전 무중단화 결정에 따라 폐기됐다. 이제 LLM이 산출하는 `[권고]` 결과를 사람 확인 없이 그대로 최종값으로 채택한다.

`state/<repo>/review_meta.json` 존재 여부와 무관하게 항상 아래 "서비스 특징 재분석"을 실행한다(최신 코드 기준으로 매번 갱신 — 기존 값을 유지할지 사람에게 물을 필요가 없으므로 경로 분기 자체를 제거했다).

**서비스 특징 LLM 분석**:

`testbed/<repo>/` 의 디렉터리 구조, 주요 컨트롤러/서비스 클래스, 빌드 설정(build.gradle / package.json), README 등을 탐색하여 아래 항목을 분석하고 출력한다:

- **기술 스택**: 언어, 프레임워크, 주요 라이브러리
- **서비스 도메인**: 핵심 업무 영역
- **주요 기능**: 인증, API, 데이터 처리, 외부 연동 등
- **취급 민감 데이터**: PII(개인정보), 금융정보, 카드정보, 세션 토큰 등
- **보안 리스크 프로파일**: 외부 노출 범위, 주요 공격 표면

**출력 형식** (```text``` 코드펜스로 감싸서):

```text
=== 서비스 특징 분석 ===
기술 스택    : Spring Boot 2.7 / Java 11 / MyBatis / Redis
서비스 도메인 : OK Cashbag 포인트 조회·적립 API
주요 기능    : 회원 인증, 포인트 거래 이력, 외부 가맹점 API 연동
민감 데이터  : 회원 ID, 거래 금액, 카드 마지막 4자리
리스크 프로파일: 대외 노출 API, 금융 데이터 취급
==========================
```

**추가 진단 필요 여부 — [권고] 자동 채택**

Claude는 서비스 특징(기술 스택/주요 기능/민감 데이터)뿐 아니라, 이번 세션에서 확정된 **정탐 findings의 상세 내용
(title/severity/evidence/review_note, §5b 보고서 초안의 "위험 시나리오"·"코드 직접 확인 결과")** 을 함께 근거로
PoC 가능성과 모의해킹 시나리오를 종합해 아래 형식으로 권고안을 제시한다:

```text
[권고] 이 서비스는 {서비스 특징 근거 — 예: 자체 로그인/세션 발급 로직 보유, PG 연동 결제 API 존재 등}로 보아
       {인증, 결제} 진단을 권고합니다. (해당 유형 없으면: "추가 진단 불필요 — SAST로 충분")

[PoC 가능성 / 모의해킹 시나리오]
- {정탐 finding_id} ({severity}): {해당 finding의 evidence/위험 시나리오를 근거로 실제 브라우저·API 호출
  환경에서 어떻게 실증 가능한지 1~2문장 — 예: "Persistent XSS(XSS-002)는 관리자 계정 탈취 후 공지 필드에
  <script> 페이로드를 저장, 타 관리자 세션에서 렌더링되는지 실제 화면에서 확인하는 시나리오로 실증 가능"}
- (정탐 finding이 여러 건이면 유형별로 대표 1~2건만 요약, 전수 나열하지 않는다)
```

이 `[권고]` 결과를 **사람 확인 없이 그대로 최종값으로 채택**한다:
- `[권고]` 줄에 유형이 하나 이상 나열되면 → `additional_diagnosis_needed: true`, 나열된 유형을 `additional_diagnosis_types` 배열로 저장 (자유 서술 유형도 그대로 문자열로 저장 — 고정 4종 옵션에 강제로 맞추지 않는다)
- `[권고]`가 "추가 진단 불필요"로 결론 나면 → `additional_diagnosis_needed: false`, `additional_diagnosis_types: []`

**유사 서비스 대조 (보조 근거, 자동판정을 덮어쓰지 않음)**

`Glob`으로 `state/*/review_meta.json` 전체를 스캔해, 이번 레포와 기술스택/도메인 키워드가 겹치는 과거 레포의 `additional_diagnosis_types`를 확인한다:
- 겹치는 사례가 있으면 → `additional_diagnosis_basis`에 `"유사 서비스 대조: <repo1>, <repo2>는 동일 유형 진단 권고됨"` 문구를 덧붙인다
- 없으면 → `"유사 사례 없음 — 서비스 특징 단독 근거"`를 덧붙인다
- 이 대조는 참고 문구일 뿐 위 `[권고]` 채택 결과를 바꾸지 않는다

**저장**: `state/<repo>/review_meta.json` 에 아래 형식으로 저장한다:

```json
{
  "repo": "<repo>",
  "service_characteristics": "기술 스택: Spring Boot / Java 11 | 서비스 도메인: 포인트 API | 민감 데이터: 회원 ID, 거래 금액",
  "additional_diagnosis_needed": true,
  "additional_diagnosis_types": ["인증", "결제"],
  "additional_diagnosis_basis": "자체 로그인/세션 발급 로직 보유, PG 연동 결제 API 존재. PoC: Persistent XSS(XSS-002) 관리자 세션 탈취 시나리오 실증 가능. 유사 사례 없음 — 서비스 특징 단독 근거",
  "updated_at": "2026-06-17T10:30:00"
}
```

- `additional_diagnosis_needed`: `[권고]`에 진단 유형이 있으면 `true`, 없으면 `false`
- `additional_diagnosis_types`: `additional_diagnosis_needed == true` 일 때만 `[권고]` 유형을 그대로 저장 (문자열 배열). `false`인 경우 `[]`
- `additional_diagnosis_basis`: `[권고]`/`[PoC 가능성]` 서술 + 유사 서비스 대조 문구
- `testbed/<repo>/` 가 없으면 LLM 분석 생략, `service_characteristics: "—"` 로 저장, `additional_diagnosis_needed: false`, `additional_diagnosis_types: []`

### 5e. Phase C-2 — 클렌징 완료 처리

> **정책**: `shared/references/llm_data_cleansing_policy.md` | **절차**: `shared/references/phase_c_cleansing.md`

Audit 세션 종료 직후 자동 수행한다.

> **자율 완주 대상 (2026-08-25, 사용자 명시적 지시)**: 이 단계(`tools/retroactive_cleanse.py` 실행 —
> testbed 삭제 + Confluence 클렌징 레지스트리 게시 포함)는 findings 판정처럼 사람 판단이 필요한
> 확인 대상이 아니다. 판정 결과를 기계적으로 반영하는 후속 처리이므로 확인 질문 없이 즉시 실행한다.
> `tools/retroactive_cleanse.py --repo <repo>`로 아래 1~7 단계를 일괄 수행한다 (스크립트가 없거나
> 실패하면 1~7을 개별 수행).

**1. `state/<repo>/llm_data_access_log.json` 로드**
- 파일 없는 경우 → 빈 `skills[]`로 신규 생성 후 진행

**2. testbed 삭제**

⚠️ 삭제 전, `state/<repo>/repo_meta.json`이 없으면 `testbed/<repo>/.clone_info.json`에서 백업한다
(정상 clone 레포는 `clone_repo.py`가 clone 시점에 이미 기록해두므로 보통 생략됨):
```bash
test -f state/<repo>/repo_meta.json || \
  ( mkdir -p state/<repo>/ && cp testbed/<repo>/.clone_info.json state/<repo>/repo_meta.json )
```
이 파일이 없으면 이후 `generate_final_report.py`가 Bitbucket 프로젝트/저장소/브랜치/커밋 해시/담당자를
전부 `—`로 표시한다 (`--publish` 시 `[GATE ERROR]`로 차단됨 — 상세: `shared/references/phase_c_cleansing.md`).

```bash
rm -rf testbed/<repo>/
```
- 성공 → `cleansing_actions[testbed_deletion].confirmed = true`, `confirmed_at = <now ISO8601>`
- 이미 없음 → `confirmed = true`, `note = "이미 삭제됨"`

**3. state/ 소스코드 감사**
```bash
find state/<repo>/ \( -name "*.java" -o -name "*.kt" -o -name "*.xml" -o -name "*.py" \) \
  | grep -v "__pycache__" | head -5
```
- 0건 → `state_snippet_audit.confirmed = true`
- 1건 이상 → 파일 목록 출력 + `note = "주의: 소스 파일 N건 발견"`, `confirmed = false`

**4. 스캔 redact 확인**
- `sec-scan-data` skill 실행 여부를 `state/<repo>/data/` 존재로 확인
- data skill 실행됨 → `scan_script_redact.confirmed = true`, `note = "scan_data_protection.py _redact_snippet() 자동 적용"`
- data skill 미실행 → `scan_script_redact.confirmed = false`, `note = "data skill 미실행"`

**5. `cleansing_completed` 갱신**
- `testbed_deletion.confirmed == true` AND `state_snippet_audit.confirmed == true` → `cleansing_completed = true`, `cleansing_completed_at = <now ISO8601>`
- 이외 → `cleansing_completed = false`, `notes`에 미완료 사유 기록

**6. Confluence 레지스트리 행 추가** (pageId: `<YOUR_REGISTRY_PAGE_ID>`)

`.env`의 `CONFLUENCE_TOKEN`(Bearer)을 사용하여 REST API로 테이블 행을 추가한다.

행 구성 (레포당 1행):
| 필드 | 값 |
|---|---|
| 진단일 | `skills[]` 중 가장 최신 `scanned_at` 날짜 (YYYY-MM-DD) |
| 고객사/프로젝트 | `project` 값 |
| 레포 | `repo` 값 |
| Skill | `all (injection/xss/file/data/auth/php/sca)` — 실제 존재하는 skill만 나열 |
| testbed 삭제 | ✅ 또는 ⚠️ |
| state 감사 | ✅ 또는 ⚠️ |
| 스캔 redact | ✅ 또는 ⚠️ |
| 세션 종료 | 🔲 |
| 완료 | 🔲 |
| 로그 위치 | `state/<repo>/llm_data_access_log.json` |

Confluence 페이지 업데이트 실패 시 → `notes`에 오류 기록 후 계속 진행

**7. `llm_data_access_log.json` 최종 저장**

**완료 출력**:
```
[Phase C-2] 클렌징 완료 처리
  testbed 삭제   : ✅  testbed/<repo>/ 삭제
  state 감사     : ✅  소스 파일 0건
  스캔 redact    : ✅
  Confluence     : ✅  레지스트리 행 추가 (pageId: <YOUR_REGISTRY_PAGE_ID>)
  로그           : state/<repo>/llm_data_access_log.json
```

확인 질문 없이 곧바로 §5f(전체양호 판단) → §6(보고서 생성/게시)으로 이어서 진행한다.

> **[운영자] 참고**: 이 Claude 세션에는 여전히 `testbed/<repo>/` 소스코드가 포함된 대화 컨텍스트가
> 남아있다. §6까지 완료된 뒤에는 세션을 종료하고 새 세션을 시작하는 것을 권장한다(자동 실행 대상 아님).

### 5f. 전체양호 자동 처리 (레포 단위 모드 전용)

> **적용 조건 (모두 충족 시에만 실행)**:
> - **레포 단위 모드** (`run_id=None`, §0 인수 파싱 기준) — RUN_ID 모드에서는 실행하지 않는다.
>   체크리스트(`docs/ocb_scan_plan.md`)는 레포 전체 현황을 추적하므로, skill 일부만 리뷰한 RUN_ID 모드 결과로
>   전체양호를 단정하면 다른 skill의 미판정/정탐 건과 충돌할 수 있다.
> - 이번 리뷰 세션 종료 시점 기준 **정탐 건수 == 0**
> - **미판정(스킵) 건수 == 0** (전체 finding이 정탐 또는 오탐으로 판정 완료된 상태)

Phase C-2 완료 직후, 위 조건을 모두 충족하면 자동 실행한다:

```bash
python3 tools/update_ocb_plan.py --all-clear <repo>
```

- `docs/ocb_scan_plan.md` 의 해당 레포 행 갱신: 보고서 컬럼 → `전체양호`, Jira 티켓 컬럼 → `{bg:#D4EDDA}전체양호`
- 스크립트 내부에서 Confluence 페이지(pageId: `750459063`, "26년 진단결과")까지 자동 동기화
- 레포 행을 찾지 못하는 등 갱신 실패 시 `[WARN]` 출력 후 계속 진행 (사람 개입 불필요 — blocking 아님)
- 조건 미충족(정탐 > 0 이거나 미판정 > 0 이거나 RUN_ID 모드) 시 이 단계 전체를 건너뛰고 Step 6으로 진행

**완료 출력**:
```
[전체양호 처리] docs/ocb_scan_plan.md 갱신 + Confluence 동기화 완료
  보고서    : 전체양호
  Jira 티켓 : 전체양호
```

### 6. 최종 보고서 생성 + Confluence 게시 (자동)

> **자율 완주 대상 (2026-08-25, 사용자 명시적 지시)**: §5e 클렌징 직후, 정탐 finding이 1건이라도
> 있으면 확인 질문 없이 곧바로 `approve_report.py`를 `--publish` 포함하여 실행한다. 이 단계는
> `/sec-review` 완료 후 별도 스킬/도구를 사용자가 수동으로 재호출해야 하는 것이 아니라, `/sec-review`
> 자체의 마지막 phase로 취급한다.

**정탐 0건 + 미판정 0건인 경우** (§5f 전체양호 자동 처리가 이미 실행됨) → 이 단계 전체를 건너뛴다
(`approve_report.py`는 정탐 finding이 없으면 생성할 내용이 없다).

**정탐 ≥ 1건인 경우** — RUN_ID 모드/레포 단위 모드 공통으로 아래를 실행한다:

```bash
# RUN_ID 모드
python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish

# 레포 단위 모드
python3 tools/approve_report.py --repo <repo> --publish
```

- 스크립트 실행 중 `[GATE ERROR]` 등 사람만 해결 가능한 blocking 오류가 나면 HARD RULE의 예외 조항에
  따라 보고 후 대기한다 (예: `repo_meta.json` 누락으로 인한 게시 차단 등)
- 정상 종료 시 아래 형식으로 완료 요약을 출력한다:

```
=== 리뷰 완료 ===
정탐: {N}건  /  오탐: {N}건  /  미판정: {N}건
자동판정(저신뢰): {N}건 — review_note '[AUTO-LOWCONF]' 검색 권장 (사후 표본 점검 대상)
report_expand 생성: {N}건

클렌징 완료 — testbed 삭제 / state 감사 / 클렌징 레지스트리(pageId: <YOUR_REGISTRY_PAGE_ID>) 갱신
최종 보고서   : logs/final_<repo>_<RUN_ID|repo전체>.md
Confluence 게시: ✅ <게시된 page 링크 또는 page_id>
```

- `자동판정(저신뢰)` 건수는 §4에서 `review_note`에 `[AUTO-LOWCONF]` 문자열이 포함된 finding 수를 집계한 값이다

**정탐 0건 + 미판정 0건인 경우**(§5f 실행됨) 완료 요약:

```
=== 리뷰 완료 ===
정탐: 0건  /  오탐: {N}건  /  미판정: 0건

전체양호 처리 완료 — docs/ocb_scan_plan.md 및 Confluence(pageId: 750459063) 갱신됨
approve_report.py 실행 불필요 (정탐 finding 없음)
```

### 주의 사항

- 리뷰 중 **어떤 형태의 확인 질문도 출력하지 말 것** (HARD RULE) — §4/§5d 모두 AskUserQuestion 없이 규칙 파일·`judgment_lookup.py` 기반으로 자동 판정한다
- finding 파일은 판정 즉시 저장 (중단해도 진행 내용 보존)
- §4는 모든 finding을 `reviewed: true`로 종결하므로 정상적으로는 미판정(스킵) 건이 발생하지 않는다 — 혹시 남아있으면(레거시 데이터 등) `approve_report.py` 에서 정탐으로 처리됨
- 소스 파일 경로: `testbed/<repo>/` 기준으로 `scope.affected_file` 을 조합
- **Phase 2는 자율 완주** — 완료 전 어떤 확인도 없이 모든 정탐 finding에 대해 순서대로 실행
- Phase 2 완료 전까지 `approve_report.py` 실행 금지 (report_expand 미생성 상태로 보고서 생성되면 review_note 폴백 사용됨)

#### §N. evidence_trail 교차검증 (누락 판정 전 필수)

**원시 스캔 파일(`xss.json`, `injection.json` 등)의 `취약` 건수 > `findings_*.json`의 `findings[]` 건수인 경우,
"finding 누락"으로 판정하기 전에 반드시 아래 절차를 먼저 수행한다.**

1. `findings_*.json`의 `evidence_trail[]` 배열을 확인한다
2. `evidence_trail[]`에 `fp_corrected: true` + 해당 endpoint 항목이 존재하면 → LLM-Check 단계에서 FP로 올바르게 제외된 것임 → **누락 아님, 추가 불필요**
3. `evidence_trail[]`에도 없고 `findings[]`에도 없는 경우에만 → 실제 누락으로 판단하고 수동 조사 진행

> **배경**: LLM-Check가 원시 스캔 결과를 FP 판정하면 해당 항목은 `findings[]`가 아닌 `evidence_trail[]`에만 기록된다.
> `evidence_trail[]` 확인 없이 숫자 차이만으로 누락 판정 시 올바르게 제외된 FP를 재추가하는 오류가 발생한다.
