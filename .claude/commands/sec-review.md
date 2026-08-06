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

#### 1a. Audit 정합성 검증 ⚠️ 필수 — `reviewed: true` 항목의 사람 판정 여부 확인

> **목적**: `reviewed`/`review_status`는 오직 본 skill(`/sec-review`) §4의 사람 판정에서만 부여되는 필드다.
> 그런데 스캔/LLM-Check 단계(예: 이전 세션의 수동 편집, 스킬 지시사항 오해 등)에서 이 필드가 audit 기록 없이 직접 기록되는 사고가 실제로 발생한 바 있다(2026-08-03 displayadmin_server XSS-001 사례 — 사람 판정 없이 `reviewed:true`가 설정돼 인터랙티브 리뷰를 거치지 않고 `approve_report.py`로 그대로 보고서에 반영됨).
> 이 필드를 맹목적으로 신뢰하면 사람이 실제로 판정하지 않은 finding이 조용히 보고서에 포함될 수 있다.

수집된 finding 중 `reviewed: true` 인 항목 각각에 대해:

1. `state/audit_log.json`을 로드하여 `event_type == "finding_reviewed"` AND `repo == <repo>` AND `finding_id == <해당 finding_id>` 인 항목이 존재하는지 확인
2. **존재하지 않으면** → 이 finding은 사람 판정을 거친 적이 없는 것으로 간주하고, `reviewed: false` 인 것처럼 취급하여 리뷰 대상 목록에 **포함**시킨다 (JSON 파일 자체는 아직 수정하지 않음 — §4 판정 시 정상적으로 재확정 후 저장)
3. 아래와 같이 콘솔에 경고를 출력한다:
   ```
   [AUDIT GAP] {finding_id} — reviewed=true 이나 audit_log에 사람 판정 기록 없음 → 리뷰 대상에 재포함
   ```
4. `event_type == "finding_reviewed"` 항목이 존재하면 정상적으로 §0d 재개 로직에 따라 건너뜀

각 파일에서 (위 1a 검증을 통과한) `reviewed` 가 `true` 가 아닌 finding 중 `result` 가 아래 **제외 목록에 없는** 항목을 리뷰 대상으로 추린다.

**제외 목록** (evidence_trail 전용 또는 정상): `"양호"`, `"양호(FP)"`, `"해당없음"`, `"safe"`

`"취약"`, `"정보"` 는 물론, 비표준 값(`"수동검토필요"`, `"정보(수동검토필요)"` 등 스캐너 버그로 발생)도 리뷰 대상에 포함한다.

### 1b. 서비스 특징 분석 및 추가 진단 필요 여부 입력

`state/<repo>/review_meta.json` 존재 여부에 따라 두 가지 경로로 분기한다.

---

#### 경로 A — review_meta.json 없음 (최초 실행)

**서비스 특징 LLM 분석**:

`testbed/<repo>/` 의 디렉터리 구조, 주요 컨트롤러/서비스 클래스, 빌드 설정(build.gradle / package.json), README 등을 탐색하여 아래 항목을 분석하고 출력한다:

- **기술 스택**: 언어, 프레임워크, 주요 라이브러리
- **서비스 도메인**: 핵심 업무 영역
- **주요 기능**: 인증, API, 데이터 처리, 외부 연동 등
- **취급 민감 데이터**: PII(개인정보), 금융정보, 카드정보, 세션 토큰 등
- **보안 리스크 프로파일**: 외부 노출 범위, 주요 공격 표면

분석 결과를 아래 형식으로 출력한 뒤, 추가 진단 필요 여부를 입력받는다.

---

#### 경로 B — review_meta.json 존재 (재실행)

기존 데이터를 출력하고 업데이트 여부를 선택받는다:

```
=== 서비스 특징 (기존 데이터) ===
{service_characteristics 값}
추가 진단 필요 여부: 필요 / 불필요
추가 진단 유형     : {additional_diagnosis_types 값, 없으면 "—"}
============================
업데이트하시겠습니까?
  y  →  서비스 특징 LLM 재분석 + 추가 진단 여부 재입력
  d  →  추가 진단 여부만 재입력 (서비스 특징 분석 생략)
  Enter  →  변경 없이 스킵

[y/d/Enter]:
```

- `y` 입력 → 경로 A 전체 실행 (LLM 재분석 포함)
- `d` 입력 → LLM 분석 생략, 추가 진단 필요 여부 입력만 진행
- Enter → Step 1b 전체 스킵, 기존 review_meta.json 유지

---

**출력 형식** (경로 A 또는 경로 B-y 실행 시):

```
=== 서비스 특징 분석 ===
기술 스택    : Spring Boot 2.7 / Java 11 / MyBatis / Redis
서비스 도메인 : OK Cashbag 포인트 조회·적립 API
주요 기능    : 회원 인증, 포인트 거래 이력, 외부 가맹점 API 연동
민감 데이터  : 회원 ID, 거래 금액, 카드 마지막 4자리
리스크 프로파일: 대외 노출 API, 금융 데이터 취급
==========================
```

**추가 진단 필요 여부 입력** (경로 A / B-y / B-d 공통):

> **BLOCKING INPUT** — 이 단계는 **자율 완주 규칙의 예외**다.  
> Claude가 서비스 특징을 분석하더라도 추가 진단 필요 여부를 **스스로 판단하거나 자동 저장하지 않는다.**  
> 반드시 아래 프롬프트를 출력하고 **auditor의 실제 입력을 받은 뒤에만** 저장·진행한다.

```
=== 동적진단 등 추가진단 필요여부 (동적 진단 / 모의해킹 등) ===
y  →  추가 진단 필요
n  또는 Enter  →  불필요

판정 [y/n/Enter]:
```

**추가 진단 유형 입력** (`y` 입력 시에만 진행, `n`/Enter 면 이 단계 스킵):

> **BLOCKING INPUT** — y/n 판정과 동일하게 자율 완주 규칙의 예외다.
> Claude는 직전 서비스 특징 분석(주요 기능/민감 데이터/리스크 프로파일)을 근거로 **권고 유형을 제시**할 수 있으나,
> 최종적으로 database(`review_meta.json`)에 남는 유형 목록은 **auditor 입력값**이다.

먼저 서비스 특징 분석 결과를 근거로 권고안을 한 줄로 제시한 뒤 입력을 받는다:

```
[권고] 이 서비스는 {근거 — 예: 자체 로그인/세션 발급 로직 보유, PG 연동 결제 API 존재 등}로 보아
       {인증, 결제} 진단을 권고합니다.

=== 추가 진단 유형 선택 ===
복수 선택 가능, 쉼표로 구분. 목록에 없는 유형은 자유 텍스트로 입력.

  1. 인증   (로그인/세션/토큰/권한 체계)
  2. 결제   (PG 연동, 정산, 포인트/캐시 차감)
  3. 인프라 (네트워크 구성, 방화벽, 클라우드 설정)
  4. 개인정보 (PII 대량 처리, 외부 전송)
  5. 기타   (자유 텍스트로 명시)

입력 (예: 1,2  또는  인증,결제 / Enter=권고안 그대로 적용 / n=선택 안 함):
```

- 번호(`1,2`) 또는 유형명 자유 텍스트(`인증,결제`) 모두 허용, 콤마로 다중 선택 파싱
- Enter(빈 입력) → 직전 [권고] 줄의 유형을 그대로 채택
- `n` → 유형 미지정 (`additional_diagnosis_types: []`)로 저장, 필요 시 이후 재실행(§경로 B `d`)으로 보완 가능
- `5.기타` 또는 목록에 없는 자유 텍스트 입력 시 해당 문자열 그대로 배열에 포함

**저장**: `state/<repo>/review_meta.json` 에 아래 형식으로 저장한다 (경로 B-Enter 제외):

```json
{
  "repo": "<repo>",
  "service_characteristics": "기술 스택: Spring Boot / Java 11 | 서비스 도메인: 포인트 API | 민감 데이터: 회원 ID, 거래 금액",
  "additional_diagnosis_needed": true,
  "additional_diagnosis_types": ["인증", "결제"],
  "additional_diagnosis_basis": "자체 로그인/세션 발급 로직 보유, PG 연동 결제 API 존재",
  "updated_at": "2026-06-17T10:30:00"
}
```

- `additional_diagnosis_needed`: `y` 입력 시 `true`, `n` 또는 Enter 시 `false`
- `additional_diagnosis_types`: `additional_diagnosis_needed == true` 일 때만 입력받아 저장 (문자열 배열). `false`인 경우 `[]`
- `additional_diagnosis_basis`: 유형 선택의 근거가 된 서비스 특징 요약 1문장 ([권고] 줄 근거를 그대로 기록, auditor가 자유 텍스트로 교체 입력한 경우 해당 텍스트 사용)
- Claude가 리스크 프로파일을 참고해 권고 의견을 제시할 수 있으나, **최종 판정 입력은 auditor만 한다**
- `testbed/<repo>/` 가 없으면 LLM 분석 생략, `service_characteristics: "—"` 로 저장, 추가 진단 유형 입력도 생략(`additional_diagnosis_types: []`)

### 2. 전체 취약점 개요 출력

리뷰 시작 전, 수집된 모든 finding을 아래 형식의 테이블로 **한 번에** 출력한다.

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

```
=== 오탐/정탐 인터랙티브 리뷰 ===
RUN_ID : <RUN_ID>
레포   : <repo>
대상   : <N>건 (취약/정보/수동검토필요 판정 findings)

판정 입력 방법:
  정탐 (실제 취약점)    →  1  또는  y  → 이후 결과 판정(취약/정보) 입력
  오탐 (false positive) →  0  또는  n
  스킵 (나중에 판정)    →  s  또는 Enter
  종료                  →  q
  의견/질문             →  자유 텍스트 입력 → 코드 확인 후 분석

정탐 판정 후 결과 판정:
  취약 (보고서에 취약으로 표시) →  v  또는  취약
  정보 (보고서에 정보로 표시)   →  i  또는  정보
  Enter (스캔 결과값 유지)      →  그대로 Enter

결과 판정 후 위험도 조정:
  Enter (스캔 위험도 유지)      →  그대로 Enter
  c  →  Critical
  h  →  High
  m  →  Medium
  l  →  Low
  i  →  Informational

판정 완료 후 approve_report.py 로 최종 보고서를 생성한다.
===================================
```

### 4. finding별 인터랙티브 판정

각 finding을 아래 형식으로 제시한다:

```
[{순번}/{전체}] {skill} — {finding_id}
위험도 : {severity}
제목   : {title}
위치   : {scope.affected_file}:{scope.affected_line}  (또는 scope.endpoint)
설명   : {description} (첫 200자)
증거   : {evidence.snippet} (첫 300자, 있을 경우)

판정 [1=정탐 / 0=오탐 / s=스킵 / q=종료 / 의견 입력]:
```

#### 입력 분기

**플래그 입력 (`1` / `y` / `0` / `n` / `s` / Enter / `q`)**:

- `1` / `y` → `review_status: "정탐"`, `reviewed: true`
  - **결과 판정**:
    `결과 판정 [v=취약 / i=정보 / Enter=스캔값 유지 ({result})]:` 를 출력하고 입력 대기
    - `v` / `취약` → `review_result: "취약"` 저장
    - `i` / `정보` → `review_result: "정보"` 저장
    - Enter (빈 입력) → `review_result` 필드 저장하지 않음 (스캔 result 값 그대로 사용)
  - **위험도 조정**:
    `위험도 조정 [Enter=유지 ({severity}) / c=Critical / h=High / m=Medium / l=Low / i=Informational]:` 를 출력하고 입력 대기
    - Enter (빈 입력) → severity 변경 없음
    - `c` → `severity: "Critical"` 로 갱신
    - `h` → `severity: "High"` 로 갱신
    - `m` → `severity: "Medium"` 로 갱신
    - `l` → `severity: "Low"` 로 갱신
    - `i` → `severity: "Informational"` 로 갱신
    - 변경 시 review_note 에 `"위험도 {이전} → {이후} 조정"` 자동 기록 (기존 메모 앞에 추가)
  - 추가로 "메모 (Enter 스킵):" 입력 받아 `draft_note` 에 임시 저장
  - **§4a 지시사항 자동 실행** 적용 후 최종 `review_note` 결정
- `0` / `n` → `review_status: "오탐"`, `reviewed: true`  
  - 추가로 "오탐 사유 (Enter 스킵):" 입력 받아 `review_note` 에 저장
  - `review_result` 는 저장하지 않음 (오탐 finding은 보고서에서 제외됨)
- `s` / Enter → `reviewed: false` (변경 없음, 다음으로)
- `q` → 즉시 중단, 지금까지 입력한 내용 저장 후 종료

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

**자유 텍스트 입력 (의견 / 질문)**:

1. `testbed/<repo>/<scope.affected_file>` 을 Read 도구로 읽는다
   - `scope.affected_line` 기준 앞뒤 40줄 범위를 우선 표시
   - 파일이 없으면 "소스 파일을 찾을 수 없음" 으로 안내 후 계속
2. 사용자의 의견/질문에 답하며 코드를 분석한다:
   - 취약점이 실제로 존재하는지 코드 레벨에서 검토
   - 관련 함수 / 호출 경로 / 보안 처리 여부 파악
   - 필요 시 `Grep` 으로 관련 패턴 추가 검색
3. 분석 완료 후 재판정을 요청한다:

```
[코드 분석 완료]
<분석 내용>

판정 [1=정탐 / 0=오탐 / s=스킵]:
```

4. 이후 플래그 입력 분기를 그대로 적용 (메모 입력 포함)
5. 분석 중 추가 질문이 들어오면 답변 후 다시 판정 요청 — finding이 종료될 때까지 반복

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
  --decision    "<정탐|오탐|스킵>" \
  [--review-result   "<취약|정보>"] \
  [--severity-before "<old_severity>"] \
  [--severity-after  "<new_severity>"] \
  [--review-note     "<findings_*.json에_저장된_최종_review_note>"] \
  [--auditor-questions '["<사용자_입력_질문1>", "<사용자_입력_질문2>"]'] \
  [--code-analysis   "<§4a_탐색_및_교체_내용_요약>"]
```

인수 매핑 규칙:

| 인수 | 값 출처 | 주의 |
|------|---------|------|
| `--scan-severity` | 판정 **전** finding의 `severity` 원본값 | 위험도 조정 전 스냅샷 |
| `--scan-result` | 판정 **전** finding의 `result` 원본값 | |
| `--decision` | 사용자 입력 (정탐/오탐/스킵) | |
| `--review-result` | 정탐 후 결과 판정값 (`취약`/`정보`), 스킵 시 생략 | |
| `--severity-before` | 위험도 조정 전 severity (변경한 경우만) | |
| `--severity-after` | 위험도 조정 후 severity (변경한 경우만) | |
| `--review-note` | **findings_*.json에 최종 저장된 `review_note` 전체** | §4a 교체 후 값. 사용자 원본 메모가 짧았더라도 교체 후 enriched content를 기록 |
| `--auditor-questions` | 사용자가 자유 텍스트로 입력한 질문 목록 (JSON 배열) | 코드 분석 요청 질문만 포함 |
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
4. `feedback_severity_reporting_policy.md` — Informational → 최소 Medium

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

2. **review_note 해석 및 실행**:
   - review_note에 담긴 리뷰어 판단(위험도 근거, 공격 경로, 특이사항)을 **이해**한다
   - 지시성 메모(파일 명시 필수, 목록화 필요, N개 클래스 등)가 있으면 codebase 탐색으로 즉시 이행한다
   - severity 변경 메모가 있으면 해당 finding의 severity 필드도 즉시 갱신한다

   **review_note가 긴 경우 (20줄 초과 또는 `## ` 헤더 포함):**
   - `## ` 헤더 이전의 평문 메모(1~5줄)를 **핵심 판단 근거**로 먼저 추출
   - 헤더 이후 테이블/목록은 report_expand의 해당 섹션에 직접 인용
   - 내용 분량이 많아도 **판정 기준 파일(0c)과의 대조를 생략하지 않는다**  
     예: review_note에 대형 표가 있어도 severity가 Informational이면 기준 파일에 따라 Medium으로 처리

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

4. **저장**: `findings_*.json`의 해당 finding에 `report_expand` 필드 추가 후 즉시 저장

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

### 5d. Phase C-2 — 클렌징 완료 처리

> **정책**: `shared/references/llm_data_cleansing_policy.md` | **절차**: `shared/references/phase_c_cleansing.md`

Audit 세션 종료 직후 자동 수행한다.

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
| Skill | `all (injection/xss/file/data/sca)` — 실제 존재하는 skill만 나열 |
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
  ─────────────────────────────────────────
  [운영자] 이 Claude 세션을 종료하고 새 세션을 시작하세요.
  (고객사 소스코드가 포함된 대화 컨텍스트를 만료시키기 위한 필수 절차입니다)
```

### 5e. 전체양호 자동 처리 (레포 단위 모드 전용)

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
- 스크립트 내부에서 Confluence 페이지(pageId: `746439687`, "OCB 서비스 군 보안 진단 계획")까지 자동 동기화
- 레포 행을 찾지 못하는 등 갱신 실패 시 `[WARN]` 출력 후 계속 진행 (사람 개입 불필요 — blocking 아님)
- 조건 미충족(정탐 > 0 이거나 미판정 > 0 이거나 RUN_ID 모드) 시 이 단계 전체를 건너뛰고 Step 6으로 진행

**완료 출력**:
```
[전체양호 처리] docs/ocb_scan_plan.md 갱신 + Confluence 동기화 완료
  보고서    : 전체양호
  Jira 티켓 : 전체양호
```

### 6. 완료 요약

RUN_ID 모드:

```
=== 리뷰 완료 ===
정탐: {N}건  /  오탐: {N}건  /  미판정: {N}건

다음 단계 — 최종 보고서 생성:
  python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo>

Confluence 게시 포함:
  python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish
```

레포 단위 모드 (정탐 > 0 이거나 미판정 > 0 — 일반 케이스):

```
=== 리뷰 완료 ===
정탐: {N}건  /  오탐: {N}건  /  미판정: {N}건
report_expand 생성: {N}건

다음 단계 — 최종 보고서 생성:
  python3 tools/approve_report.py --repo <repo>

Confluence 게시 포함:
  python3 tools/approve_report.py --repo <repo> --publish
```

레포 단위 모드 (정탐 0건 + 미판정 0건 — §5e 전체양호 자동 처리 실행됨):

```
=== 리뷰 완료 ===
정탐: 0건  /  오탐: {N}건  /  미판정: 0건

전체양호 처리 완료 — docs/ocb_scan_plan.md 및 Confluence(pageId: 746439687) 갱신됨
approve_report.py 실행 불필요 (정탐 finding 없음)
```

### 주의 사항

- 리뷰 중 **어떤 형태의 확인 질문도 출력하지 말 것** (HARD RULE) — 단, 의견/질문 입력 시 코드 분석·답변은 허용
- finding 파일은 판정 즉시 저장 (중단해도 진행 내용 보존)
- 미판정(스킵) finding은 `approve_report.py` 에서 정탐으로 처리됨
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
