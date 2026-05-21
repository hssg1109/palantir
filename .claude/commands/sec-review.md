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

### 1. findings 수집

**RUN_ID 모드**: `state/<repo>/*/<RUN_ID>/findings_*.json` 패턴으로 수집.

**레포 단위 모드**: `state/<repo>/*/` 하위 모든 RUN_ID 디렉터리를 탐색하여
skill별로 RUN_ID 내림차순(최신) 파일 하나씩 선택:
- `state/<repo>/<skill>/*/findings_*.json` — skill별 최신 파일
- 수집 후 어떤 RUN_ID를 사용했는지 skill별로 출력

각 파일에서 `reviewed` 가 `true` 가 아닌 finding 중 `result` 가 아래 **제외 목록에 없는** 항목을 리뷰 대상으로 추린다.

**제외 목록** (evidence_trail 전용 또는 정상): `"양호"`, `"양호(FP)"`, `"해당없음"`, `"safe"`

`"취약"`, `"정보"` 는 물론, 비표준 값(`"수동검토필요"`, `"정보(수동검토필요)"` 등 스캐너 버그로 발생)도 리뷰 대상에 포함한다.

### 2. 전체 취약점 개요 출력

리뷰 시작 전, 수집된 모든 finding을 아래 형식의 테이블로 **한 번에** 출력한다.

```
=== 리뷰 대상 전체 목록 ===
레포   : <repo>
대상   : <N>건

 #  | 분류      | ID               | 위험도   | 제목 요약
----+-----------+------------------+----------+-----------------------------------------------------
  1 | injection | INJ-001          | High     | SQL Injection — userInfo 조회 파라미터 미검증
  2 | xss       | XSS-AUTO-009     | High     | Persistent XSS — 댓글/피드 DB 저장 API 다수
...
===========================================================
```

- 제목 요약은 `title` 필드 그대로 사용 (60자 초과 시 말줄임)
- `result` 가 비표준 값(`수동검토필요` 등)이면 위험도 뒤에 `[수동검토]` 표기
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
| POST /file/ocr/coupon | GptOcrCouponService.java | 41 | 확장자 whitelist만, MIME 없음 |"
```

```
변환 전: "debug 로그 PII 노출 — 목록화 필요"

변환 후: "## 노출 파일 및 라인별 PII 상세 (debug 레벨)
| 파일 | 라인 | 노출 파라미터 | 비고 |
|------|------|--------------|------|
| AuthService.java | 476 | mbrId, newPasswd | ⚠️ 비밀번호 평문 |
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

**Phase 2 실행 절차**:

```
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

`UserInfoService.java`의 `getUserInfo()` 메서드에서 `gender`(String)와 `ageGroup`(int) 파라미터가
SQL 쿼리에 직접 삽입된다. 두 파라미터 모두 인증된 사용자의 프로필 정보(`userInfo`)에서 유입되므로
일반적인 외부 직접 조작은 제한되나, UI를 통한 프로필 편집 경로에서 비정상 값이 주입될 경우
SQL Injection이 발현될 수 있다.

## 위험 시나리오

1. 공격자가 프로필 수정 API를 통해 `gender` 필드에 SQL 페이로드 삽입
2. 변경된 프로필 정보가 `userInfo` 캐시/DB에 저장
3. 이후 `getUserInfo()` 호출 시 오염된 값이 SQL 쿼리에 반영되어 Injection 발현

## 취약 위치

| 파일 | 라인 | 취약 파라미터 | 타입 |
|------|------|--------------|------|
| UserInfoService.java | 해당라인 | gender | String — SQL 직접 삽입 |
| UserInfoService.java | 해당라인 | ageGroup | int — 타입 제약으로 위험 낮음 |
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

레포 단위 모드:

```
=== 리뷰 완료 ===
정탐: {N}건  /  오탐: {N}건  /  미판정: {N}건
report_expand 생성: {N}건

다음 단계 — 최종 보고서 생성:
  python3 tools/approve_report.py --repo <repo>

Confluence 게시 포함:
  python3 tools/approve_report.py --repo <repo> --publish
```

### 주의 사항

- 리뷰 중 **어떤 형태의 확인 질문도 출력하지 말 것** (HARD RULE) — 단, 의견/질문 입력 시 코드 분석·답변은 허용
- finding 파일은 판정 즉시 저장 (중단해도 진행 내용 보존)
- 미판정(스킵) finding은 `approve_report.py` 에서 정탐으로 처리됨
- 소스 파일 경로: `testbed/<repo>/` 기준으로 `scope.affected_file` 을 조합
- **Phase 2는 자율 완주** — 완료 전 어떤 확인도 없이 모든 정탐 finding에 대해 순서대로 실행
- Phase 2 완료 전까지 `approve_report.py` 실행 금지 (report_expand 미생성 상태로 보고서 생성되면 review_note 폴백 사용됨)
