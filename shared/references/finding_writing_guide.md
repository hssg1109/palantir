# Finding 작성 가이드 (공통 기준)

> **모든 Task(2-2 ~ 2-5) LLM 분석 결과 JSON 작성 시 이 가이드를 반드시 준수한다.**
> Confluence 렌더러가 이 규칙을 전제로 동작한다.

---

## 1. `evidence.code_snippet` — 코드 증적 필수

**모든 취약·정보 finding은 `evidence.code_snippet`을 반드시 포함해야 한다.**

- 취약한 코드 라인을 직접 인용한다 (10~30줄 내외, 핵심 구간 전후 3~5줄 포함).
- `evidence.file`에 소스 파일 경로, `evidence.lines`에 라인 번호(범위)를 명시한다.
- 코드가 두 개 이상의 파일에 걸쳐 있으면 `taint_evidence` 배열로 Controller → Service → Repository 순으로 기술한다.

```json
"evidence": {
  "file": "src/main/java/com/example/repository/sql/FeedQuery.kt",
  "lines": "1712-1720",
  "code_snippet": "fun incrementOdanjiClickCount(gender: String?, ageGroup: String?): String {\n    val columnName = if (gender != null && ageGroup != null)\n        \"${gender}_${ageGroup}_VISIT\".uppercase() else null\n    if (columnName != null) {\n        sql2 += \", counter.${columnName} = counter.${columnName} + 1\"\n    }\n}"
}
```

코드가 여러 레이어에 걸치는 경우 `taint_evidence` 사용:

```json
"taint_evidence": [
  {
    "title": "Controller → Service → Repository 호출 흐름",
    "controller_file": "controller/OdanjiController.java",
    "controller_lines": "42-50",
    "controller_snippet": "...",
    "service_file": "service/OdanjiService.kt",
    "service_lines": "160-170",
    "service_snippet": "...",
    "repository_file": "repository/sql/FeedQuery.kt",
    "repository_lines": "1712-1720",
    "repository_snippet": "..."
  }
]
```

---

## 2. `description` — 개발자가 이해하기 쉬운 구어체 설명

**개발자가 보고서를 읽고 바로 이해할 수 있도록 구어체로 작성한다.** 보안 용어 나열이 아니라,
이 서비스에서 실제로 어떤 코드 흐름이 문제이고 어떤 보안 위협이 발생하는지 설명한다.

### 작성 구성 (이 순서로 서술)

1. **현황 설명**: 어느 파일의 어느 로직에서 문제가 발생하는지 구체적으로.
2. **보안 위협**: 공격자가 이 취약점을 어떻게 악용할 수 있는지. 실제 영향(데이터 유출, 서버 장악 등).
3. **현재 상태 평가**: 현재 서비스에서 실제 익스플로잇 가능성, 접근 경로, 완화 요소 등.

### 예시 (Bad → Good)

**Bad** (기술 용어 나열):
```
FeedQuery.kt의 incrementOdanjiClickCount()에서 gender 파라미터가 CWE-89에 해당하는
SQL 컬럼명 직접 삽입 패턴으로 사용됩니다.
```

**Good** (구어체, 현황+위협+평가):
```
FeedQuery.kt의 incrementOdanjiClickCount() 함수를 보면, 사용자 성별 코드(gender)가 SQL
컬럼명으로 그대로 문자열 보간되고 있어요. 예를 들어 gender값이 'M'이면
"counter.M_30_VISIT = counter.M_30_VISIT + 1" 같은 SQL이 만들어집니다.

문제는 UserInfo.getGender()가 '01'/'02' 이외의 gender 코드를 받으면 해당 값을 그대로
반환한다는 점입니다. 만약 공격자가 세션 토큰을 위조하거나 인증 로직이 바뀌어서 임의의
gender 값을 넣을 수 있게 된다면, SQL 구문에 악의적인 문자를 삽입해 데이터베이스를
조작하는 SQL 인젝션 공격이 가능해집니다.

현재는 SOI 인증 서버에서 표준화된 값만 발급하고 있어 직접적인 공격 경로는 확인되지
않지만, 이 코드 패턴 자체가 위험합니다. 향후 인증 로직이 수정되거나 다른 호출 경로가
생기면 그대로 인젝션으로 이어질 수 있습니다.
```

### 금지 표현

- "해당 취약점은 CWE-89에 해당합니다" (→ 설명 말미에 CWE 별도 필드로 기재)
- "보안 위협이 존재합니다" (→ 어떤 위협인지 구체적으로)
- "적절한 조치가 필요합니다" (→ 대응방안 필드에 기재)

---

## 3. `recommendation` — 번호 매긴 실질적 대응방안

**실제로 개발자가 코드를 어떻게 고쳐야 하는지 구체적으로 작성한다.**
여러 항목은 반드시 번호(`1. 2. 3.`)를 붙여 줄바꿈으로 구분한다 — Confluence에서 번호 목록으로 렌더링된다.

### 작성 규칙

- 1번은 **즉시 적용 가능한 핵심 조치** (코드 수정 방법).
- 2번 이후는 **보완 조치** (설정 변경, 검증 로직 추가, 테스트 등).
- 코드 예시가 있으면 description이 아닌 별도 `evidence.code_snippet` 또는 `taint_evidence`에 추가. recommendation 자체에는 간략한 지침만.

### 예시

**Bad** (뭉뚱그림):
```
gender 값을 적절히 검증하고 안전한 방식으로 사용하도록 변경이 필요합니다.
```

**Good** (번호 목록, 구체적):
```
1. FeedQuery.kt의 incrementOdanjiClickCount()에서 gender를 SQL 컬럼명으로 직접 보간하는 방식을 제거하세요. 대신 Kotlin when 표현식으로 허용된 컬럼명을 하드코딩 매핑합니다.
   예: when(gender) { "M" -> "M", "W" -> "W", else -> return }
2. UserInfo.getGender()가 비표준 값을 반환할 수 없도록, 반환 전에 Enum 또는 화이트리스트 검증을 추가합니다.
3. 동일 패턴인 incrementOdanjiLikeCount()도 동일하게 수정합니다.
4. SQL 컬럼명·테이블명 등 SQL 구조 요소에는 외부 파라미터를 절대 직접 삽입하지 않는다는 개발 규칙을 팀 코드 리뷰 체크리스트에 추가합니다.
```

---

## 4. 위험도 (Risk Level) 1~5 등급 기준

보고서 "위험도" 열과 상세 섹션 "심각도" 모두 아래 5등급 숫자 체계를 사용한다.
**영문 severity(Critical/High/Medium/Low/Info)만 기재하지 않는다 — 반드시 숫자 등급도 병기한다.**

| 등급 | 표기 | 영문 | 기준 |
|:---:|:---|:---|:---|
| **5** | 5 매우 위험 | Critical | RCE, 인증 우회, 거래 위변조, 세션 탈취 |
| **4** | 4 고위험 | High | XSS(운영), CSRF, 인증 우회, 민감정보 평문 노출 |
| **3** | 3 중간 위험 | Medium | 설정 오류, 보안 수준 약화, 다른 취약점과 결합 악용 |
| **2** | 2 저위험 | Low | 특정 조건에서 악용 가능, 정보성 취약 패턴 |
| **1** | 1 매우 낮음 | Informational | 운영 영향 없는 수준, 참고용 |

> ※ LLM 재판정으로 severity가 조정된 finding(예: 스캐너는 High, LLM이 저위험으로 판단)은
>    판단 근거를 `manual_review_note`에 기재하고 등급을 실제 위험도에 맞게 조정한다.

**항목별 상세목록 "위험도" 열 작성 형식**: `N 표기명` (예: `5 매우 위험`, `2 저위험`)
**섹션 3 심각도 줄 작성 형식**: `**심각도:** <severity> &nbsp;|&nbsp; **결과:** <result> &nbsp;|&nbsp; **위험도:** N 표기명`

---

## 5. 항목별 상세목록 anchor 링크 규칙

**항목별 상세목록 테이블의 Finding ID 셀은 반드시 해당 섹션 3 상세 앵커로 링크한다.**

- 앵커 이름 규칙: `detail-{finding-id-lowercase}`
  예: `FILE-001` → 앵커 이름 `detail-file-001`, `INJ-001` → `detail-inj-001`
- 섹션 3 상세에 `[[ANCHOR:detail-{id}]]` 마커 삽입 (publish_confluence.py가 Confluence anchor macro로 변환)
- 항목별 상세목록 Finding ID 셀 HTML: `<a href="#detail-{id}">FINDING-ID</a>`

```html
<!-- 항목별 상세목록 테이블 Finding ID 셀 — Confluence 네이티브 형식 필수 -->
<td><ac:link ac:anchor="detail-inj-001"><ac:plain-text-link-body><![CDATA[INJ-001]]></ac:plain-text-link-body></ac:link></td>

<!-- 섹션 3 상세 앵커 (publish_confluence.py가 anchor macro로 변환) -->
[[ANCHOR:detail-inj-001]]
#### INJ-001 — 제목
```
> ⚠️ HTML `<table>` 내에서 `<a href="#...">` 방식은 Confluence Server에서 앵커 이동이 동작하지 않는다.

> ※ 섹션 3에 상세 항목이 없는 집계성 행(예: XSS-AUTO)은 링크 없이 plain text로 기재한다.

---

## 6. JSON finding 구조 체크리스트

finding 하나를 완성하기 전에 아래를 모두 확인한다:

```
[ ] evidence.file — 소스 파일 경로 기재
[ ] evidence.lines — 라인 번호(범위) 기재
[ ] evidence.code_snippet — 취약 코드 직접 인용 (10줄 이상 권장)
[ ] description — 현황+위협+평가 구어체 3단 구성 완료
[ ] recommendation — 번호 목록 (1. 2. ...) 2개 이상
[ ] affected_endpoints — [{method, path, ...}] 구조로 영향 API 명시
[ ] 동일 패턴 반복형 취약점이면 영향 엔드포인트 전수 기재 여부 확인 (7절)
     — scope.affected_files[]에 확정분 전건 + report_expand에 확정/제외 표
[ ] cwe_id / owasp_category — 기재 완료
[ ] severity — 영문 등급 기재 (Critical/High/Medium/Low/Informational)
[ ] risk_level — 숫자 등급 (1~5) 필수 병기. severity와 일치 확인 (4절 기준)
             예: severity="High" ↔ risk_level=4
[ ] llm_checked — 최상위 필드가 true 인지 확인 (false이면 sec-review 진행 불가)
```

> **⚠️ `risk_level` 누락 시 보고서 위험도 컬럼이 공란으로 출력된다. 반드시 포함.**

코드 증적(`code_snippet`)이 없으면 finding을 미완성으로 간주한다.


---

## 7. 동일 패턴 반복형 취약점의 영향 엔드포인트 전수 명시 (필수)

> **적용 대상**: 하나의 근본 원인(정제 계층 부재 등)이 여러 엔드포인트에 동일하게 나타나는 취약점.
> 대표적으로 **Persistent XSS**(자유 텍스트 DB 저장 API), 전역 필터 부재, 공통 유틸 기반 SQL Injection,
> 동일 업로드 핸들러를 공유하는 파일 업로드 취약점 등.
>
> **도입 근거 (2026-09-18 sample-game-backend XSS-002)**: Auto-Scan 취약 후보 42건 중 대표 샘플 7건만
> finding에 기재되어 보고서에 나갔고, 실제로는 자유 텍스트를 저장하는 API가 24건이었다.
> 개발팀이 조치 범위를 특정할 수 없었고, 사용자 지적으로 17건을 사후 보강해 재게시해야 했다.
> 영향 범위 목록은 조치 범위 그 자체이므로, 샘플이 아니라 전수로 확정되어야 한다.

### 7.1 원칙

1. **확정분은 전건 기재.** `scope.affected_files[]`에 확정(정탐)된 엔드포인트를 빠짐없이 넣는다.
   건수가 많다는 이유로 "외 N건"으로 줄이지 않는다. 이 배열이 최종 보고서 영향 범위의 근거다.
2. **제외분도 명시.** 후보였으나 조치 대상이 아닌 엔드포인트는 사유와 함께 `report_expand`에 남긴다.
   제외 근거가 보고서에 없으면 개발팀이 "왜 이 API는 빠졌는지"를 검증할 수 없고,
   재진단 시 같은 판단을 반복하게 된다.
3. **"미확인"으로 종결 금지.** 후보 전건은 확정 / 제외 / 타 finding 이관 중 하나로 분류한다.
4. **입력 경로가 다른 건은 분리.** 같은 취약 유형이라도 입력 경로(JSON 본문 / multipart 폼 /
   엑셀·CSV 파싱 등)가 다르면 조치 방법이 달라지므로 별도 finding으로 나누거나,
   최소한 표에서 경로를 구분해 표기한다 — 전역 정제로 덮이는 범위가 달라지기 때문이다.

### 7.2 report_expand 표 형식

**확정 목록** — 컨트롤러 / 엔드포인트 / 자유 텍스트 필드 / 저장 sink 4열을 기본으로 한다.

```markdown
### 동일 패턴 추가 확인 엔드포인트

| 컨트롤러 | 엔드포인트 | 자유 텍스트 필드 | 저장 sink |
|---|---|---|---|
| UserQuestionBoardController | `POST /api/v1/board/question` | `title`, `contents` | `QuestionRepository.save()` |
| PartnerDepartmentController | `POST /api/v1/partner/{seq}/department` | `name` | `DepartmentRepository.save()` |
```

**제외 목록** — 엔드포인트 / 제외 사유 2열 이상.

```markdown
### 조치 대상에서 제외한 엔드포인트

| 엔드포인트 | 제외 사유 |
|---|---|
| `POST .../employee/unlock` | `employeeIds` 식별자(Long) 목록만 수신 — 페이로드 삽입 불가 |
| `POST .../auth/verify-otp` | 인증 계열, 형식 고정(숫자 6자리) |
```

동일 사유가 여러 건이면 한 행으로 묶고 건수를 병기해도 된다(예: `배치·인증 계열 19건`).

### 7.3 집계 일관성

`scan_coverage.result_breakdown`(엔드포인트 기준)과 finding 건수는 서로 다른 모수이므로 혼용하지 않는다.
summary와 보고서에서 둘을 함께 제시할 때는 **"finding 기준" / "엔드포인트 기준"으로 표를 분리**하고,
`result_breakdown_basis`에 원본 취약 → FP 제외 → 소스 검증 이관 → 최종 확정까지의 산출 경로를 문장으로 남긴다.

### 7.4 기계적 백스톱

`tools/check_endpoint_coverage.py`가 Auto-Scan 취약 엔드포인트 전건이 finding에 등장하는지 대조한다.
`/sec-review` §5b 자기일관성 검증 단계에서 자동 실행되며, 누락 엔드포인트가 나오면
해당 finding의 `affected_files`/`report_expand`를 보강한 뒤 진행한다.

