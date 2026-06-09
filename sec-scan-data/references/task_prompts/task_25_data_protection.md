## Task: 2-5 데이터 보호 검토 (LLM 수동분석 보완)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>/task25.json` (scan_data_protection.py 자동스캔 결과)
**출력 파일**: `state/<prefix>/task25_llm.json` (LLM 수동분석 보완 — supplemental)
**게시 방식**: `findings_DATA.json`으로 통합하여 /sec-review 대상으로 전달

---

### ⛔ HARD RULE — task25_llm.json 출력 전 반드시 준수 (생략·축약 절대 불가)

#### [RULE-1] SENSITIVE_LOGGING — 로그 레벨 단위 병합 (Step 6 엄수)

자동스캔이 탐지한 SENSITIVE_LOGGING 개별 건들을 **반드시 아래 2버킷으로 통합**한다:
- **DATA-LOG-001 (Critical)**: `info / warn / error / fatal` 레벨 PII 로깅 → 전 모듈 통합 1건
- **DATA-LOG-002 (Medium)**: `debug / trace` 레벨 PII 로깅 → 전 모듈 통합 1건

**금지**: 모듈별 분리(`DATA-LOG-001(shoppingtab)`, `DATA-LOG-001(pointcon)`)
**금지**: 파일별 분리(파일당 1건 finding 출력)
**금지**: 자동스캔 개별 finding을 그대로 복사 출력

#### [RULE-2] HARDCODED_SECRET — 파일/환경 단위 병합 (Step 5 엄수)

- 동일 파일 내 여러 라인 → **1개 finding** (lines 배열에 전체 라인 번호 나열)
- 동일 환경의 동일 유형 파일(예: ccdev/*.properties 3개) → **1개 finding**
- `src/main/java/` 또는 `src/main/kotlin/` 경로 = 운영 코드 → `needs_review: false` 강제
- severity 계층: java/kotlin 소스(Critical) > resources/(High) > ccalp(High) > ccdev(Medium) > local(Low)

#### [RULE-3] DTO_EXPOSURE — Controller 코드 직접 확인 후 취약 여부 판정 (Step 7 엄수)

- `affected_endpoints` 비어있음 → 내부 객체 → FP 처리 (finding 생성 금지)
- `affected_endpoints` 있음 → Controller 코드 **직접 Read**해서 판정:
  - 본인 정보 반환 API (Safe by Design) → 양호
  - `@JsonIgnore` / `@JsonSerialize(using=MaskSerializer.class)` 적용 → 양호
  - PII 필드 노출 + 타인 조회 가능 → 취약 (finding 확정)
- 한글 주석 파싱 버그(ex: `민감 필드(//)`, `민감 필드(용)`) → 코드 확인 후 FP 처리

#### [RULE-4] 고객사 민감정보 마스킹 — finding 출력 전 필수 (진단 및 보고서 공통)

`evidence.code_snippet` 및 `manual_review_note`에 **아래 정보 원문 절대 포함 금지**:

| 항목 | 마스킹 규칙 | 예시 |
|---|---|---|
| DB 패스워드·API 키·JWT Secret 원문 | `[REDACTED]` 또는 `****` 로 치환 | `password=[REDACTED]` |
| 자동스캔이 `"**** (마스킹)"` 처리한 값 | 원본 복원 절대 금지, 마스킹 상태 유지 | — |
| **내부 IP 주소** (IPv4) | `[REDACTED_IP]` 로 치환 | `10.1.2.3` → `[REDACTED_IP]` |
| **DB 계정명 (username/account)** | `[REDACTED_ACCOUNT]` 로 치환 | `username=admin` → `username=[REDACTED_ACCOUNT]` |
| **JDBC URL 전체** (IP·포트·DB명·계정 포함) | `jdbc:<type>://[REDACTED_JDBC_URL]` 로 치환 | `jdbc:mysql://10.1.2.3:3306/prod` → `jdbc:mysql://[REDACTED_JDBC_URL]` |
| **내부 호스트명·도메인** (사내망 주소) | `[REDACTED_HOST]` 로 치환 | `db.internal.corp` → `[REDACTED_HOST]` |
| LLM이 Read 툴로 읽은 파일에서 발견 | 기재 전 반드시 마스킹 처리 후 출력 | — |
| 변수명·파일경로·라인번호 | 마스킹 불필요 (비민감 메타데이터) | — |

> **[적용 범위]** 이 규칙은 task25_llm.json(진단 JSON) 및 summary_data.md 양쪽 모두에 적용된다.
> code_snippet 원문이 보고서에 그대로 출력되므로 **JSON 작성 단계에서 마스킹 완료** 필수.

> **[자동 보조]** `scan_data_protection.py v1.4.0+`은 JWT/API Key/AWS Key/Base64 Secret 스니펫에서
> IP·계정·JDBC URL을 `_masked_snippet()`으로 자동 마스킹한다.
> LLM이 직접 Read 툴로 소스를 읽고 snippet을 기재할 때는 위 표를 기준으로 **수동 마스킹 필수**.

> **[추가 보완]** sec-review 전 JSON 파일을 재검토하여 잔여 IP·계정·JWT 등을 수동 치환한다.

#### [RULE-5] review_note — 자동 보고서 포함용 마크다운 섹션 형식 필수

`SENSITIVE_LOGGING` / `API_RESPONSE_PII` / `DTO_EXPOSURE` 카테고리의 finding은
`review_note` 필드에 **`## 섹션 제목 + 마크다운 테이블`** 형식으로 상세 데이터를 작성해야 한다.

`generate_final_report.py`가 `## ` 이후 구간을 자동 추출하여 Confluence `:::expand` 블록으로 렌더링한다.

**필수 형식:**
```
(앞부분 서술 텍스트 — 보고서에서 skip됨)

## 영향 파일 목록 (N건)

| 파일 | 레벨 | PII 필드 | 라인 수 |
|------|------|----------|---------|
| FooService.java | ERROR | mbrId, cardNo | 42, 88 |
...

## (추가 섹션 필요 시 동일 형식 반복)
```

**금지**: HARDCODED_SECRET / SECRET_EXPOSURE 카테고리에 `## ` 섹션 사용 → 보고서에 credential 원문 노출 위험.

**권장 섹션 이름 예시:**

| 카테고리 | 권장 섹션 이름 |
|---|---|
| SENSITIVE_LOGGING (LOG-001) | `## 영향 파일 목록 (N건)` |
| SENSITIVE_LOGGING (LOG-002) | `## 디버그 로그 파일 목록 (N건)` |
| API_RESPONSE_PII | `## PII 노출 엔드포인트 목록` |
| DTO_EXPOSURE (Critical) | `## Critical DTO 클래스 목록` |
| DTO_EXPOSURE (High) | `## High DTO 클래스 목록` |

---

### [데이터 탐색 지침] — 토큰 절약 필수

> **원시 JSON 전체를 컨텍스트에 로드하지 말 것.** 아래 절차를 따른다.

1. **먼저 요약본만 로드**: `state/<prefix>/task25_llm_summary.json` 을 읽는다.
   - 포함 내용: 전체 건수·severity별/category별 통계, 원본 파일 경로, 카테고리별 대표 샘플 1~2건.
   - category 코드: `HARDCODED_SECRET`, `SENSITIVE_LOGGING`, `WEAK_CRYPTO`, `JWT_INCOMPLETE`, `CORS_MISCONFIG`, `SECURITY_HEADER`, `DTO_EXPOSURE`
2. **상세 데이터가 필요할 때만 원본 접근**: `full_result_path` 의 경로를 `FileRead` 도구로 열되, **전체 파일을 한 번에 읽지 않는다**.
   - 특정 카테고리 항목만 필요하면 `offset`/`limit` 로 해당 finding 위치를 조회한다.
3. **탐색 우선순위**: `severity: Critical/High` → `result: 취약` → `result: 정보` 순으로 처리한다.

> ⚠️ **이 JSON은 자동스캔 결과와 통합된다.** LLM-Check 완료 후 `findings_DATA.json`에 병합하여 /sec-review 대상으로 전달.

> 📋 **Finding 작성 기준**: `references/finding_writing_guide.md` 필수 준수
> - `evidence.code_snippet`: 취약 코드 직접 인용 필수 (없으면 finding 미완성)
> - `description`: 현황 → 보안 위협 → 현재 평가 3단 구어체 서술
> - `recommendation`: 번호 목록(`1. 2. 3.`) 2개 이상, 구체적 코드 수정 방법 포함

> 📋 **취약점 분류 기준**: `shared/references/vuln_taxonomy.md` 필수 참조
> - `scope.type` 허용값 5종: `endpoint` / `file` / `config` / `dependency` / `global`
> - **금지** scope.type 값 예시: `list`, `module`, `service`, `frontend-component`
> - `diagnosis_method` 허용값 3종: `자동스캔(SAST)` / `교차검증(수동)` / `수동진단(LLM)`

---

### ⚠️ 모듈 스코프 제한 시 필수 절차

> `scan_data_protection.py`는 `--modules` 옵션을 지원하지 않아 **항상 전체 repo를 스캔**한다.
> 진단 범위가 특정 서브모듈로 제한된 경우 아래 절차를 반드시 따른다.

#### Step 0: in-scope 필터링

`DIAGNOSIS_SCOPE` (예: `wv/pointcon`, `wv/shoppingtab`)가 정의된 경우:

1. `state/<prefix>/task25.json`의 모든 findings를 **파일 경로 기준**으로 분류
   - **in-scope**: `file` 경로에 `DIAGNOSIS_SCOPE` 모듈명 포함 → 이후 단계에서 분석
   - **out-of-scope**: 해당 없음 → `data_protection_assessment.out_of_scope` 섹션에 요약, 분석 생략

2. **오탐(FP) 처리**: in-scope finding이더라도 실제 코드 확인 결과 로깅 내용이 PII/시크릿이 아닌 경우 `false_positives` 섹션에 기록

3. **카테고리별 in-scope finding 0건인 경우** (예: 하드코딩 시크릿 0건, CORS 0건 등)
   - 별도 finding 생성 불필요 — `data_protection_assessment` 내 해당 항목에 `result: "해당없음"` 기록으로 충분

> PII 로깅(SENSITIVE_LOGGING)이 in-scope에서 완전히 0건인 경우에도 `data_protection_assessment.pii_logging` 블록에 명시적으로 `result: "해당없음"`, 확인 근거를 기록한다.

---

### 컨텍스트

`scan_data_protection.py`로 1차 자동 스캔 후, 자동 탐지 한계인 **관리자 페이지 분리**, **DTO 과다 노출 심층 확인**, **needs_review 항목 판정**에 대해 LLM이 보조 분석합니다.
또한 개별 탐지 건수가 많은 카테고리(HARDCODED_SECRET, SENSITIVE_LOGGING)는 **파일/환경/심각도 단위로 병합**하여 최종 보고서 가독성을 높입니다.

```
자동 스캔 (scan_data_protection.py)
  ├─ HARDCODED_SECRET   → CWE-798
  ├─ SENSITIVE_LOGGING  → CWE-532
  ├─ WEAK_CRYPTO        → CWE-327
  ├─ JWT_ISSUE          → CWE-347
  ├─ DTO_EXPOSURE       → CWE-200
  ├─ CORS_MISCONFIGURATION → CWE-942
  └─ SECURITY_HEADER    → CWE-693

LLM 보조 분석 (이 프롬프트)
  ├─ needs_review: true 항목 판정 (케이스 A/B/C)
  ├─ 관리자 페이지 분리 여부
  ├─ DTO 민감 필드 직렬화 우회 확인
  ├─ [병합] HARDCODED_SECRET: 파일/환경 단위 그룹화
  └─ [병합] SENSITIVE_LOGGING: 심각도 단위 그룹화 + FP 노트
```

---

### Step 1: 자동 스캔 결과 검토

`state/<prefix>/task25.json`을 로드하여 다음을 확인합니다:
- `result: "취약"` 항목 → 코드 근거 재확인 후 최종 판정
- `needs_review: true` 항목 → `manual_review_prompt.md` 케이스 A/B/C 기준 심층 분석

---

### Step 2: 관리자 페이지 분리 (자동 스캔 미지원)

**판정 기준:**
- 관리자 페이지가 별도 서버에서 서비스 (물리적 분리) → **양호**
- 동일 서버이나 별개 WAS/포트에서 서비스 (논리적 분리) → **양호**
- 동일 서버+WAS이나 IP 접근제어 (`hasIpAddress`) 적용 → **양호**
- 일반 사용자 페이지와 동일 서버/포트에서 접근 가능 → **취약**

**검색 키워드:** `admin`, `/admin`, `management`, `/manage`, `@PreAuthorize`, `hasRole('ADMIN')`, `hasIpAddress`

---

### Step 3: CORS 심층 확인

자동 스캔이 플래그한 CORS 항목에 대해 추가 확인:

| Origin 설정 | Credentials 설정 | 판정 |
|---|---|---|
| `*` (와일드카드) | `true` | **취약** |
| `*` (와일드카드) | 없음/false | **취약** |
| 특정 URL | `true` | **양호** (단, Origin 우회 확인 필요) |
| 특정 URL | 없음/false | **양호** |
| 미선언 | - | 단순 WEB → 양호, API 서버 → **취약** |

**Origin 우회 확인:**
- `request.getHeader("Origin")` 값을 그대로 응답에 반영하는 코드 → **취약**

---

### Step 4: JWT 보안 심층 확인

자동 스캔이 플래그한 JWT 항목에 대해 추가 확인:
- `parseUnsecuredClaims()` / `parseClaimsJwt()` 호출 → **취약** (미서명 토큰 허용)
- `SignatureAlgorithm.NONE` 사용 → **취약**
- JWT Secret Key가 짧거나 추측 가능 → **취약** (needs_review → 케이스 A 적용)
- JWT 만료 시간(`setExpiration`) 미설정 → **Info**

---

### Step 5: HARDCODED_SECRET — 파일/환경 단위 병합

자동 스캔의 개별 findings를 **파일 경로 및 배포 환경 단위**로 그룹화하여 가독성을 높입니다.

**병합 기준표:**

| 우선순위 | 그룹 기준 | 심각도 상한 |
|---|---|---|
| 1 | 운영 코드(Java/Kotlin 소스) 내 리터럴 → 파일별 1건 | Critical |
| 2 | `src/main/resources/` (공통 설정) → 파일별 1건 | High |
| 3 | `src/main/resources-ccalp/` (ALP/운영 유사) → 파일별 1건 | High |
| 4 | `src/main/resources-cc*/` (개발/스테이지) → 환경별 파일 유형 그룹 | Medium |
| 5 | `src/main/resources-local-*/` (로컬 개발) → 1건 | Low |

**병합 규칙:**
1. 동일 파일 내 여러 라인 → 1개 finding, `lines` 배열에 전체 라인 번호 나열
2. 동일 환경의 동일 유형 파일 (예: ccdev/*.properties 3파일) → 1개 finding, `file` 필드에 쉼표 구분 나열
3. 병합 시 가장 높은 severity 유지
4. `evidence.code_snippet`에 대표 1건만 기재, 나머지는 "외 N건" 표기
5. **운영 자격증명 확정 근거** (`newocbpushreal` 'real' 접미사, `IS_DEBUG=false` 분기 등)는 `manual_review_note`에 명시

**LLM 심각도 상향 조건 (케이스 A):**
- 소스 경로가 `src/main/java/` 또는 `src/main/kotlin/` (운영 코드) → **케이스 A 자동 확정**: `severity: Critical`, `needs_review: false` 강제. 별도 확인 불필요.
- 설정 파일명에 `real`, `prod`, `운영` 포함 → **운영 자격증명 확정**: `needs_review: false` 강제.

> ⚠️ **주의**: `src/main/java/` 경로 findings에 `needs_review: true`를 절대 남기지 않는다. 운영 코드 내 리터럴은 코드 경로만으로 운영 키 확정 근거가 된다.

> 🔍 **[휴리스틱 탐지 예외]** `needs_review: true`로 플래그된 `HARDCODED_SECRET` — 특히 `Key`, `InitialVector`, `IV`, `HASH_SALT`, `ECG_AES_KEY` 등 **도메인 전용 변수명 또는 고엔트로피 문자열 휴리스틱으로 탐지된 결과** — 는 `src/main/java/` 경로여도 무조건 Critical로 확정하지 말 것.
> 코드 문맥을 직접 확인하여 다음 세 가지를 판별한 후 severity를 결정한다:
> 1. **실제 사용 여부**: 해당 변수가 `Cipher.init()`, `new SecretKeySpec()`, `MessageDigest` 등 암호화 함수에 실제 전달되는가?
> 2. **테스트/더미 여부**: 변수명, 주석, 파일 경로에 test/mock/dummy/sample 등 힌트가 있는가?
> 3. **환경 구분**: `@Profile`, `application-local.yml`, `@ConditionalOnProperty` 등으로 로컬/개발 환경에만 활성화되는가?
> → 조건 1 충족 + 조건 2·3 불충족 → `severity: Critical`, `needs_review: false` 확정
> → 조건 2 또는 3 충족 → `severity: Informational` 또는 `Low`, `needs_review: false` 처리

---

### Step 5-FE: 프론트엔드(JS/React/Vue) 소스 특수 진단 기준

> 진단 대상이 **프론트엔드(SPA/MPA) 소스코드**인 경우, 아래 추가 기준을 적용한다.
> Java/Kotlin 백엔드 대상에는 해당 없음.

#### HARDCODED_SECRET — 프론트엔드 환경 심각도 및 대응방안

| 상황 | 심각도 | 대응방안 |
|---|---|---|
| 외부 API용 토큰/키가 JS 소스코드에 하드코딩 | **Critical** | BFF 아키텍처 전환 (아래 참조) |
| `.env` 파일이 git 추적 + 빌드 번들 참조 | **High** | `.gitignore` 추가 + CI/CD 환경변수 주입 |
| `.env` 파일이 git 추적이나 소스코드 미참조 | **Medium** | 잔존값 여부 확인 후 `.gitignore` 추가 |

**⚠️ 프론트엔드 환경변수는 시크릿 보관 수단이 아님 (중요)**
- React(`REACT_APP_*`) · Vite(`VITE_*`) 환경변수는 **빌드 시점에 JS 번들에 평문 삽입**됨
- 환경변수로 전환해도 브라우저 다운로드 번들에 노출 → 백엔드 `@Value("${...}")`와 완전히 다른 상황
- `"토큰은 환경변수 또는 Runtime에서 주입"` 문구를 FE 컨텍스트에 **절대 사용 금지**

**올바른 대응 — BFF(Backend For Frontend) 아키텍처:**
```
[AS-IS] 프론트엔드 → 토큰 하드코딩 → 외부 API 직접 호출
[TO-BE] 프론트엔드 → 자사 BFF API → (서버측 환경변수에서 토큰 로드) → 외부 API 대리 요청
```
recommendation 문구 예시:
```
"[아키텍처 전환 필수] 프론트엔드에서 외부 API로 직접 호출하는 구조를 제거하고
자사 백엔드(BFF: Backend For Frontend)를 경유하도록 변경.
BFF 서버가 서버사이드 환경변수에서 토큰을 로드하여 외부 API에 대리 요청 후 결과만 반환.
※ React/Vite 환경변수(REACT_APP_*/VITE_*)는 빌드 시 번들에 평문 포함되므로 시크릿 보관 불가."
```

#### SENSITIVE_LOGGING — 프론트엔드 console.log 특수 기준

| 상황 | 심각도 | 대응방안 |
|---|---|---|
| `console.log`에 세션 ID / 인증 헤더 / PII 출력 | **Info** | 직접 제거 + 빌드 파이프라인 자동 제거 설정 |

**빌드 파이프라인 자동 제거 설정 (recommendation 필수 포함):**
- Webpack: `TerserPlugin` 옵션 `drop_console: true` 적용
- Vite: `build.terserOptions.compress.drop_console = true`
- 수동 제거만으로는 재발 위험 — 빌드 파이프라인 설정을 근본 조치로 제안

---

### Step 6: SENSITIVE_LOGGING — 심각도 단위 병합

자동 스캔의 개별 findings를 **로그 레벨(심각도) 기준 2개**로 통합합니다.

#### 6-0. 허용 목록 / 보호 필수 목록 (FP 판정 기준)

로그 진단 시 아래 목록을 기준으로 TP/FP를 분리한다.

**[허용 목록] — 단독 출력 시 FP, 탐지 결과에서 제외**

| 분류 | 변수/패턴 | 판정 근거 |
|---|---|---|
| 내부 추적 식별자 | `userId`, `feedId`, `feedSeq`, `asumUid` | 애플리케이션 내부 동작 추적용. 고객 식별에 직결되지 않음 |
| 비즈니스 상수/URL | `pushType`, `redirectUri` | 단순 상수값·URL 경로. 개인정보 미포함 |
| 일반 예외 메시지 | `e.message`, `exception.message` | 오류 타입·메시지 텍스트. 단, **토큰 원문·Secret Key가 결합 출력되는 경우는 TP** |

> 허용 목록 변수가 `mbrId`·`authToken` 등 보호 필수 변수와 **동일 로그 라인에 결합** 출력되는 경우 → 보호 필수 변수 기준으로 **TP 처리** (허용 목록 적용 불가).

**[보호 필수 목록] — 로그 레벨 무관, 반드시 TP + 마스킹 필수**

| 분류 | 변수/패턴 | 조치 방안 |
|---|---|---|
| 핵심 고객 식별자 | `mbrId`, `mbrno`, `mbr_id` | **절대 예외 불가** — MaskingUtils.mask() 필수 |
| 인증·세션 토큰 | `authToken`, `accessToken`, `refreshToken`, `httpSession.getId()` | 토큰 원문 마스킹 처리 필수 |
| 개인정보 포함 객체 전체 | `webTokenInfo`, `kmcResult`, `response` (회원 API 응답 전체) | 로그 제외 또는 필드별 마스킹 |
| 암호화 처리 전/후 데이터 | `encryptData`, `plainText` | 평문 결합 로깅 금지 |

**병합 규칙:**

| 버킷 | 조건 | finding 1건으로 통합 | 결과 | 심각도 |
|---|---|---|---|---|
| `high` | `info/warn/error/fatal` 레벨 보호 필수 변수 로깅 | 전체 파일 × 라인 집계 | **취약** | **Critical** |
| `low` | `debug/trace` 레벨 보호 필수 변수 로깅 | 전체 파일 × 라인 집계 | 정보 | **Medium** |

**evidence 기재 방법:**
```
"file": "대표 파일 외 N개 파일 (총 M건)",
"lines": "대표 라인 번호 (대표 샘플)",
"code_snippet": "대표 2~3건 샘플 코드 + (※ 컨설턴트 Note: FP 가능성 있는 항목 명시)"
```

**FP 컨설턴트 노트 기재 기준:**
- 허용 목록 변수(`userId`, `feedSeq` 등)가 단독으로 로깅되는 경우 → FP 처리
- 로그 메시지 문자열 리터럴(예: `"Invalid JWT :"`)에 PII 키워드 포함 + 실제 파라미터는 `e.message` 단독 → FP
- Kotlin 문자열 보간(`$hmacSignature`) — 변수명이 PII 패턴에 일치하나 실제로는 서명값인 경우 → FP
- FP 가능성이 있으면 `code_snippet` 하단에 아래 형식으로 반드시 기재:
  ```
  (※ 컨설턴트 Note: [파일명:라인]의 [코드 패턴]은 FP(오탐) — 보호 필수 변수 미포함.
  [다른 파일:라인]의 mbrId 직접 바인딩은 명백한 취약점(TP)입니다.)
  ```

**대응 방안 필수 포함 항목:**
1. [필수] `mbrId`, `authToken` 등 보호 필수 변수: `MaskingUtils.mask()` 적용 리팩토링 — **"해당 파라미터는 마스킹 처리 필수"** 명시
2. 근본 조치: Logback `MessageConverter` 커스텀 구현으로 전역 자동 마스킹 아키텍처 도입

---

### Step 7: DTO_EXPOSURE 분석 — 엔드포인트 역추적 + FP 방지

#### 7-0. 스크립트 역추적 결과 활용 (포지티브 분석)

`scan_data_protection.py`는 `--api-inventory` 옵션 사용 시 DTO 클래스를 실제로 반환하는 컨트롤러 엔드포인트를 자동 역추적하여 `affected_endpoints` 배열로 제공한다.

**LLM 분석 절차:**

1. `task25.json`의 `DTO_EXPOSURE` findings에서 `affected_endpoints` 배열 확인
2. `affected_endpoints`가 비어 있는 경우 (`endpoint_type: "INTERNAL"` 등): 내부 객체로 API 응답에 미포함 → **FP 처리**
3. `affected_endpoints`에 실제 API 경로가 있는 경우:
   - 해당 DTO 클래스를 직접 읽어 PII 필드 목록 확인
   - 해당 API의 **비즈니스 목적** 파악: 본인 정보 조회(Safe by Design) vs 관리자/목록 조회(취약 가능)
   - `@JsonIgnore`, `@JsonView`, `@JsonSerialize(using=MaskSerializer.class)` 적용 여부 확인
4. 분석 결과를 finding의 `affected_endpoints` 배열로 출력 (method, path, controller, description 구조화)

```
분석 흐름:
task25.json DTO finding
  └─ affected_endpoints 존재 여부
       ├─ 없음(INTERNAL/Consumer DTO) → FP → 7-1~7-4 FP 규칙 적용
       └─ 있음 → 해당 Controller 코드 확인
                   ├─ 본인 정보 반환 API → Safe by Design → 양호
                   ├─ PII 필드에 @JsonIgnore 적용 → 양호
                   └─ PII 필드 노출 + 타인 조회 가능 → 취약 (finding 확정)
```

> `affected_endpoints`가 없고(`[]`) `--api-inventory` 옵션을 사용하지 않은 경우:
> DTO 클래스명으로 Controller 코드를 직접 검색하여 응답 경로에 포함되는지 수동 확인

---

자동 스캐너가 `DTO_EXPOSURE`로 플래그한 항목 중 아래 패턴은 **코드 직접 확인 후 FP 처리**하십시오.

#### 7-1. 스캐너 한글 주석 파싱 버그

스캐너가 필드 선언 끝에 위치한 한글 주석을 **필드명·타입으로 오인**하는 버그가 있음.

| 버그 패턴 | 예시 코드 | 잘못된 스캐너 출력 | 실제 의미 |
|:---------|:---------|:-----------------|:---------|
| 빈 주석 `//` | `private String addr; //` | "민감 필드(//)" | 주석 없음 (FP) |
| 괄호 포함 주석 끝 | `// 카드번호 대용으로 사용되는 MDN 전화번호 (HP포인트 용)` | "민감 필드(용))" | MDN 전화번호 설명 (FP) |
| 키워드 포함 주석 | `// oneIdPass Token` | "민감 필드(Token)" | 주석 내 단어 (FP) |

**판정 기준:**
- `description`에 `민감 필드(//)`가 있으면 빈 주석 파싱 버그 → **FP**
- `description`에 `민감 필드(한글단어)` 형태에서 해당 단어가 Java 타입/필드명이 아닌 한글이면 주석 추출 버그 → **FP**

#### 7-2. 가맹점/비즈니스 주소 vs 고객 개인 주소 구분

`addr` 필드가 고객 PII(개인 주소)인지 비즈니스 데이터(가맹점 주소)인지 **컨텍스트 확인 필수**.

```
확인 절차:
1. 해당 DTO 클래스의 다른 필드 확인 → 쿠폰/가맹점 관련 필드(code, bizNm, couponSeq 등) = 가맹점 주소 → FP
2. 클래스명 확인 → SearchCoupon*, Partner*, Store* 계열 = 비즈니스 데이터 → FP
3. 고객 개인 주소가 포함된 DTO = UserAddress*, OrderDelivery* 계열 = 고객 PII → TP
```

#### 7-3. Safe by Design — 본인 정보 반환

**회원 본인에게 본인 정보를 반환하는 것은 정상 비즈니스 로직**이며 DTO 노출 취약점이 아님.

| 패턴 | 판정 |
|:-----|:---:|
| 인증된 세션 사용자에게 본인 `mbrId` 반환 | **양호 (Safe by Design)** |
| 로그인 응답에 본인 프로필 필드 포함 | **양호 (Safe by Design)** |
| **타인의** `mbrId`/개인정보가 응답에 포함 | **취약** |

#### 7-4. 세션/내부 객체 vs 응답 DTO 구분

스캐너가 모든 클래스를 응답 DTO로 취급하는 경우가 있음. `*Response`, `*Dto`, `*Vo`(응답용)가 아닌 세션 저장/내부 처리 객체는 FP 가능성 점검 필수.

```
확인 절차:
1. 클래스명 확인: UserInfo, SessionHolder, Context* 계열 = 내부 객체 → FP 가능성
2. 패키지 확인: util/session/helper 패키지 = 내부 객체 → FP 가능성
3. @RestController/@Controller 응답 타입 확인: 해당 DTO가 직접 직렬화되는지 확인
4. JSON 직렬화 경로에 없으면 → FP
```

---

### Step 8: TLS 클라이언트 설정 / gRPC 채널 보안 / Redis 직렬화 (Semgrep 스캔 결과 기반)

> **파이프라인**: Auto-Scan Phase에서 Semgrep SSC 피드백 룰이 사전 실행되어
> `state/<prefix>/ssc_feedback_semgrep.json`에 결과가 저장된다.
> LLM은 해당 JSON을 읽어 판정만 수행한다. grep 직접 실행 금지.

#### Step 8 입력 데이터 확인

```
1. state/<prefix>/ssc_feedback_semgrep.json 파일 존재 여부 확인
   - 존재: 아래 8-1~8-3 절차로 findings 판정
   - 미존재: workflow.md Auto-Scan Phase Semgrep 스캔 단계를 먼저 수행 요청
             (scan_data_protection.py 이후 Semgrep 추가 실행 필요)

2. JSON 구조 확인:
   results[].check_id     → 룰 ID (ssl-client-bypass, grpc-plaintext-channel, redis-template-*)
   results[].path         → 탐지 파일 경로
   results[].start.line   → 탐지 라인
   results[].extra.message → 룰 메시지
```

#### 8-1. SSL 인증서 검증 우회 (check_id: ssl-client-bypass)

**판정 기준**:

| 조건 | 판정 |
|------|------|
| `src/test/` 경로 내 탐지 | 양호(FP) — 테스트 전용 |
| `src/main/` + `NoopHostnameVerifier` | **취약** (severity 4) |
| `src/main/` + `loadTrustMaterial(null, ...)` | **취약** (severity 4) |
| `src/main/` + `verify=False` | **취약** (severity 3) |
| 외부 결제사/금융사 통신에 적용 시 | severity 5로 상향 |

**Finding 템플릿**:

```json
{
  "finding_id": "DATA-001",
  "title": "HTTP 클라이언트 SSL 인증서 검증 비활성화",
  "severity": "High",
  "risk_level": 4,
  "category": "INSECURE_TLS_CLIENT",
  "cwe_id": "CWE-295",
  "owasp_category": "A02:2021 Cryptographic Failures",
  "result": "취약",
  "diagnosis_method": "수동진단(LLM)",
  "source": "llm-check",
  "fn_detected": false,
  "fp_corrected": false,
  "scope": {
    "type": "file",
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>"
  },
  "description": "SSL 인증서 검증이 비활성화되어 MITM 공격에 취약합니다.",
  "recommendation": "loadTrustMaterial 제거. 필요 시 해당 CA 인증서만 TrustStore에 등록. NoopHostnameVerifier → DefaultHostnameVerifier 교체.",
  "evidence": {
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>",
    "code_snippet": "<Read 툴로 해당 파일 ±5줄 확인 후 기재>"
  },
  "needs_review": false
}
```

#### 8-2. gRPC 채널 평문 전송 (check_id: grpc-plaintext-channel)

> ⚠️ **MSA/서비스 메시 환경 오탐 주의**: Kubernetes + Istio/Linkerd 환경에서
> `usePlaintext()`는 sidecar proxy가 mTLS를 담당하는 정상 구성일 수 있다.
> 인프라 아키텍처를 확인하기 전까지 "정보/검토필요"로만 분류한다.

**판정 기준**:

| 조건 | 판정 |
|------|------|
| `localhost` / `127.0.0.1` 전용 | 양호(FP) |
| 서비스 메시(Istio/Linkerd) 확인됨 | 양호(FP) — sidecar mTLS |
| 서비스 메시 불명확 / k8s manifest 미확인 | **정보** (severity 2, 검토필요) |
| 서비스 메시 없음 확인 + 외부 서비스 통신 | **취약** (severity 3) |

**Finding 템플릿**:

```json
{
  "finding_id": "DATA-002",
  "title": "gRPC 채널 평문 전송 — 서비스 메시 아키텍처 확인 필요",
  "severity": "Low",
  "risk_level": 2,
  "category": "INSECURE_TLS_CLIENT",
  "cwe_id": "CWE-295",
  "owasp_category": "A02:2021 Cryptographic Failures",
  "result": "정보",
  "diagnosis_method": "수동진단(LLM)",
  "source": "llm-check",
  "fn_detected": false,
  "fp_corrected": false,
  "scope": {
    "type": "file",
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>"
  },
  "description": "gRPC 채널이 평문으로 전송됩니다. 서비스 메시(Istio/Linkerd) 적용 여부에 따라 취약/양호가 달라집니다.",
  "recommendation": "인프라팀과 서비스 메시(Istio/Linkerd) 적용 여부 확인. 서비스 메시 없는 환경이면 useTransportSecurity() 적용 필요.",
  "evidence": {
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>",
    "code_snippet": "<Read 툴로 해당 파일 ±5줄 확인 후 기재>"
  },
  "needs_review": true
}
```

#### 8-3. Redis 직렬화 설정 누락 (check_id: redis-template-default-serializer)

**판정 기준**:

| 조건 | 판정 |
|------|------|
| `StringRedisTemplate` 탐지 | 양호(FP) — StringRedisSerializer 고정 |
| `RedisTemplate` + `setDefaultSerializer()` 없음 | **취약** (severity 4) |
| `RedisTemplate` + `setValueSerializer(new GenericJackson2JsonRedisSerializer())` 있음 | 양호 |
| `ReactiveRedisTemplate` + `RedisSerializationContext` 없음 | **취약** (severity 3) |

**Finding 템플릿**:

```json
{
  "finding_id": "DATA-003",
  "title": "RedisTemplate 기본 JDK 직렬화 — 역직렬화 RCE 위험",
  "severity": "High",
  "risk_level": 4,
  "category": "UNSAFE_DESERIALIZATION",
  "cwe_id": "CWE-502",
  "owasp_category": "A08:2021 Software and Data Integrity Failures",
  "result": "취약",
  "diagnosis_method": "수동진단(LLM)",
  "source": "llm-check",
  "fn_detected": false,
  "fp_corrected": false,
  "scope": {
    "type": "file",
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>"
  },
  "description": "RedisTemplate에 직렬화 설정이 없어 기본 JDK 직렬화가 사용됩니다. 악의적 직렬화 데이터 주입 시 RCE 가능합니다.",
  "recommendation": "redisTemplate.setDefaultSerializer(new GenericJackson2JsonRedisSerializer()) 명시적 추가.",
  "evidence": {
    "file": "<semgrep results[].path>",
    "line": "<semgrep results[].start.line>",
    "code_snippet": "<Read 툴로 @Bean 메서드 전체 확인 후 기재>"
  },
  "needs_review": false
}
```

> **참고**: Semgrep 룰 원본 — `references/rules/semgrep/ssl-client-bypass.yaml`,
> `grpc-plaintext-channel.yaml`, `redis-template-default-serializer.yaml`
> Auto-Scan Phase 실행 명령은 `workflow.md` Phase 2 "Semgrep SSC 피드백 룰 실행" 참조.

---

### Step 9: API 응답 내 UserInfo PII 직접 반환 확인 (API_RESPONSE_PII)

> **목적**: 자동스캔(`scan_api_response_pii()`)은 패턴 기반 탐지이므로 LLM이 수동 확인하여 TP/FP 판정 및 심각도 보정을 수행한다.

#### 9-0. 자동스캔 결과 확인

`task25.json`의 `API_RESPONSE_PII` findings 확인:
- `needs_review: true` → 아래 9-1~9-3 절차로 수동 검증
- `result: "정보"` → 수동 검증 후 "취약" 상향 또는 FP 처리

#### 9-1. 판정 흐름

```
API_RESPONSE_PII 자동탐지 건
  ├─ 본인 정보 반환 API (Safe by Design)
  │     → 인증된 사용자에게 본인 PII를 반환하는 것은 정상 → 양호(FP)
  │
  ├─ PII 비마스킹 + GET/POST 간 마스킹 불일치
  │     → 동일 리소스 GET에서 마스킹하나 POST에서 누락 → 취약 (Medium)
  │
  ├─ PII 비마스킹 + 타인 조회 가능 경로
  │     → 취약 (High)
  │
  └─ PII 비마스킹이나 내부 시스템 전용 (외부 노출 없음)
        → 정보 (Low)
```

#### 9-2. 필수 확인 항목

1. **해당 엔드포인트의 HTTP 메서드와 비즈니스 목적** 파악
   - POST(생성/신청) vs GET(조회): 마스킹 일관성 비교
   - 응답을 수신하는 클라이언트가 인증된 본인인지 확인

2. **동일 리소스 다른 메서드와 마스킹 비교**
   - 예: GET /resource → maskPhoneNumber() 있음, POST /resource → 없음 → **불일치, 취약**

3. **탐지된 필드의 실제 PII 민감도**
   - `mdn` → 전화번호 (High PII)
   - `userName` → 실명 (High PII)
   - `birthDate/birth` → 생년월일 (Medium PII)
   - `mbrId` → 회원 식별자 (Low PII, 본인 정보면 Safe by Design 가능)
   - `ciNo` → CI (Very High PII — KISA 고유식별정보)

#### 9-3. Severity 기준

| 조건 | Severity | Result |
|---|---|---|
| 전화번호(mdn) 또는 실명(userName) + 비마스킹 + GET/POST 불일치 | Medium | 취약 |
| CI(ciNo) 비마스킹 노출 | High | 취약 |
| 생년월일(birthDate) 비마스킹 | Low | 취약 |
| mbrId 본인 반환 | Low | 정보 (Safe by Design 검토) |
| 내부 전용 API (외부 노출 없음) | Low | 정보 |

#### 9-4. RULE-5 — API_RESPONSE_PII finding 작성 기준

- `code_snippet`: 취약한 할당 라인 + 마스킹이 적용된 다른 메서드 코드를 **대조** 제시
- `description`: "POST 응답에 XXX 비마스킹 / GET 응답에는 maskXxx() 적용 → 일관성 결함" 명시
- `category: "API_RESPONSE_PII"`, `cwe_id: "CWE-359"`

---

### ⚠️ 완료 조건 자가 검증 (필수 — 미충족 시 Task 미완료)

출력 JSON 작성 전 반드시 아래 기준을 자가 검증하라:

```
□ SENSITIVE_LOGGING 병합 적용 여부 — 분할 기준은 모듈/파일이 아닌 로그 레벨
  - info/warn/error/fatal 레벨 PII 로깅 전체 → 1개 finding(DATA-LOG-001, Critical)으로 통합
  - debug/trace 레벨 PII 로깅 전체 → 1개 finding(DATA-LOG-002, Medium)으로 통합
  - 동일 PII 타입이 여러 모듈에 걸쳐 있어도 같은 레벨 버킷에 통합 (모듈별 분리 금지)
  ⚠️ 잘못된 패턴: DATA-LOG-001(shoppingtab mbrId), DATA-LOG-002(pointcon mbrId) → 모듈별 분리
  ✅ 올바른 패턴: DATA-LOG-001(info/error 레벨 mbrId, 전 모듈), DATA-LOG-002(debug 레벨 mbrId, 전 모듈)
  - DATA-LOG-001(info/error)과 DATA-LOG-002(debug)가 동시에 존재하는 것은 정상

□ HARDCODED_SECRET 병합 적용 여부
  - 동일 파일 내 여러 라인 → 1개 finding
  - 동일 환경의 동일 유형 파일(ccdev/*.properties 3파일) → 1개 finding

□ data_protection_assessment 블록 존재 여부
  - admin_page_separation, cors_wildcard, jwt_unsigned_allowed 필드 기재 필수

□ findings 배열이 비어 있지 않은 경우 각 finding에 evidence.file(실제 경로) 기재 필수

□ [Step 8] Semgrep SSC 피드백 스캔 결과 참조 여부
  □ state/<prefix>/ssc_feedback_semgrep.json 파일 확인 (Phase 2 사전 실행 필요)
  □ check_id 별 결과 확인: ssl-client-bypass / grpc-plaintext-channel / redis-template-*
  □ 탐지 건 → Read 툴로 해당 파일 직접 확인 후 판정 (Semgrep 탐지만으로 취약 단정 금지)
  □ gRPC usePlaintext: 반드시 "정보/검토필요"로 분류 (취약 단정 금지 — MSA 아키텍처 확인 필요)
  → 0건이면 "해당없음" 기록. Semgrep JSON 미존재 시 Auto-Scan Phase 재실행 요청.

□ [Step 9] API_RESPONSE_PII 수동 검증 여부
  □ task25.json API_RESPONSE_PII findings 확인 (자동탐지 결과)
  □ 각 건: 본인 정보 반환 여부(Safe by Design) 확인
  □ GET/POST 간 마스킹 일관성 비교 — 불일치 시 취약 상향
  □ CI(ciNo) 탐지 건은 High로 상향 검토
  □ FP(내부 전용 API, 본인 반환) vs TP(마스킹 불일치, 타인 조회 가능) 판정
```

**병합 미적용 시 거부 조건:**
- 동일 PII 타입 + 동일 로그 레벨을 모듈별로 분리하여 별도 finding 생성 → **모듈별 분리 금지, 병합 미완료**
- `data_protection_assessment` 키가 없음 → **미완료**

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 소스코드 내 DB 비밀번호/API 시크릿/AWS 키 하드코딩 + 외부 접근 가능 |
| **High** | CORS 와일드카드 + credentials, JWT `none` 알고리즘, 미서명 토큰 허용 |
| **Medium** | 응답 DTO 민감정보 미마스킹, 관리자 페이지 미분리, PII 직접 로깅, Origin 우회 |
| **Low** | 취약 해시(MD5·SHA-1) 사용, 에러 페이지 서버 버전 노출, 주석 내 테스트 계정 |
| **Info** | 보안 개선 권고 (JWT 만료 미설정, AES/CBC→GCM 전환, CORS 정책 강화 등) |

---

### 출력 형식

자동스캔 결과(`<prefix>_task25.json`)를 기반으로, **병합·확정된 findings 전체**를 출력합니다.
HARDCODED_SECRET / SENSITIVE_LOGGING은 Step 5/6 병합 규칙을 적용하여 통합 finding으로 출력하고,
WEAK_CRYPTO / CORS / JWT 등 나머지 카테고리는 자동스캔 확정 항목만 포함합니다.

> **`affected_endpoints` 작성 규칙 (전체 Task 공통)**
>
> 각 finding에서 실제로 영향을 받는 API 엔드포인트를 `affected_endpoints` 배열로 명시하십시오.
> 보고서 렌더링 시 이 목록은 `<details>` 펼치기 섹션 또는 Confluence Expand 매크로로 자동 출력됩니다.
>
> | 필드 | 필수 | 설명 |
> |---|:---:|---|
> | `method` | 권장 | HTTP 메서드 (GET/POST/PUT/DELETE 등). 전역 영향 시 생략 가능 |
> | `path` | **필수** | Request Mapping 경로 (예: `/api/v1/user/login`). 전역 영향 시 "전역 (전체 API)" |
> | `controller` | 권장 | 클래스명.메서드명() (예: `UserController.login()`) |
> | `description` | 권장 | 해당 엔드포인트에서 취약점이 어떻게 발현되는지 한 줄 설명 |
>
> - 특정 엔드포인트에 취약점이 한정되는 경우: 해당 엔드포인트만 기재
> - HARDCODED_SECRET 등 전역 영향: `"path": "전역 (시크릿 참조 전체 API)"` 1건 기재
> - SENSITIVE_LOGGING 다건 병합: 대표 2-3건만 기재하고 `description`에 "외 N건" 표기

```json
{
  "task_id": "data",
  "status": "completed",
  "findings": [
    {
      "id": "DATA-SEC-NNN",
      "title": "[병합 그룹 제목] — 파일명 (N건 병합)",
      "severity": "Critical / High / Medium / Low",
      "category": "HARDCODED_SECRET",
      "description": "(LLM 확정 또는 자동스캔 확인) 상세 설명. 운영 키 확정 근거 포함.",
      "affected_endpoints": [
        {
          "method": "",
          "path": "전역 (시크릿 참조 전체 API)",
          "controller": "",
          "description": "해당 자격증명을 사용하는 모든 외부 연동 엔드포인트에 영향"
        }
      ],
      "evidence": {
        "file": "src/main/resources/config.properties",
        "lines": "214, 1054, 1162, ...",
        "code_snippet": "// 대표 코드 스니펫 (마스킹 처리)\n// 외 N건 — 원본 스캐너 report 참조"
      },
      "cwe_id": "CWE-798",
      "owasp_category": "A02:2021 Cryptographic Failures",
      "diagnosis_method": "교차검증(수동)",
      "result": "취약",
      "needs_review": false,
      "manual_review_note": "[케이스 A 확정] 운영 키 판별 근거 기재",
      "recommendation": "조치 방안 (환경별 단계별 제시)"
    },
    {
      "id": "DATA-LOG-001",
      "title": "운영 환경(info/error) 로그 내 PII 평문 노출 — N건 병합",
      "severity": "Critical",
      "category": "SENSITIVE_LOGGING",
      "description": "운영 활성 로그 레벨에 mbrId/mdn 등 PII가 마스킹 없이 출력됨. PIPA 위반 가능.",
      "affected_endpoints": [
        {
          "method": "POST",
          "path": "/api/v1/user/login",
          "controller": "UserController.login()",
          "description": "mbrId가 log.info()에 직접 바인딩됨"
        },
        {
          "method": "GET",
          "path": "/api/v1/order/list",
          "controller": "OrderController.list()",
          "description": "cardNo가 log.error() 스택트레이스에 포함됨"
        }
      ],
      "evidence": {
        "file": "대표 파일 외 N개 파일 (총 N건)",
        "lines": "대표 라인 번호",
        "code_snippet": "// 대표 샘플\nlog.info(\"mbrId={}\", mbrId);\n\n// (※ 컨설턴트 Note: FP 가능성 있는 항목은 여기에 명시)"
      },
      "cwe_id": "CWE-532",
      "owasp_category": "A09:2021 Security Logging and Monitoring Failures",
      "diagnosis_method": "교차검증(수동)",
      "result": "취약",
      "needs_review": false,
      "manual_review_note": "[케이스 B 확정] info/error 레벨 PII 직접 바인딩 확인. MaskingUtil 미적용.",
      "recommendation": "1) MaskingUtils.mask() 전면 적용.\n2) Logback MessageConverter 커스텀 구현으로 전역 자동 마스킹 아키텍처 도입."
    }
  ],
  "data_protection_assessment": {
    "admin_page_separation": "물리적 분리 / 논리적 분리 / 미분리 / 미확인 중 하나",
    "cors_wildcard": false,
    "jwt_unsigned_allowed": false,
    "hardcoded_secret_consolidated_count": 8,
    "hardcoded_secret_original_findings": 23,
    "sensitive_logging_critical_count": 117,
    "sensitive_logging_info_count": 80,
    "sensitive_logging_consolidated_count": 2,
    "weak_crypto_count": 2
  },
  "consolidation_note": "자동스캔 N건을 파일/심각도 단위로 병합. 원본 개별 findings는 state/<prefix>/task25.json에 증적 보존.",
  "executed_at": "",
  "claude_session": ""
}
```

**ID 명명 규칙:**
- `DATA-SEC-NNN` — HARDCODED_SECRET 병합 그룹 (환경/파일 단위, 001부터 순차 부여)
- `DATA-LOG-001` — SENSITIVE_LOGGING Critical 병합 (info/warn/error/fatal 레벨, 전 모듈 통합)
- `DATA-LOG-002` — SENSITIVE_LOGGING Medium 병합 (debug/trace 레벨, 전 모듈 통합)
- `DATA-LLM-NNN` — 기타 LLM 단독 발견 (WEAK_CRYPTO, DTO 등)

**주의**:
- 원본 자동스캔 JSON(`<prefix>_task25.json`)은 수정하지 않는다. 증적 보존용.
- 병합 findings는 모두 이 LLM 파일(`<prefix>_task25_llm.json`)에만 작성한다.
- findings 배열이 비어 있으면(`[]`) 파일을 저장하되 `supplemental_sources`에서 자동으로 무시된다.

---

### 금지사항
- 추측 금지 (코드 근거 필수)
- 민감정보(실제 비밀번호, API 키 값) 포함 금지 → 마스킹 처리 (`****`)
- 자동 스캔 결과를 번복할 때는 코드 근거 명시 필수
- 스크립트가 이미 판정한 "양호" 항목은 재검토 불필요
- 병합 시 원본 findings의 증적(라인 번호, 파일 경로)을 누락하지 않는다

---

### 코드 증적 품질 기준 (필수 준수)

> ⚠️ **evidence.file은 반드시 실제 파일 경로여야 한다 (디렉토리 금지).
> evidence.code_snippet은 반드시 Read 툴로 읽은 실제 파일 내용을 사용한다.**

- `evidence.file`: **repo root 기준 전체 상대경로** 필수 (`src/main/resources/application-local.properties`, `src/main/java/com/foo/Bar.java` 등) — 파일명만(`application.yml`) 또는 디렉토리 경로 금지
- `evidence.code_snippet`: Read 툴로 직접 읽은 실제 코드만 허용 — 생성/추측 주석 금지
- 파일을 직접 읽지 못한 경우: `needs_review: true` + `manual_review_note: "코드 미확인"` 표시
- 자동스캔 `code_snippet`이 `"**** (마스킹)"` 상태인 경우, LLM 보완 finding 작성 시 반드시 Read 툴로 실제 파일을 읽어 evidence 첨부

---

## findings_DATA.json 생성 (LLM-Check Phase 최종 출력)

LLM-Check Phase 완료 후 `state/<prefix>/findings_DATA.json`을 생성한다.

### 절차

1. `state/<prefix>/task25.json`의 `auto_findings[]` 로드
2. 각 항목 LLM 교차검증 수행:
   - **FP 판정**: `findings[]`에서 **제거**, `evidence_trail[]`에 `fp_corrected: true`로 기록
   - **TP 확정**: description, code_snippet, evidence 보강 (마스킹 항목은 Read 툴로 실제 코드 확인)
3. Auto-Scan 미탐지 취약점(F/N) 발견 시 신규 finding 추가:
   - `fn_detected: true`, `source: "llm-check(fn-detected)"`
4. finding_id 재부여: `DATA-001` 순번 (심각도 내림차순)
5. `state/<prefix>/findings_DATA.json` 저장

### 출력 스키마 (shared/references/output_schemas.md 참조)

```json
{
  "task_id": "data",
  "generated_at": "ISO8601",
  "scan_coverage": {
    "fn_disclaimer": "Auto-Scan은 정적 패턴 기반이므로 런타임 설정 주입(환경변수/Vault 등)·동적 암호화 선택은 탐지 불가"
  },
  "summary": {
    "total": 0, "취약": 0, "정보": 0, "fn_detected": 0
  },
  "llm_checked": true,
  "findings": [
    {
      "finding_id": "DATA-001",
      "title": "",
      "severity": "Critical|High|Medium|Low|Informational",
      "risk_level": 5,
      "category": "HARDCODED_SECRET|SENSITIVE_LOGGING|WEAK_CRYPTO|JWT_INCOMPLETE|DTO_EXPOSURE|CORS_MISCONFIG|SECURITY_HEADER|INSECURE_TLS_CLIENT|UNSAFE_DESERIALIZATION",
      "cwe_id": "CWE-798|CWE-532|CWE-327|CWE-347|CWE-200|CWE-346|CWE-693|CWE-295|CWE-502",
      "owasp_category": "A02:2021 Cryptographic Failures",
      "result": "취약|정보",
      "diagnosis_method": "자동스캔(SAST)|교차검증(수동)|수동진단(LLM)",
      "source": "auto-scan|llm-check|llm-check(fn-detected)",
      "fn_detected": false,
      "fp_corrected": false,
      "scope": {
        "type": "file|config",
        "endpoint": null,
        "file": "path/to/Config.java",
        "line": 42,
        "module": null
      },
      "description": "한국어 설명",
      "recommendation": "조치 방법",
      "evidence": {
        "file": "path/to/File.java",
        "line": 42,
        "code_snippet": "실제 코드 (마스킹 적용)"
      },
      "needs_review": false
    }
  ],
  "evidence_trail": []
}
```
