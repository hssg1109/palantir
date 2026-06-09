## Task: 2-3 XSS 취약점 검토 (LLM 수동분석 보완)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>/xss.json` (scan_xss.py 자동스캔 결과)
**출력 파일**: `state/<prefix>/task23_llm.json` (LLM 수동분석 보완 — supplemental)
**게시 방식**: `findings_XSS.json`으로 통합하여 /sec-review 대상으로 전달

---

### [데이터 탐색 지침] — 토큰 절약 필수

> **원시 JSON 전체를 컨텍스트에 로드하지 말 것.** 아래 절차를 따른다.

1. **먼저 요약본만 로드**: `state/<prefix>/xss_llm_summary.json` 을 읽는다.
   - 포함 내용: 전체 건수·유형별 통계(`xss_category` 분류 포함), 원본 파일 경로, 카테고리별 대표 샘플 1~2건.
2. **상세 데이터가 필요할 때만 원본 접근**: `full_result_path` 의 경로를 `FileRead` 도구로 열되, **전체 파일을 한 번에 읽지 않는다**.
   - `endpoint_diagnoses[N]` 한 건이 필요하면 `offset`/`limit` 파라미터로 해당 위치만 읽는다.
   - DOM XSS 전역 스캔 결과는 원본의 `scan_metadata.dom_xss_scan` 섹션만 부분 읽기한다.
3. **탐색 우선순위**: `xss_category: 실제위협` → `잠재적위협` → `수동확인필요` 순으로 처리한다.
   - 요약본의 `samples_by_category` 에서 카테고리별 대표 케이스를 먼저 확인한다.

> ⚠️ **이 JSON은 자동스캔 결과와 통합된다.** LLM-Check 완료 후 `findings_XSS.json`에 병합하여 /sec-review 대상으로 전달.

> 📋 **Finding 작성 기준**: `references/finding_writing_guide.md` 필수 준수
> - `evidence.code_snippet`: 취약 코드 직접 인용 필수 (없으면 finding 미완성)
> - `description`: 현황 → 보안 위협 → 현재 평가 3단 구어체 서술
> - `recommendation`: 번호 목록(`1. 2. 3.`) 2개 이상, 구체적 코드 수정 방법 포함

> 📋 **취약점 분류 기준**: `shared/references/vuln_taxonomy.md` 필수 참조
> - `category` / `cwe_id` / `owasp_category` / 기본 `severity` / `scope.type` 은 이 표를 기준으로 결정
> - **금지** category 값 예시: `XSS`, `크로스 사이트 스크립팅`, `Persistent/Reflected XSS`, `Stored XSS`, `XSS필터`, `xss_filter`

---

### 진단 프로세스 (2단계)

> 토큰 절약을 위해 **스크립트 자동 진단 → LLM In-place 업데이트** 2단계로 진행합니다.

#### 1단계: 스크립트 자동 진단 (사전 실행)

```bash
python3 shared/scripts/scan_xss.py <source_dir> \
    --api-inventory state/{prefix}_api_inventory.json \
    -o state/{prefix}_xss.json
```

#### 2단계: LLM 검증 및 findings_XSS.json 생성 (이 프롬프트의 역할)

> **LLM은 `xss.json`의 auto_findings[]를 검토한 뒤 `findings_XSS.json`을 새로 작성한다.**
> xss.json은 Auto-Scan 원본 증적으로 보존하며 수정하지 않는다.
>
> **LLM이 채워야 하는 finding별 필드:**
> - `fp_corrected`: true | false  — FP 확정 시 true
> - `llm_verdict`: `"TP"` | `"FP"` | `"needs_review"` — LLM 최종 판정
> - `llm_reviewed_at`: ISO8601 타임스탬프 (현재 시각)
> - `manual_review_note`: 판정 근거 요약 (코드 경로 또는 FP 이유, 비워두지 않음)
>
> **Root Cause finding (`finding_type: "root_cause"`) 처리:**
> - `affected_endpoints[]` 배열에서 대표 샘플 3-5건을 직접 코드 추적하여
>   Taint 확정 여부와 Data Type(String/Integer/Enum)을 검증한다.
> - 전체 그룹의 대표 판정을 `llm_verdict`에 기록하고,
>   `manual_review_note`에 "확정 N건 / FP M건 / 추가 검토 K건" 형식으로 기재한다.
> - FP가 과반이면 `fp_corrected: true` + `llm_verdict: "FP"`로 설정한다.
>
> **findings_XSS.json 생성 절차:**
> 1. `xss.json`의 `auto_findings[]` 전체를 읽는다.
> 2. 각 finding을 순서대로 LLM 검토한다.
> 3. **TP/needs_review 항목** → findings[] 에 포함. `llm_verdict`, `manual_review_note`, `evidence.taint_flow` 채움.
> 4. **FP 항목** → findings[] 제외, evidence_trail[] 에 기록 (`fp_corrected: true`).
> 5. LLM이 신규 발굴한 취약점 → findings[] 에 추가 (`source: "llm-check"`).
> 6. findings[] severity 내림차순 정렬 후 finding_id 최종 부여 (XSS-001, XSS-002, ...).
> 7. `state/<prefix>/findings_XSS.json` 저장 (`llm_checked: true`).

스크립트 결과 JSON을 로드하여 아래 항목을 검토합니다:

1. **`result: 정보` + `xss_category: 잠재적위협` (Persistent XSS 후보) 심층 분석 [필수]**

   > ⚠️ **`잠재적위협` → `REST_JSON이면 양호` 처리 금지**
   > REST_JSON(application/json)은 Reflected XSS 경로를 차단하지만, Persistent XSS에는 무관하다.
   > `잠재적위협` 항목은 반드시 **DB write 여부를 직접 코드로 확인**한 후 판정한다.

   **`잠재적위협` 판정 절차 (순서대로 적용):**

   **Step 1**: xss.json에서 해당 endpoint의 `call_chain` / `taint_path` 확인
   - `Repository.save()` / `insert()` / `update()` 직접 호출 경로가 있는가?

   **Step 2**: DB write 경로 확인 시 → 저장 필드 타입 검증 (Persistent XSS 식별 3원칙 원칙 2)
   - `String` / `TEXT` → **실제위협** (취약 확정, xss_category_after_review: `실제위협`)
   - `Integer` / `Boolean` / `Enum` / `UUID` → **양호 (FP)** (페이로드 삽입 불가)

   **Step 3**: DB write 경로 미확인 시 (taint tracking 실패) → Service/Repository 코드 직접 탐색
   ```bash
   # call_chain에서 Service 클래스명 확인 후 직접 탐색
   rg "Repository|Mapper|JdbcTemplate|save|insert|update" testbed/<repo>/src -l | head -10
   ```
   - 확인 후 Step 2 적용

   **Step 4**: Kafka/MQ 경유만 확인 → **잠재적위협 유지** (async taint break, 여전히 취약 카운트)
   - xss_category_after_review: `잠재적위협(Async Taint Break)` 기록

   **Step 5**: DB write 없음 확정 (FeignClient/외부 API 전용, 조회 only) → **양호 (FP)**
   - xss_category_after_review: `안전확인` 기록

   > **요약**: DB write 직접 확인 → 실제위협 / 타입이 숫자·Enum → FP / DB없음 확정 → FP / Kafka만 → 잠재적위협 유지

2. **`result: 정보` + `xss_category: 수동확인필요` 심층 분석 [필수]**
   - `수동확인필요` (HTML_VIEW 미탐지): 실제 컨트롤러 소스 확인 → `ResponseEntity<Protobuf/JSON>` 반환이면 View XSS **양호**. `@ResponseBody` + `produces="text/html"` JSP 렌더링이면 JSP 출력 이스케이핑 확인.
   - `수동확인필요` (Reflected XSS text/html): 파라미터가 JSP 출력에 직접 반영되는지 추적. `StringEscapeUtils.escapeHtml()` / `<c:out>` 적용 여부 확인.
   - `수동확인필요` (REST_JSON controller): Content-Type: application/json → Reflected/View XSS **양호**. (단 Persistent XSS는 별도로 Step 1~5 적용 필요)

2. **판정 결과 저장**: `xss_endpoint_review` 블록으로 저장

3. **XSS 필터 충분성 검증** (전역 필터 결함 finding 생성)

---

### 컨텍스트
Task 2-1에서 추출한 API 인벤토리를 기반으로 **Persistent XSS**, **Reflected XSS**, **Redirect XSS**, **View XSS**, **DOM XSS** 취약점을 정적 분석합니다.

---

### View XSS 진단 범위 (레이어 구분)

> **View XSS는 두 레이어를 모두 포함한다.** 레이어별 탐지 방법과 스캐너 한계를 구분하여 적용한다.

#### A. 서버사이드 템플릿 View XSS (scan_xss.py Step 2)

- **대상**: `.jsp`, `.html`(Thymeleaf), `.ftl`(FreeMarker), `.vm`(Velocity) 등 서버가 렌더링하는 View 파일
- **탐지**: `scan_xss.py`가 Controller → View 파일을 추적하여 naked EL / 미이스케이핑 자동 탐지
- **한계**: **API 인벤토리에 등록된 Controller가 렌더링하는 View만 탐지** → 컨트롤러 없이 직접 접근 가능한 JSP(`WEB-INF` 외부)는 미탐지
- ⚠️ **직접 접근 가능 JSP 수동 보완 필수**: `src/main/webapp/` 하위 JSP 중 `WEB-INF` 외부에 있는 파일은 URL로 직접 호출 가능 → `request.getParameterMap()` 등 HTTP 파라미터 직접 렌더링 패턴 확인

```bash
# WEB-INF 외부 JSP 확인 (직접 접근 가능)
find src/main/webapp -name "*.jsp" ! -path "*/WEB-INF/*"
```

#### B. 프론트엔드 JS/TS/Vue View XSS (scan_xss.py Phase 6 = DOM XSS 스캔)

- **대상**: `.js`, `.ts`, `.vue`, `.tsx`, `.jsx` 프론트엔드 소스 파일
- **탐지**: `scan_xss.py`가 `dom_xss_scan`으로 전역 스캔 (`scan_metadata.dom_xss_scan` 참조)
- **탐지 패턴**: `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`, `$().html()`, `document.write()` 등
- **한계**: 빌드 결과물(`dist/`, `build/`) 및 `node_modules/` 제외, **원본 소스가 없으면 탐지 불가**
- `js_files_scanned: 0`이면 프론트엔드 소스 없음 (React/Vue/Angular 별도 레포 분리 구조 가능) → 별도 레포 존재 시 해당 레포도 진단 대상에 포함해야 함

**레이어별 진단 요약:**

| 레이어 | 파일 위치 | 스캐너 커버 | LLM 수동 보완 필요 |
|---|---|---|---|
| 서버 템플릿 (WEB-INF 내) | `WEB-INF/jsp/*.jsp` | ✅ Controller 추적으로 탐지 | needs_review 항목 |
| 서버 템플릿 (WEB-INF 외) | `webapp/static/*.jsp` | ❌ 미탐지 | **수동 직접 확인 필수** |
| 프론트엔드 JS | `.js/.ts/.vue` | ✅ dom_xss_scan | js_files_scanned=0 시 확인 |
| 프론트엔드 별도 레포 | 별도 레포 | ❌ 미탐지 | 진단 대상 범위 확인 필요 |

---

### 파일 탐색 전략 (토큰 최적화)

> **전체 소스코드를 탐색하지 마세요.** 아래 순서로 필요한 파일만 추적합니다.

1. `state/<prefix>/xss.json`에서 auto-scan 결과 로드
2. 각 API의 **Controller 파일**을 확인 → `@Controller` vs `@RestController` 어노테이션 판별
3. Controller에서 View로 데이터를 전달하는 패턴 확인 (`model.addAttribute()` 등)
4. **View 파일** 추적: JSP, Thymeleaf, Pug, React/Vue/Angular 컴포넌트
5. **WEB-INF 외부 JSP 수동 확인** (스캐너 미탐지 영역)
6. 전역 필터/인터셉터 확인: XSS 필터 설정 (web.xml, SecurityConfig, Lucy Filter 설정 등)

```
API 목록 → Controller (@Controller/@RestController 판별)
              ├→ Service → DB 저장 로직 (Persistent XSS)
              ├→ View 파일 WEB-INF/jsp/ (서버 템플릿 View XSS) ← scan_xss.py 탐지
              ├→ webapp/static/*.jsp 직접 접근 JSP (서버 템플릿 View XSS) ← 수동 확인
              ├→ Redirect 로직 (sendRedirect/forward) (Redirect XSS)
              └→ JS/TS/Vue 파일 전역 스캔 (DOM XSS) ← scan_xss.py dom_xss_scan
```

---

### 1. Persistent XSS (저장형)

사용자 입력 파라미터가 **DB에 저장될 때** XSS 필터링 없이 저장되는 경우.

**진단 방법:**
1. Controller → Service → Repository 추적하여 사용자 입력이 DB에 저장되는 흐름 확인
2. 저장 시점에 XSS 필터가 적용되는지 확인
3. 저장된 데이터를 소비하는 모든 View/프론트엔드에서 안전한 출력 인코딩이 적용됨을 **직접 코드로 확인**한 경우에만 하향 가능

**코드 흐름 증적 작성 기준 (Persistent XSS finding 필수):**

> 단순 "DB에 저장될 수 있음" 서술은 증적으로 불충분. 아래 형식으로 실제 저장 경로를 명시해야 한다.

```
[DB 저장 경로] Controller.method() → ServiceImpl.method() → Repository.save()|Mapper.insert()
[저장 필드]   requestParam/requestBody 필드명 → 저장 컬럼명 (확인 가능한 경우)
[필터 적용]   없음 (filter_level: none) | Lucy 미적용 | 커스텀 필터 미작동
```

**대표 증적 선택 우선순위:**
1. taint 경로가 자동 추적 완료된 엔드포인트 (taint_confirmed=true) — call_chain 그대로 인용
2. 자동 추적 실패 시: Controller 소스에서 Service 호출 → Repository/Mapper 호출 수동 추적
3. Repository/Mapper 확인 불가 시: "Service 레이어 호출 확인, Repository 직접 추적 불가" 명시

**대응방안 작성 기준:**
- `filter_level: none` (필터 자체 없음): Lucy XSS Filter 신규 도입 또는 Jackson 커스텀 Deserializer 권고. `skipXss` 언급 금지 (Lucy 미설치 서비스에 해당 없음)
- `filter_level: insufficient` (Lucy 있으나 설정 미흡): `skipXss=false` 설정, multipartFilter 추가 등 구체 설정 명시
- `filter_level: none` + REST JSON 서버: "저장 시점 Jackson ObjectMapper 커스텀 또는 Lucy JSON 모드" 권고

> ⚠️ 위 항목은 Lucy 설정 기준이다. 실제 recommendation 작성은 아래 **"대응방안(recommendation) 작성 기준"** 섹션을 따른다.

---

### ⚠️ Persistent XSS 식별 3원칙 (오탐 방지 필수 적용)

> 이 원칙을 적용하지 않으면 Persistent XSS 오탐(FP)이 대량 발생한다. 자동 스캐너 및 LLM 수동 검토 시 **반드시** 이 순서로 검증한다.

#### 원칙 1 — Sink 도달(DB Write) 검증

HTTP Request 파라미터가 최종적으로 DB 영구 저장소(`INSERT`/`UPDATE` 로직)에 **직접** 도달하는지 추적한다.

| 경우 | 판정 |
|------|------|
| Controller → Service → Repository.save()/insert()/update() 직접 호출 확인 | **Sink 도달 ✓** → 원칙 2로 진행 |
| 조회(SELECT)만 수행하거나 토큰/세션 생성만 수행 | **Sink 미도달 → 즉시 FP (양호)** |
| 단순 로깅(Logger.info) 또는 외부 API 호출만 수행 | **Sink 미도달 → 즉시 FP (양호)** |

#### 원칙 2 — Data Type 검증 (필수)

DB에 저장되더라도, 해당 파라미터가 매핑되는 **엔티티/DTO의 필드 타입**을 확인한다.

| 저장 필드 타입 | 판정 |
|---|---|
| `String` / `VARCHAR` / `TEXT` (자유 텍스트) | **XSS 페이로드 삽입 가능 → 취약 후보** |
| `Integer` / `Long` / `BigDecimal` (숫자) | **페이로드 삽입 불가 → FP (양호)** |
| `Boolean` / `Enum` (열거형) | **페이로드 삽입 불가 → FP (양호)** |
| `UUID` / 식별자 코드값 | **페이로드 삽입 불가 → FP (양호)** |
| 비밀번호 해시 (BCrypt 등) | **해시 후 저장 → FP (양호)** |

> **핵심**: "DB에 저장된다"는 사실만으로 취약 판정 금지. **자유 텍스트 String 필드에 저장될 때만** 취약으로 판정한다.

#### 원칙 3 — Async Taint Break & 보수적 카운팅 원칙 (Kafka/MQ 비동기)

Kafka, RabbitMQ 등 비동기 메시지 브로커로 전송되는 데이터는 **Taint Flow가 끊어진다(Taint Break)**.

| 경우 | 판정 | 카운팅 |
|---|---|---|
| Controller → KafkaTemplate.send()만, Consumer 미추적 | **[잠재 취약 - Async Taint Break]** | **취약 건수에 포함** |
| Consumer에서 Repository.save() + String 필드 확인 | **확정 취약** | 취약 건수에 포함 |
| Consumer에서 숫자/Enum만 저장 확인 | **양호 (FP)** | 제외 |
| Consumer 확인 후 DB Write 없음 | **양호 (FP)** | 제외 |

> **⚠️ Fail-Safe 보수적 카운팅 원칙 (엄격 적용):**
> Consumer 측 Sink 및 텍스트 타입이 **명확히 확인되기 전까지** Kafka 경유 엔드포인트를 FP 처리 금지.
> 보고서 기재: `확정 취약 N건 + [잠재 취약 - Async Taint Break] M건 = 총 (N+M)건`
>
> **조치 방안 필수 문구:**
> *"비동기 메시지(Kafka)를 수신하는 Consumer 측 모듈에서 해당 데이터가 DB의 자유 텍스트 필드로
> 저장되는지 아키텍처 수준의 수동 교차 검증이 필요함."*
>
> **수동 확인:** Producer 코드에서 `KafkaTemplate.send()` 호출 → 동일 레포 또는 연관 레포의 Consumer에서 해당 topic을 구독하여 DB write하는 코드를 `rg "KafkaListener\|@Consumer"` 로 추적한다.

---

**판정 (보수적 기본값 적용):**

> ⚠️ **기본 판정 원칙**: 입력 정제(sanitization)는 저장 시점에 수행되어야 한다 (Defense-in-Depth). 현재 렌더링 컨텍스트가 안전하더라도, 필터 없이 DB에 저장된 데이터는 아키텍처 변경·Admin 화면 추가·데이터 이관 시 즉시 XSS로 발현될 수 있다. **저장 시점 필터 미적용 = 취약**이 기본값이다.
> **단, "Persistent XSS 식별 3원칙" 적용 후 취약 판정 진행한다.**

| 조건 | 판정 |
|---|---|
| 전역 XSS 필터 없이 **자유 텍스트(String) DB 저장** (원칙 1+2 충족) | **취약 (Medium)** |
| 서블릿 필터(Lucy 등) 적용 중이나 `multipart/form-data` multipartFilter 미설정 | **취약 (Medium)** |
| 저장 필드가 숫자/UUID/Enum/Hash 등 HTML 메타문자 포함 불가 타입 (원칙 2) | **양호 — FP** (Data Type 증적 필수) |
| Kafka/MQ로만 전달되고 Consumer 미확인 (원칙 3) | **잠재 위협 — Consumer 측 수동 검토 필요** |
| DB Write 없음 — 조회/토큰/외부API만 (원칙 1) | **양호 — FP** |

#### 1-A. Cross-module Stored XSS 하향 조건 (엄격 적용)

> ⚠️ **하향은 예외다.** 아래 두 조건을 **모두 코드 직접 확인**으로 충족한 경우에만 정보로 하향한다. 확인 불가 시 취약 유지.

**하향(정보) 조건:** 두 조건 모두 충족 시에만 `정보(Entry Point 경고)` 허용.

| 조건 | 확인 방법 |
|---|---|
| ① REST API 전용 서버 — 서버사이드 HTML 렌더링 View 파일 0개 확인 | View 파일(.jsp/.html/.ftl/.vm) 실제 탐색으로 0개 확인 |
| ② **모든 소비자(admin, frontend, batch, 연동 시스템)**에서 출력 인코딩 적용을 코드로 직접 확인 | Admin JSP `<c:out>` / React DOMPurify / 전역 응답 필터 등 직접 코드 확인 |

**판정:**
- 두 조건 모두 충족 + 증적 있음 → **정보: Cross-module Stored XSS Entry Point 가능성**
- 소비자 코드 미확인 / 외부 시스템이 소비자인 경우 → **취약 유지** (소비자 측 안전성 보장 불가)
- REST API가 읽기 전용(GET only) → **해당 없음**

**대응 방안 문구 (recommendation):**
```
저장 시점 XSS 방어 적용 (Defense-in-Depth):
- Jackson JsonDeserializer 커스텀 또는 @ControllerAdvice + @InitBinder로 OWASP HTML Sanitizer(java-html-sanitizer) 적용
- 또는 Spring Lucy XSS Filter (REST JSON 모드) 전역 적용
- 소비자 측 출력 인코딩이 있더라도 저장 시점 방어는 별도로 적용 권고 (계층 방어)
```

#### 1-B. 관리자 전용 기능 Persistent XSS — 심각도 하향만 허용, FP 금지

> ⚠️ **보수적 원칙**: 관리자 전용 기능이라도 Persistent XSS는 **취약으로 보고**한다. 심각도를 낮출 수는 있지만 FP(양호) 처리는 금지한다.

**근거:**
- 관리자 계정이 피싱·자격증명 탈취·세션 하이재킹으로 침해된 경우, 공격자가 악성 콘텐츠를 주입할 수 있다.
- 주입된 콘텐츠가 다른 관리자, 일반 사용자, 또는 배치 시스템으로 전파될 수 있다.
- "관리자만 접근 가능" = 외부 공격자의 직접 접근 불가, "공격 불가능" ≠

| 접근 제어 상황 | 판정 | 심각도 조정 |
|---|---|---|
| 인증 없이 누구나 접근 가능 | 취약 | High |
| 로그인 필요, 일반 사용자 접근 가능 | 취약 | High |
| 관리자(ADMIN role) 전용 기능 | **취약 (심각도 하향 가능)** | **Medium** |
| 관리자 + 접근 IP 화이트리스트 | 취약 | Low |

**Finding 작성 시 필수 포함:**
```
"severity": "Medium",
"access_control_note": "관리자 전용 기능. 관리자 계정 침해 시 Stored XSS 발현 가능."
```

#### 1-C. XSS 필터 우회(Blacklist Bypass) — 프론트엔드 렌더링 미확인 시 취약 유지

XssUtil / AntiSamy 등 커스텀 필터의 **블랙리스트 방식 우회**가 확인된 경우(예: `onerror=`, `onmouseover=` 등 이벤트 핸들러 미차단):

| 프론트엔드 렌더링 확인 여부 | 판정 |
|---|---|
| `innerHTML` / `v-html` / `dangerouslySetInnerHTML` 직접 확인 → XSS 발현 경로 명확 | **취약 (Stored XSS 확정)** |
| 프론트엔드 미확인 (별도 레포, 소스 없음 등) | **취약 (잠재적 Stored XSS)** — 렌더링 미확인이 FP 근거가 되지 않음 |
| `textContent` / JSON API 응답만 사용 확인 | 양호 (FP) — 코드 직접 확인 필수 |

> 필터 우회 페이로드가 DB 저장 → 향후 렌더링 방식 변경 시 즉시 XSS로 발현되므로, **렌더링 컨텍스트 미확인을 이유로 FP 처리 금지**.
> Finding 작성 시: `"rendering_confirmed": false` + `"note": "프론트엔드 렌더링 방식 확인 필요 — 현재 필터 우회 가능 페이로드가 DB에 저장되어 잠재적 Stored XSS"` 명시.

---

### 2. Reflected XSS (반사형)

서버 응답을 통해 사용자 입력이 그대로 클라이언트에 반환되는 경우.

**정적 분석 핵심 판별법:**

| 어노테이션 | 반환 타입 | Content-Type | 판정 |
|---|---|---|---|
| `@Controller` | String (view name) | text/html | **취약** (필터 없으면) |
| `@Controller` + `@ResponseBody` | Object/DTO | application/json | **양호** |
| `@RestController` | 모든 반환값 | application/json | **양호** |

**예외사항:**
- `Gson` 라이브러리 사용 시 `disableHtmlEscaping()` 옵션 → JSON 내 HTML escape 미처리 → **취약**
- `com.google.gson.GsonBuilder` 사용 여부 확인 필요

**JSP 출력 검증:**
- `<c:out value="${값}" />` (escapeXml 기본값 true) → **양호**
- `<c:out value="${값}" escapeXml="false" />` → **취약**
- `${값}`, `<%= %>` 직접 출력 → **취약** (HTML escape 미지원)

**Front로 데이터 전달 패턴:**
- `model.addAttribute()` → JSP 영역으로 데이터 전달 (String, Object, DTO, Map, List 모두 가능) → 확인 필요

---

### 3. Redirect XSS (리다이렉트)

사용자 입력값을 검증 없이 리다이렉트 대상으로 사용하는 경우.

**서버단 검색 키워드:**

| 키워드 | 설명 |
|---|---|
| `redirect:` | Spring 리디렉션 지시어 |
| `sendRedirect(` | Java Servlet 리디렉션 |
| `response.setHeader("Location"` | Location 헤더 수동 설정 |
| `UriComponentsBuilder.fromUriString(` | URI 조합 함수 |
| `@RequestParam("next"/"returnUrl"/"callback")` | 리디렉션용 파라미터 |
| `RequestDispatcher.forward(` | 서버 내부 포워딩 |

**프론트단 검색 키워드:**

| 키워드 | 설명 |
|---|---|
| `location.href =` | URL 이동 |
| `window.location =` | 리디렉션 |
| `document.location` | DOM 기반 처리 |

**판정:**
- 사용자 입력값을 검증 없이 리다이렉트 → **취약**
- 리다이렉트 대상이 화이트리스트/고정 URL → **양호**

---

### 3-B. Redirect XSS — 사용자 입력 확인 필수 원칙

> ⚠️ **XSS/Open Redirect finding 생성 전 데이터 소스를 반드시 확인한다.**
>
> JSP naked EL, `location.replace()`, `form action` 등에서 취약 패턴이 발견되더라도,
> **해당 값이 사용자(HTTP 요청)가 직접 제어할 수 없는 경우** → **정보(Info)** 로 하향한다.

**입력 소스 분류 기준:**

| 입력 소스 | 판정 |
|---|---|
| HTTP 요청 파라미터(`@RequestParam`, `@RequestBody`, `@PathVariable`) → 직접 View 출력 | **취약** |
| 사용자 입력이 암호화/서명되어 서버에 저장됐다가 복호화 후 출력 (공격자가 원본 값 주입 가능한 경우) | **취약** |
| **JOSE/JWE/AES 등으로 암호화된 파라미터** — 복호화 키 없이 내부 필드 변조 불가 | **양호** |
| 외부 서비스(PG사, API Gateway, KCP 등) 서버가 반환한 값 → View 출력 (사용자 직접 제어 불가) | **정보** |
| 서버 내부 설정값(`@Value`, DB 조회 코드값, enum) → View 출력 | **양호** |
| 외부 서비스 응답이지만 MITM/Supply Chain 공격 시나리오만 해당 | **정보** (악용 조건 명시) |

**⚠️ 컨트롤러 다중 경로(성공/실패 분기) 분석 필수:**

HTML_VIEW 컨트롤러가 조건 분기로 여러 JSP를 반환하는 경우, **스캐너가 어느 경로를 탐지했는지 확인하고 모든 경로를 분석**해야 한다.

```
예: tokenIssueAndRedirectionKcp():
  if (Code == "0000") → redirectionToKcp.jsp  (성공 경로)
  else                → callbackPageForError.jsp  (실패 경로)
```

- **LLM은 성공 경로 JSP만 보고 정보 판정 → error path 누락 → 취약 미탐지** 위험
- 스캐너가 탐지한 `phase2_view.view_file` 경로를 반드시 확인하고, **해당 JSP의 데이터 소스를 추적**한다
- 실패 경로 JSP에서 `errorCallbackUrl`, `errorMessage` 등이 사용자 입력에서 파생된 경우 → **취약**

**⚠️ 테스트 엔드포인트 환경 분기 확인 필수:**

`Test`, `Dev`, `Sample` 접미사가 붙은 엔드포인트는 환경 체크 로직이 있을 수 있다.

```java
// 예: prod/alp에서는 하드코딩 반환 → 취약 경로 미노출
if ("alp".equals(active) || "real".equals(active)) {
    modelAndView.addObject("errorCallbackUrl", "/error.html");
    return modelAndView;
}
// dev/stage에서는 실제 로직 실행 → 취약
return this.actualLogic(request);
```

- prod에서 취약 경로가 노출되지 않더라도 **취약 finding으로 기록** (severity는 Medium 하향 가능)
- 테스트 엔드포인트가 prod/alp 배포본에서 실제 비활성화되는지 확인 권고 포함

**정보 분류 시 필수 기재 사항:**
- `diagnosis_type`: `[정보] View naked EL — 사용자 직접 입력 미확인 (외부 서비스 응답 의존)` 형태
- `manual_review_note`: 데이터 소스 추적 결과 (어떤 서비스/메서드에서 값이 오는지 명시)
- `recommendation`: 방어적 코딩 권고 (취약 조치와 동일하나 우선순위 낮음)

---

### 4. View XSS (뷰 단)

View에서 스크립트 문자열이 렌더링될 때 실행 가능한 경우.

**프론트엔드 프레임워크별 취약 패턴:**

| 프레임워크 | 취약 패턴 | 비고 |
|---|---|---|
| React | `dangerouslySetInnerHTML` | HTML 직접 삽입 |
| Vue | `v-html` | HTML 직접 삽입 |
| Angular | `innerHTML` 바인딩 | HTML 직접 삽입 |
| Handlebars | `{{{변수}}}` (triple brace) | HTML escape 미적용 |
| jQuery | `.html()`, `.append()`, `.prepend()`, `.after()`, `.before()`, `.wrap()`, `.insert*()` | DOM XSS 취약 |

**jQuery 안전 함수:** `.text()`, `.attr()`, `.prop()`, `.val()`

**Template Engine별 안전 출력:**
- Thymeleaf: `th:text="${}"` → 자동 escape (양호)
- Pug(Jade): `#{}` → 자동 escape (양호, 단 `<script>` + `JSON.stringify` 사용 시 추가 조치 필요)
- JSTL: `<c:out>` + `escapeXml=true` (기본값) → 양호

> **[Context-aware Escaping 수동 점검 필수]** 스캐너가 `<c:out>` 또는 `fn:escapeXml()`을 확인하여 '양호'로 마킹했더라도, 해당 변수가 **`<script> ... </script>` 내부(JavaScript 문맥)** 에 위치하는지 수동으로 확인하십시오. JS 문맥에서는 HTML 이스케이핑만으로 XSS를 방어할 수 없습니다. 스크립트 블록 내부에 출력된다면 이는 **취약(High)**으로 판정 범위를 번복해야 합니다.
>
> 취약 패턴 예시:
> ```jsp
> <script>
>   var data = "<c:out value='${userInput}'/>";  // HTML escape만으로 JS break-out 가능
>   var obj = ${fn:escapeXml(jsonData)};          // </script> 주입 가능
> </script>
> ```
> 안전한 대안: `JSON.stringify()` 적용 후 출력, 또는 서버에서 `\u003c\u003e` Unicode escape 처리

**DOMPurify 적용 확인:**
- `vue-dompurify-html`, `DOMPurify.sanitize()` 등 사용 시 → **양호**

---

### 5. DOM XSS (DOM 기반)

클라이언트 JavaScript가 **DOM을 동적으로 조작**할 때 사용자 제어 데이터가 직접 삽입되는 경우.
서버 응답에 스크립트가 반영되지 않아 서버측 로그에 미노출 — 탐지 난이도 높음.

**취약 패턴 (JavaScript/TypeScript/Vue 파일 탐색):**

| 패턴 | 설명 | 안전 대안 |
|------|------|-----------|
| `element.innerHTML = userInput` | HTML 직접 삽입 | `element.textContent =` |
| `element.outerHTML = userInput` | HTML 직접 교체 | `textContent` |
| `document.write(userInput)` | DOM에 직접 출력 | 사용 금지 권장 |
| `eval(userInput)` | JS 코드 실행 | JSON.parse 등 대안 |
| `insertAdjacentHTML(pos, userInput)` | HTML 삽입 | `insertAdjacentText()` |
| `$(el).html(userInput)` | jQuery HTML 삽입 | `$(el).text(userInput)` |
| `dangerouslySetInnerHTML={{ __html: val }}` | React HTML 삽입 | DOMPurify.sanitize() 적용 |
| `v-html="userInput"` | Vue HTML 삽입 | DOMPurify 또는 v-text |
| `[innerHTML]="userInput"` | Angular HTML 바인딩 | DomSanitizer 사용 |
| `setTimeout(userInput)` | 동적 코드 실행 | function 레퍼런스 사용 |

**판정:**
- `innerHTML =` / `document.write()` + 사용자 입력 → **취약**
- `dangerouslySetInnerHTML` / `v-html` + DOMPurify 미적용 → **정보(잠재)**
- `dangerouslySetInnerHTML` / `v-html` + DOMPurify.sanitize() 적용 → **양호**

**자동 탐지:** `scan_xss.py` Phase 6 — JS/TS/Vue 파일 전역 스캔 결과 `scan_metadata.dom_xss_scan` 참조

---

### 6. XSS 필터 충분성 검증

> ⚠️ **전역 XSS 필터 미구현(filter_level: none)은 아키텍처와 무관하게 항상 취약(High)으로 판정한다.**
> - REST API 전용·JSON-only라도 동일 기준 적용 (방어 심층 원칙, 향후 HTML 렌더링 추가 시 즉시 노출)
> - "현재 렌더링이 안전하므로 양호" 판정은 **오진(FP)** — 절대 금지
> - OWASP ASVS V5.2.1(입력 검증), V5.3.1(출력 인코딩) 모두 전역 필터 구현 요구

> **[전역 필터 평가 시 절대 규칙]** `filter_level: none`이거나 필터가 불충분할 때, 스캔 결과에 `HTML_VIEW` 컨트롤러나 `.jsp` / `.html` 템플릿이 단 1개라도 존재한다면, "REST API JSON 응답 구조"를 핑계로 위험도를 하향하는 것을 **엄격히 금지**합니다. 반드시 **현재 위험도: 높음(High)**으로 판정하십시오.

---

#### 6-A. Lucy XSS Filter — 등록 검증 필수 (선언 ≠ 동작)

> ⚠️ **build.gradle/pom.xml에 의존성이 선언되어 있어도, 실제 Filter Chain에 등록되지 않으면 필터가 동작하지 않는다. 반드시 등록 코드를 코드로 직접 확인할 것.**

**검증 대상 (이 중 하나가 반드시 있어야 실제 동작):**

| 등록 방식 | 확인 코드 패턴 |
|---|---|
| Spring Java Config | `FilterRegistrationBean`에 `new XssEscapeServletFilter()` 또는 `new LucyXssServletFilter()` 등록 |
| web.xml | `<filter-class>` 태그에 `XssEscapeServletFilter` 또는 `LucyXssServletFilter` 등록 |
| Spring Boot Bean | `@Bean` 메서드가 `FilterRegistrationBean<XssEscapeServletFilter>` 반환 |

**판정:**

| 상태 | 판정 |
|---|---|
| build.gradle에 `lucy-xss-servlet` 선언 + 등록 코드 없음 | **취약 (High)** — 의존성 선언만으로는 보호 효과 없음 (`filter_level: none`과 동일) |
| `XssEscapeServletFilter` 등록 코드 확인 | Lucy 정상 등록 → multipart 순서 추가 검증 |

```bash
# 등록 코드 확인 grep
grep -r "XssEscapeServletFilter\|LucyXssServletFilter\|FilterRegistrationBean" src/
grep -r "filter-class" src/main/webapp/WEB-INF/web.xml 2>/dev/null
```

---

#### 6-B. Jackson XSS Deserializer — 커버리지 맹점 (@RequestParam 미적용)

> ⚠️ **Jackson XSS Deserializer(`XSSStringDeserializer` 등)는 `@RequestBody`(JSON 역직렬화) 경로에만 유효하다. `@RequestParam`, `@ModelAttribute`, `request.getParameter()` 경로는 Jackson을 거치지 않으므로 이 필터의 보호를 받지 못한다.**

**입력 경로별 Jackson Deserializer 적용 여부:**

| 입력 방식 | 처리 경로 | XSS 필터 적용 |
|---|---|---|
| `@RequestBody` (JSON) | Jackson ObjectMapper 역직렬화 | ✅ XSSStringDeserializer 적용 |
| `@RequestParam` (쿼리스트링/form) | Servlet `request.getParameter()` | ❌ 미적용 |
| `@ModelAttribute` (form 바인딩) | Servlet `request.getParameter()` | ❌ 미적용 |
| `@PathVariable` | URI 파싱 | ❌ 미적용 |

**판정 기준:**

| 상태 | 판정 |
|---|---|
| `XSSStringDeserializer` 전역 등록 + **모든 엔드포인트가 @RequestBody 전용** + `@JsonXssFilter(disable=true)` 없음 | **양호** (`filter_level: jackson_requestbody_only`, 서블릿 파라미터 없음, Secure-by-Default 확인) |
| `XSSStringDeserializer` 전역 등록 + `@JsonXssFilter(disable=true)` 필드 존재 | **취약 (High)** — 해당 필드 개별 추적 필요 (6-C 기준) |
| `XSSStringDeserializer` 전역 등록 + **@RequestParam/ModelAttribute 파라미터 존재** | **취약 (High)** — 해당 파라미터 경로는 필터 미보호 → 별도 Servlet 레벨 필터 필요 |
| Jackson Deserializer만 있고 Lucy/AntiSamy/ESAPI 없음 + @RequestParam 존재 | **취약 (High)** — 전역 Servlet 필터 완전 부재 |

**확인 방법:**
```bash
# Jackson XSS Deserializer 등록 여부
grep -r "XSSStringDeserializer\|addDeserializer.*Xss\|XssStringDeserializer" src/

# @RequestParam 사용 엔드포인트 수 확인
grep -r "@RequestParam" src/main/java/ | grep -v "test" | wc -l
```

**`filter_level: jackson_requestbody_only` 판정 시 LLM 수동 검토 절차:**
1. `scan_xss.py` 결과에서 `xss_category: 잠재적위협`으로 표시된 `[Jackson 필터 커버리지 맹점]` finding 확인
2. `@RequestParam` 파라미터가 응답에 반사되거나 DB에 저장되는 엔드포인트 추적
3. 별도 Servlet 레벨 필터(Lucy, 커스텀 `HttpServletRequestWrapper`) 부재 확인
4. 취약 finding 등록: `"전역 XSS 필터 — @RequestParam 경로 미보호 (Jackson Deserializer 한계)"`

---

#### 6-C. Jackson XSS Deserializer — 전역 등록 시 Secure-by-Default 아키텍처 (오탐 방지 필수)

> ⚠️ **`XSSStringDeserializer`가 `addDeserializer(String.class, ...)` 형태로 전역 등록된 경우,
> `@JsonXssFilter` 어노테이션 유무만으로 보호 여부를 판단하면 오탐이 대량 발생한다.
> 어노테이션이 없는 필드가 오히려 가장 강한 보호를 받는 구조다.**

**판별 전제: 전역 등록 여부 확인 (필수 선행 절차)**

```bash
# WebMvcConfiguration 또는 Jackson 설정 파일에서 전역 등록 코드 확인
grep -r "addDeserializer.*String\|addDeserializer.*String\.class" src/
# 출력 예시: .addDeserializer(String.class, new XSSStringDeserializer())
```

전역 등록이 확인된 경우에만 아래 판정 기준을 적용한다.

**@JsonXssFilter 어노테이션 의미 (전역 등록 전제)**

| 상태 | 동작 | 판정 |
|---|---|---|
| 어노테이션 없음 (기본) | `XssPreventer.escape()` — 모든 HTML 특수문자 엔티티 변환 (가장 강한 보호) | **양호** |
| `@JsonXssFilter` 있음 | `XssFilter.doFilter()` — Lucy 화이트리스트 모드 (허용 태그만 통과, 나머지 이스케이프) | **양호** — Lucy 화이트리스트도 XSS 보호 |
| `@JsonXssFilter(disable=true)` | raw 값 반환 — 보호 없음 | **취약 (High)** |

> **핵심**: `@JsonXssFilter`는 "보호를 활성화"하는 어노테이션이 아니라 "예외 처리 모드"를 지정하는 어노테이션이다.
> 어노테이션이 없으면 기본값이 가장 강한 이스케이프로 적용되는 **Secure-by-Default** 아키텍처다.
> Lucy 화이트리스트는 일부 HTML 태그를 허용하지만, 비허용 태그·스크립트는 이스케이프·제거하므로 **XSS 미보호가 아니다**.

**실제 취약 지점 — `disable=true` grep 필수**

```bash
# 진짜 미보호 필드 탐색
grep -r "@JsonXssFilter.*disable.*true\|disable\s*=\s*true" src/ | grep -i "xss"
```

- 결과 없음 → 전체 `@RequestBody` 경로 **양호**
- 결과 있음 → 해당 필드·엔드포인트 개별 추적 후 DB 저장·응답 반사 여부 확인

**Lucy 화이트리스트 필터 취급 원칙**

- Lucy `XssFilter.doFilter()` 적용 필드를 "필터가 덜 엄격하다"는 이유로 취약 리포팅 **금지**
- 허용 태그 목록(`lucy-xss-superset.xml` 등)을 확인하여 스크립트 실행 가능 태그가 허용 목록에 포함된 경우에만 별도 검토 대상
- 허용 목록에 `<script>`, `<iframe>`, `javascript:` 등이 명시적으로 포함된 경우 → **정보** 수준으로 기록 (구성 검토 권고)

**오탐 예방 — 판정 체크리스트**

```
□ WebMvcConfiguration 등에서 addDeserializer(String.class, ...) 전역 등록 확인?
  → 미확인 시 아래 체크 생략, 일반 판정 절차 적용

□ (전역 등록 확인 후) @JsonXssFilter(disable=true) 필드가 있는가?
  → 없으면 전체 @RequestBody String 필드 양호 처리
  → 있으면 해당 필드만 개별 추적

□ @JsonXssFilter (disable 없음) 필드를 "Lucy만 적용 = 취약"으로 판정했는가?
  → 해당 판정은 오탐 — 즉시 result: "양호" 로 수정
```

---

**전역 필터 존재 여부 판정 (종합):**

| 상태 | 판정 |
|---|---|
| Lucy/AntiSamy/ESAPI 미발견 + 등록 코드 없음 (`filter_level: none`) | **취약 (High)** — 시스템 수준 XSS 입력 정제 계층 완전 부재 |
| Lucy 의존성 선언만, `FilterRegistrationBean`/`web.xml` 등록 코드 없음 | **취약 (High)** — 선언 ≠ 동작 (6-A 기준) |
| `XSSStringDeserializer` 전역 등록 + `@RequestParam` 엔드포인트 존재 | **취약 (High)** — 서블릿 경로 미보호 (6-B 기준) |
| 전역 필터 존재 + `< > ' "` 4개 필터 누락 | **취약 (High)** |
| 전역 필터 존재 + `< > ' "` 모두 필터 + `( ) / #` 일부 누락 | **정보** |
| 8개 문자 모두 필터 + Jackson HTML escape 활성화 | **양호** |

**REST API 전용 서버의 전역 필터 판정:**
- `@RestController` + JSON 반환이라도 전역 XSS 필터 미적용은 **취약 (High)** — "현재 렌더링 안전" 논리로 양호 처리 불가
- Jackson `ObjectMapper` `ESCAPE_NON_ASCII` 전역 적용 시 → **정보** (HTML 이스케이핑이나 완전한 XSS 필터 아님)
- `filter_level: none` + POST/PUT 저장 엔드포인트 다수 → **취약 (High)** (Persistent XSS finding과 연계)

**필수 필터 문자 (8개):**

| 문자 | HTML Entity |
|---|---|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `'` | `&#x27;` |
| `"` | `&quot;` |
| `(` | `&#40;` |
| `)` | `&#41;` |
| `/` | `&#x2F;` |
| `#` | `&#35;` |

**검사 대상 필터 라이브러리:**
- OWASP AntiSamy
- Lucy XSS Filter / Lucy XSS Servlet Filter (SK Planet 사내 표준) — **등록 코드 교차 검증 필수**
- ESAPI
- Java Servlet Filter (커스텀)
- Jackson XSS Deserializer — **@RequestBody 경로만 커버, @RequestParam 별도 검증 필수** / `addDeserializer(String.class, ...)` 전역 등록 시 Secure-by-Default 아키텍처 적용 — `@JsonXssFilter` 유무 판단 전 반드시 6-C 체크리스트 수행

---

### 판정 기준

| 심각도 | 조건 |
|---|---|
| **Critical** | 인증 없는 API + Persistent XSS + 필터 없음 |
| **High** | **전역 XSS 필터 미구현 (filter_level: none) — REST API 전용 포함 전 아키텍처 공통 적용**, Persistent XSS 필터 없음, DOM XSS 사용자 입력 직접 삽입, REST API + 필터 없이 DB 저장 |
| **Medium** | 부분 필터 적용 (필수 4문자 중 일부 누락), Redirect 검증 미흡, DOM XSS 잠재 패턴 + sanitize 미확인 |
| **Low** | @RestController JSON 반환이나 Gson disableHtmlEscaping 사용 |
| **Info** | 전역 필터 있으나 보조 4문자(`( ) / #`) 누락, dangerouslySetInnerHTML / v-html + sanitize 적용 확인 권고, Cross-module Entry Point (소비자 측 안전성 코드 확인된 경우), **View naked EL/JS 컨텍스트 출력이나 사용자 직접 입력 미확인 (외부 서비스 응답·서버 내부값)** |

---

### ⚠️ 완료 조건 자가 검증 (필수 — 미충족 시 Task 미완료)

출력 JSON 작성 전 반드시 아래 기준을 자가 검증하라:

```
□ xss_endpoint_review.group_judgments 배열 각 항목의 endpoints_reviewed 비어있지 않음
  - [] 빈 배열이면 실제 분석 미수행 → 미완료

□ WEB-INF 외부 JSP 확인 수행 여부 명시
  명령: find src/main/webapp -name "*.jsp" ! -path "*/WEB-INF/*"
  결과 없으면: "WEB-INF 외부 JSP 없음" 명시
  결과 있으면: 각 JSP 내 사용자 입력(request.getParameter) 출력 패턴 확인

□ HTML_VIEW 반환 컨트롤러가 있는 경우: 다중 경로 분석 수행
  확인 사항:
  - 컨트롤러의 성공 경로 JSP + 실패/오류 경로 JSP 모두 확인
  - 자동스캔이 탐지한 경로가 성공 경로인지 실패 경로인지 명시
  - 각 경로에서 사용자 입력(errorCallbackUrl 등) 출력 확인

□ 전역 XSS 필터 finding (XSS-NNN 형식 — severity 정렬 후 최종 부여) 포함 여부
  - findings 배열에 전역 필터 평가 항목 필수

□ xss_endpoint_review.total_info_endpoints == xss.json의 실제 정보 endpoint 수
  확인: python3 -c "import json; d=json.load(open('state/<prefix>/xss.json'));
    print(d.get('summary',{}))"

□ owasp_category — 각 finding에 "A03:2021 Injection" 또는 "A01:2021 Broken Access Control" 기재 완료
  (Open Redirect → A01, 나머지 XSS 전종 → A03 / vuln_taxonomy.md 참조)
```

---

## 대응방안(recommendation) 작성 기준

> **핵심 원칙**: 고정 템플릿 복붙 금지. 각 finding의 취약점 유형, 코드 패턴, 서비스 특성(REST API / JSP 뷰 / 프론트엔드)을 반영한 실질적 조치를 번호 목록으로 작성한다.

### 참조 가이드라인

| 가이드라인 | 주요 참조 항목 |
|---|---|
| OWASP Testing Guide v4 | OTG-CLIENT-002 (Reflected XSS), OTG-CLIENT-003 (DOM XSS), OTG-INPVAL-001 (Stored XSS) |
| OWASP ASVS v4.0 | V5.2.1 (입력 유효성), V5.3.1 (출력 인코딩), V5.3.3 (JavaScript 컨텍스트 이스케이핑) |
| OWASP Top 10 2021 | A03:2021 Injection — XSS 공식 대응 전략 |
| KISA 주요정보통신기반시설 취약점 분석 | WA-11 (크로스사이트 스크립트), WA-12 (리다이렉트 취약점 검증) |
| 금융보안원 소프트웨어 보안약점 진단 가이드 | SW-10 (XSS: 출력 인코딩 미적용), SW-16 (검증되지 않은 리다이렉트) |

> 위 가이드라인은 기준·원칙으로 활용한다. recommendation 본문에 가이드라인 이름을 직접 나열하지 않고, **조치 방법을 구체적으로 기술**하는 데 활용한다.

### 취약점 유형별 핵심 대응 방향

| 취약점 유형 | 핵심 대응 방향 |
|---|---|
| **Persistent XSS — filter_level: none** | Lucy XSS Servlet Filter `FilterRegistrationBean` 등록 (전역), REST JSON 서버는 Jackson 커스텀 Deserializer 또는 Lucy JSON 모드 추가. `@RequestParam` 경로와 Multipart 경로 모두 커버 확인 |
| **Persistent XSS — filter_level: insufficient** | `skipXss=false` 강제 설정, `multipartFilter` 추가 등록, `@RequestParam` 미보호 경로에 별도 필터 또는 Validator 추가 |
| **Reflected XSS — JSP 직접 출력** | `<c:out value="${param.xxx}">` 또는 `fn:escapeXml()` 적용. `escapeXml="false"` 속성 제거. 서블릿 필터 적용 전까지 뷰 레이어 이스케이핑 명시 |
| **DOM XSS — innerHTML/v-html/dangerouslySetInnerHTML** | `innerHTML` → `textContent` 대체. HTML 삽입이 불가피한 경우 DOMPurify(`DOMPurify.sanitize()`) 화이트리스트 방식 적용 (OWASP ASVS V5.3.3) |
| **View XSS — JS 컨텍스트 출력 (`<script>var x = '${val}'`)** | 서버에서 `JSON.stringify()` 또는 Unicode escape(`\\uXXXX`)로 인코딩 후 출력. `<script>` 블록 내 직접 EL 출력 패턴 전면 제거 |
| **Open Redirect** | 리다이렉트 URL을 허용 도메인 화이트리스트(`allowedHosts[]`)로 검증 (KISA WA-12). 화이트리스트 외 URL은 기본 페이지로 이동. 외부 URL 파라미터는 서버사이드에서 파싱 후 scheme/host 검증 |
| **XSS 필터 미구현 / 불완전** | (위 filter_level별 항목 참조) `multipartFilter` 등록 여부, `excludePattern` 범위, 필수 4문자(`< > " '`) 차단 여부 교차 검증 |

### recommendation 작성 절차

1. **코드 패턴 파악** — `evidence.code_snippet` 기준으로 어느 레이어(Controller/JSP/JS/Config)의 어떤 패턴이 문제인지 확인
2. **가이드라인 선택** — 위 표에서 취약점 유형에 해당하는 핵심 대응 방향 선택
3. **서비스 컨텍스트 반영** — 스택(Spring MVC / Spring Boot REST / React / Vue), 필터 현황(`filter_level`), 접근 제어 상태를 반영하여 현실적 조치 순서 결정
4. **구체성 기준** — 메서드명·클래스명·설정 파일 경로를 포함해야 조치 가능한 수준으로 간주. "적절히 처리" / "검증 추가" 수준의 추상적 기술은 금지

### 작성 예시

**❌ 추상적 (금지)**
```
1. XSS 필터를 적용하여 사용자 입력을 적절히 처리하세요.
2. 출력 인코딩을 적용하세요.
```

**✅ 구체적 (권장)**
```
1. AgreementController의 저장 경로에 Lucy XSS Servlet Filter를 적용합니다.
   SecurityConfig.java 또는 web.xml에 FilterRegistrationBean을 등록하고
   urlPattern을 "/*"로 설정합니다. REST JSON 전용 서비스라면 Lucy JSON 모드
   (XssSaxFilter)를 Jackson ObjectMapper에 커스텀 Deserializer로 등록합니다.
2. multipart/form-data 업로드 경로는 Lucy multipartFilter를 별도 등록합니다
   (FilterRegistrationBean order를 Lucy 필터보다 낮게 설정).
3. @RequestParam으로 직접 받는 파라미터 경로가 있다면, Lucy 필터의 requestBodyOnly
   옵션 해제 또는 @RequestParam 파라미터에 HtmlUtils.htmlEscape() 수동 적용이
   필요합니다.
```

---

### 출력 형식 (findings_XSS.json)

> **LLM은 xss.json을 수정하지 않는다.** Auto-Scan 원본 증적은 xss.json에 그대로 보존한다.
> LLM-Check 완료 후 `state/<prefix>/findings_XSS.json`을 새로 작성하여 저장한다.

#### findings_XSS.json 최상위 구조

```json
{
  "task_id": "xss",
  "prefix": "<repo>/<skill>/<ts>",
  "generated_at": "<ISO8601>",
  "llm_checked": true,

  "xss_filter_assessment": {
    "has_lucy": false,
    "has_antisamy": false,
    "has_custom_filter": false,
    "filter_default_enabled": false,
    "filter_level": "none",
    "llm_note": "FilterRegistrationBean 없음 확인 — 의존성 선언만 존재"
  },

  "scan_coverage": {
    "total_endpoints": 32,
    "result_breakdown": { "취약": 3, "정보": 5, "양호": 24 },
    "fn_disclaimer": "Auto-Scan taint 추적 실패 항목 존재. LLM 교차검증 완료.",
    "source_files": ["xss.json"]
  },

  "summary": {
    "total_findings": 3,
    "by_severity": { "Critical": 0, "High": 2, "Medium": 1, "Low": 0, "Informational": 0 },
    "by_result": { "취약": 2, "정보": 1 },
    "by_source": { "auto-scan": 1, "llm-check": 2 },
    "fp_corrected": 2,
    "fn_detected": 0
  },

  "findings": [ ],

  "evidence_trail": [ ]
}
```

#### finding 객체 필수 구조

```json
{
  "finding_id": "XSS-001",
  "finding_type": "instance",
  "title": "Persistent XSS — 동의 여부 저장 API agreeYn String 필드 미정제",
  "severity": "High",
  "severity_rationale": "기본값 유지 시 생략 가능. 하향·상향 조정 시 필수 — 예: '로그인 후 본인 데이터만 노출 — High→Medium 하향', '인증 없는 공개 API — Medium→High 상향'",
  "risk_level": 4,
  "category": "Persistent XSS",
  "cwe_id": "CWE-79",
  "owasp_category": "A03:2021 Injection",

  "result": "취약",
  "diagnosis_method": "교차검증(수동)",
  "source": "llm-check",
  "fn_detected": false,
  "fp_corrected": false,

  "llm_verdict": "TP",
  "llm_reviewed_at": "<ISO8601>",
  "manual_review_note": "소스코드 직접 확인: AgreementService.setAgree()→agreementRepository.save(), agreeYn String 저장 확정. 원칙 1+2 충족.",

  "scope": {
    "type": "endpoint",
    "endpoint": "POST /api/{version}/common/agreement/setAgree",
    "handler": "AgreementController.setAgree()",
    "affected_file": "src/.../AgreementService.java",
    "affected_line": 44
  },

  "description": "...",
  "recommendation": "...",

  "evidence": {
    "file": "src/.../AgreementService.java",
    "lines": "44-54",
    "code_snippet": "/* Read 툴로 읽은 실제 코드 */",
    "taint_flow": {
      "source": "HTTP @RequestParam agreeYn (String, 사용자 입력)",
      "sink": "agreementRepository.save(agreement) — String 필드 저장",
      "sanitized": false,
      "hops": 2,
      "call_chain": [
        "AgreementController.setAgree(@RequestParam agreeYn)",
        "AgreementService.setAgree(agreeYn)",
        "agreementRepository.save(agreement)"
      ]
    },
    "taint_evidence": [
      {
        "title": "Taint Path — Controller → Service → Repository",
        "controller_file": "src/.../AgreementController.java",
        "controller_lines": "30-38",
        "controller_snippet": "/* 실제 Controller 코드 */",
        "service_file": "src/.../AgreementService.java",
        "service_lines": "44-54",
        "service_snippet": "/* 실제 Service 코드 */",
        "repository_file": "src/.../AgreementRepository.java",
        "repository_lines": "1",
        "repository_snippet": "/* 실제 Repository 인터페이스 */"
      }
    ]
  },

  "needs_review": false
}
```

#### Root Cause finding (`finding_type: "root_cause"`) LLM 검토 절차

```
1. affected_endpoints[] 에서 대표 샘플 3-5건 선택
2. 각 Controller 파일 Read → Service → Repository 추적
3. DB write 여부 + 저장 필드 Data Type(String/Integer/Enum) 확인
4. 결과 집계:
   - 확정 TP N건: llm_verdict = "TP", manual_review_note에 대표 call_chain 기재
   - FP M건: 각 endpoint 이유(숫자 파라미터만 등) manual_review_note에 기재
   - FP가 전체의 70% 이상: fp_corrected = true, llm_verdict = "FP"
   - 혼재(TP+FP): llm_verdict = "TP" 유지, note에 "TP N건 / FP M건 / 미확인 K건" 기재
```

#### Instance finding (`finding_type: "instance"`) LLM 검토 절차

```
1. scope.endpoint의 Controller 소스 Read
2. [실제위협] View XSS: JSP/Thymeleaf 파일 직접 확인 → 출력 이스케이핑 패턴 검증
3. Redirect XSS: 리다이렉트 파라미터 소스 확인 (외부 서비스 응답이면 FP 가능)
4. DOM XSS: JS 파일에서 사용자 입력 소스→싱크 추적
```

#### 복수 API가 동일 취약점에 해당하는 경우

`scope.affected_files[]` 배열로 처리한다. `scope.endpoint`는 대표 API 1건, 나머지는 `affected_files[]`에 추가.

```json
"scope": {
  "type": "endpoint",
  "endpoint": "POST /api/{version}/common/agreement/setAgree",
  "handler": "AgreementController.setAgree()",
  "affected_file": "src/.../AgreementService.java",
  "affected_line": 44,
  "affected_files": [
    {
      "file": "src/.../AgreementController.java",
      "line": 30,
      "endpoint": "POST /api/{version}/common/agreement/setAgree",
      "handler": "AgreementController.setAgree()"
    },
    {
      "file": "src/.../AgreementController.java",
      "line": 50,
      "endpoint": "POST /api/{version}/common/agreement/push/setAgree",
      "handler": "AgreementController.setPushAgree()"
    }
  ]
}
```

---

### 코드 증적 품질 기준 (필수 준수)

> ⚠️ **코드 증적은 반드시 실제 소스 파일 내용을 사용해야 한다.** 아래 규칙을 반드시 따를 것.

#### 규칙 1: evidence.file — 실제 파일 경로 (디렉토리 금지)

```
✅ 올바른 예: "foundation/oki-rest-config/src/main/java/.../LoggingFilter.java"
❌ 잘못된 예: "foundation/oki-rest-config/src/main/java/.../filter/"  ← 디렉토리
```

#### 규칙 2: evidence.code_snippet — 실제 파일 내용 (생성/추측 금지)

- Read 툴로 해당 파일을 직접 읽어 실제 코드를 복사할 것
- 아래와 같은 생성된 주석 코드는 **절대 사용 금지**:
  ```
  // LoggingFilter만 존재 — XSS 입력 필터 미발견  ← 금지 (생성된 주석)
  // has_lucy: false ...                          ← 금지 (생성된 주석)
  ```
- 파일을 읽지 않고 evidence를 작성하면 반드시 `needs_review: true` 로 표시하고 `manual_review_note`에 "코드 미확인" 명시

#### 규칙 3: evidence.taint_flow — taint 경로 요약 (evidence 안에 포함 필수)

> ⚠️ **`taint_flow`는 반드시 `evidence` 객체 안에 포함한다.** finding 최상위에 두면 sec-review 및 보고서 출력 시 누락된다.

DB 저장 경로 또는 렌더링 경로가 확인된 경우, `evidence.taint_flow`에 요약을 작성한다:

```json
"evidence": {
  "file": "실제 경로/Service.java",
  "lines": "44-54",
  "code_snippet": "/* 취약 코드 핵심 부분 */",
  "taint_flow": {
    "source": "HTTP @RequestParam agreeYn (사용자 입력)",
    "sink": "agreementRepository.save(agreement) — String 필드 저장",
    "sanitized": false,
    "hops": 2,
    "call_chain": [
      "AgreementController.setAgree(@RequestParam agreeYn)",
      "AgreementService.setAgree(agreeYn)",
      "agreementRepository.save(agreement)"
    ]
  },
  "taint_evidence": [
    {
      "title": "Taint Path — Controller → Service → Repository",
      "controller_file": "실제 경로/Controller.java",
      "controller_lines": "66-73",
      "controller_snippet": "/* Read 툴로 읽은 실제 Controller 코드 */",
      "service_file": "실제 경로/Service.java",
      "service_lines": "44-54",
      "service_snippet": "/* Read 툴로 읽은 실제 Service 코드 */",
      "repository_file": "실제 경로/Repository.java",
      "repository_lines": "26",
      "repository_snippet": "/* 실제 Repository 인터페이스/메서드 */"
    }
  ]
}
```

각 taint path마다 Controller, Service, Repository 계층 코드를 모두 Read 툴로 직접 확인하여 첨부한다.

---

### 금지사항
- 추측 금지 (코드 근거 없으면 finding 생성 금지)
- 실제 XSS 페이로드 작성 금지
- 민감정보 포함 금지
- API 인벤토리에 없는 파일을 임의로 탐색 금지

---

## LLM-Check Phase 완료 기준

> **`xss.json`은 수정하지 않는다.** Auto-Scan 원본 증적은 그대로 보존한다.
> LLM-Check 완료 후 `state/<prefix>/findings_XSS.json`을 신규 작성하여 저장한다.

### 완료 절차

1. `state/<prefix>/xss.json`을 Read 툴로 읽는다 (전체 또는 offset/limit 부분 읽기).
2. `auto_findings[]` 배열의 각 finding을 순서대로 LLM 검증한다.
3. **TP/needs_review 항목** → findings[] 에 포함. 아래 필드를 모두 채운다:
   - `llm_verdict`, `llm_reviewed_at`, `manual_review_note` (비워두지 않음)
   - `evidence.taint_flow` (DB 저장 경로 확인된 경우 필수)
   - `evidence.taint_evidence` (계층별 실제 코드, 읽은 경우 필수)
4. **FP 항목** → findings[] 미포함, evidence_trail[] 에 기록 (`fp_corrected: true`).
5. Auto-Scan 미탐지(FN) 신규 발굴 시 findings[] 에 추가:
   ```json
   {
     "finding_id": "XSS-001",
     "finding_type": "instance",
     "fn_detected": true,
     "source": "llm-check(fn-detected)",
     "diagnosis_method": "수동진단(LLM)",
     "llm_verdict": "TP",
     "llm_reviewed_at": "<ISO8601>",
     "manual_review_note": "FN 발견 경로 및 근거"
   }
   ```
6. findings[] severity 내림차순 정렬 후 finding_id 최종 부여 (XSS-001, XSS-002, ...).
7. `state/<prefix>/findings_XSS.json` 저장 (`llm_checked: true`).

### sec-review 대상

`findings_XSS.json`의 `findings[]` 배열이 `/sec-review` 정/오탐 판정 대상이다.
`evidence_trail[]`은 로컬 증적으로 보존된다.
