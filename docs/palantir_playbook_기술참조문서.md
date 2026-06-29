# palantir & playbook 기술 참조 문서

> 자택 고도화 및 이력서 심층 준비용 — 작성일: 2026-06-19

---

## 목차

1. [프로젝트 전체 지형도](#1-프로젝트-전체-지형도)
2. [palantir — 아키텍처 상세](#2-palantir--아키텍처-상세)
   - 2.1 전체 파이프라인
   - 2.2 5개 SAST Skill 상세
   - 2.3 인터랙티브 리뷰 (/sec-review)
   - 2.4 보고서 생성 · 게시 (approve_report.py)
   - 2.5 vuln_registry v2.0
3. [playbook (sec-audit-static) — 아키텍처 상세](#3-playbook-sec-audit-static--아키텍처-상세)
   - 3.1 Phase 1~4 워크플로
   - 3.2 핵심 스캐너 스크립트 로직
   - 3.3 Phase 3 LLM 교차검증 체계
4. [AI 거버넌스 체계](#4-ai-거버넌스-체계)
   - 4.1 데이터 분류 및 마스킹 정책
   - 4.2 LLM 신뢰성 통제 (오탐 제어)
   - 4.3 감사 추적 체계
5. [진단 실적 현황 (2026-06 기준)](#5-진단-실적-현황-2026-06-기준)
6. [기술 스택 요약](#6-기술-스택-요약)
7. [삼성SDS 직무 매핑 — AI 보안정책 관련 경험](#7-삼성sds-직무-매핑--ai-보안정책-관련-경험)

---

## 1. 프로젝트 전체 지형도

```
palantir (공개 레포, ~/palantir/)
│   └── SAST skill 모듈 5개 (injection/xss/file/data/sca)
│   └── /sec-review 인터랙티브 리뷰 skill
│   └── approve_report.py 최종 보고서 + Confluence 게시 + Jira 티켓
│
playbook (비공개 레포, ~/playbook/)
│   └── /sec-audit-static — 전체 파이프라인 통합 오케스트레이션
│       Phase1(자산식별) → Phase2(정적분석) → Phase3(LLM교차검증) → Phase4(Confluence게시)
│   └── tools/scripts/ — 공유 Python 스캐너 스크립트 (원본)
│   └── ai/ — AI 거버넌스 정책 문서 (AI_USAGE_POLICY.md, ai-manifest.yaml)
│
관련 저장소:
  testbed/   — 진단 대상 고객사 소스코드 (gitignored)
  state/     — 진단 결과 JSON / 보고서 (gitignored)
  ~/palantir-reports/ — Confluence 게시된 최종 보고서 누적
  palantir-jira-gateway/ — Jira 티켓 등록 Lambda Gateway
```

### 두 레포의 역할 분담

| 항목 | palantir | playbook |
|------|----------|----------|
| 공개 여부 | 공개 (GitHub) | 비공개 |
| 주요 역할 | 취약점 유형별 독립 SAST 모듈 | 전체 파이프라인 오케스트레이션, 고객사별 설정 |
| 진단 단위 | 취약점 유형 단위 (injection/xss/...) | 레포 단위 (Phase1~4 일괄) |
| AI 활용 방식 | skill-based LLM 교차검증 | taint tracking + LLM 심층진단 |
| 보고서 게시 | approve_report.py → Confluence + Jira | publish_confluence.py → Confluence |

---

## 2. palantir — 아키텍처 상세

### 2.1 전체 파이프라인

```
소스코드 Clone (Windows PowerShell)
  └── tools/clone_repo.py <PROJECT> <REPO>
  └── → testbed/<repo>/

SAST 진단 (5개 skill 순차 실행)
  ├── /sec-scan-injection  → state/<repo>/injection/<RUN_ID>/findings_INJ.json
  ├── /sec-scan-xss        → state/<repo>/xss/<RUN_ID>/findings_XSS.json
  ├── /sec-scan-file       → state/<repo>/file/<RUN_ID>/findings_FILE.json
  ├── /sec-scan-data       → state/<repo>/data/<RUN_ID>/findings_DATA.json
  └── /sec-scan-sca        → state/<repo>/sca/<RUN_ID>/findings_SCA.json

인터랙티브 리뷰
  └── /sec-review <RUN_ID> <repo>
      ├── Step 1b: LLM이 서비스 특징 자동 분석
      ├── 진단자 추가진단 필요여부 입력 (y/n)
      └── finding별 정탐(1)/오탐(0)/스킵(s) 판정
      → state/<repo>/review_meta.json
      → findings_*.json에 review_status 기록

최종 보고서 생성 + 배포
  └── python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish
      ├── logs/final_<repo>_<RUN_ID>.md (Confluence 마크다운)
      ├── Confluence 자동 게시 (REST API)
      ├── Jira 티켓 등록 (palantir-jira-gateway Lambda)
      ├── vuln_registry.json v2.0 갱신
      └── audit_result Bitbucket 업로드
```

### 2.2 5개 SAST Skill 상세

각 skill은 동일한 3단계 구조로 실행된다:

```
Phase 1: 자산 식별
  └── testbed/<repo>/ 소스코드에서 Controller/API 엔드포인트 목록 추출
  └── 기술 스택 감지 (Java/Kotlin/JS/TS)
  └── 프레임워크 확인 (Spring Boot, MyBatis, JPA, React 등)

Phase 2: Auto-Scan (정규식 패턴 매칭)
  └── shared/scripts/scan_*.py 실행
  └── 탐지 결과 → findings_*.json (중간 결과)

Phase 3: LLM 교차검증
  └── 패턴 매칭 결과를 Claude에게 전달
  └── 코드 흐름 분석으로 오탐 필터링
  └── 5단계 교차검증: 데이터흐름 → 타입 → 코드활성화 → 도달가능성 → 최종판정
  └── llm_checked: true로 마킹 + 위험도 재확인
```

#### /sec-scan-injection

진단 항목: SQL Injection / OS Command Injection / SSI Injection / SpEL Injection

스캐너: `shared/scripts/scan_injection_enhanced.py`

핵심 로직:
- **Positional Index Taint Tracking**: HTTP 파라미터 → Service 계층 → Repository 계층 → SQL 실행까지 변수 인덱스(위치 기반)를 추적
- **MyBatis `${}` vs `#{}`**: `#{}` = PreparedStatement 바인딩(안전), `${}` = 문자열 직접 삽입(취약)
- **Kotlin 문자열 보간 탐지**: `"SELECT * FROM user WHERE id = $id"` 패턴 — Fortify 등 상용 도구가 미탐지하는 영역
- **iBatis/MyBatis `<include>` 인라인 치환**: `_resolve_sql_text()` 로 중첩 include를 재귀 처리 (순환 참조 방지)
- **HTTP 클라이언트 자동 양호 확정**: `RestTemplate`, `WebClient`, `FeignClient` 사용 서비스는 자동으로 양호 처리
- **DTO 래핑 taint 추적**: `conservative_fallback` 옵션으로 DTO를 통한 파라미터 전파 추적

판정 4단계:
```
[실제] SQL Injection    → HTTP 파라미터 → SQL taint 경로 확인됨 (정탐)
[잠재] 취약한 쿼리 구조  → 취약 구조이나 taint 미확인 (추가 검토 필요)
양호                    → JPA/MyBatis #{} 바인딩 또는 DB 미접근
정보                    → 외부 모듈 위임·추적 불가
```

#### /sec-scan-xss

진단 항목: Persistent XSS / Reflected XSS / DOM XSS / Open Redirect

스캐너: `shared/scripts/scan_xss.py` (v2.4.0)

핵심 로직:
- **Persistent XSS**: DB 저장 경로(`@RequestBody`→ `save()`) → 출력 경로(`@ResponseBody`→ JSP/템플릿) 연결 확인
- **Reflected XSS**: `@RequestParam`/`@PathVariable` → 응답 본문 직접 반영 Taint Flow 검증
- **DOM XSS**: `document.write()`, `innerHTML`, `eval()`, `location.href` 등 Sink 탐지 + `postMessage` origin 미검증
- **Open Redirect**: `redirect:` + 사용자 입력, `302 Location` 헤더에 외부 URL 사용 탐지
- XSS 전역 필터(인터셉터/Filter Bean) 적용 여부 사전 확인 → 전역 필터 미적용 시 위험도 상향

#### /sec-scan-file

진단 항목: File Upload / File Download / LFI / RFI(SSRF)

스캐너: `shared/scripts/scan_file_processing.py` (v1.0)

핵심 로직:
- **File Upload**: `MultipartFile` 수신 엔드포인트 탐지 → 확장자 검증·MIME 타입 검증·저장경로 난수화 여부 확인
- **File Download**: 파라미터 기반 파일 경로 지정 여부 → Path Traversal (`../`) 가능성 판정
- **LFI**: `include()`, `require()`, 템플릿 파일 경로에 사용자 입력 사용 여부
- **RFI/SSRF**: `RestTemplate.getForObject(url)`, `new URL(userInput)` 패턴 탐지 + SSRF 차단 설정 확인

#### /sec-scan-data

진단 항목: CORS 설정 오류 / Hardcoded Secrets / JWT 취약점 / 취약 암호화 / PII 운영 로그 노출

스캐너: `shared/scripts/scan_data_protection.py` (v1.1.0)

7개 모듈:
1. **CORS**: `@CrossOrigin(origins="*")`, `allowedOrigins("*")` 탐지
2. **Hardcoded Secrets**: AWS 자격증명, JWT 시크릿, HMAC 키, DB 비밀번호 하드코딩
3. **JWT**: 알고리즘 `none`, 단순 Base64 검증, 서명 미검증 패턴
4. **Cryptography**: MD5/SHA1/DES/ECB 모드 사용, PRNG 취약 클래스 사용
5. **PII Logging**: `log.info("userId: {}", userId)` 등 개인식별자·금융정보 운영 로그 노출
6. **DTO 과다노출**: `@ToString`이 적용된 DTO에 카드번호/CI/주민번호 필드 포함 여부
7. **Security Headers**: CSP, X-Frame-Options, HSTS 헤더 미설정

위험도 기준 (Memory에도 저장됨):
- 운영 LOG 민감정보 = **취약/High**
- debug LOG = **정보/Medium**
- `@ToString` DTO = **정보/Medium**

#### /sec-scan-sca

진단 항목: 오픈소스 라이브러리 CVE 취약점 (Gradle/npm)

스캐너: `shared/scripts/scan_sca_gradle_tree.py`

핵심 로직:
```
1. JDK 탐색 (--java-home > JAVA_HOME > PATH > WSL2 Windows 경로)
2. UUID 격리 작업 디렉토리 생성 (/tmp/sca_<uuid>/)
3. ./gradlew dependencies 실행 → 전이적 의존성 트리 추출
4. "jackson-databind:2.13.3 -> 2.13.5" 에서 resolved version(2.13.5) 추출
5. OSV.dev Batch Query API (500개 단위 청크) → CVE 조회
6. CVSS v3 Base Score + CISA KEV 교차 확인
7. 결과 JSON (publish_confluence.py 호환 스키마)
```

LLM CVE 관련성 검토 (Phase 3-SCA):
```
각 CVE에 대해:
1. 소스코드 내 라이브러리 사용 여부 (rg 검색)
2. CVE 발생 조건 패턴 확인
3. 판정: 적용 / 제한적 / 조건미충족(FP) / 확인불가
4. 한국어 설명 작성 (description_ko, impact_ko, condition_ko)
```

SCA findings는 /sec-review 시 건별 판정 생략 — LLM 검증 완료 시 일괄 정탐 처리.

### 2.3 인터랙티브 리뷰 (/sec-review)

```bash
/sec-review <RUN_ID> <repo>
# 또는 RUN_ID 생략 (skill별 최신 자동 선택)
/sec-review <repo>
```

실행 흐름:
```
Step 1a: state/<repo>/ 에서 최신 findings_*.json 자동 수집
Step 1b: testbed/<repo>/ 소스코드 분석 → 서비스 특징 LLM 자동 도출
         "추가진단 필요여부" 입력 요청 (유일한 인터랙션)
Step 2 : finding 목록 출력 (ID, 위험도, 제목 요약)
Step 3 : 각 finding에 대해 1(정탐)/0(오탐)/s(스킵) 판정 입력
Step 4 : review_status 기록 → report_expand 섹션 생성
```

판정 결과는 findings_*.json 내 `review_status` 필드에 기록:
```json
{
  "id": "INJ-001",
  "review_status": "confirmed",   // confirmed | dismissed | skipped
  "reviewer_note": "..."
}
```

### 2.4 보고서 생성 · 게시 (approve_report.py)

```bash
python3 tools/approve_report.py \
  --run-id 20260609_1030 \
  --repo my-service-api \
  --publish
```

생성 산출물:
- `logs/final_<repo>_<RUN_ID>.md` — Confluence :::expand 매크로 포함 Markdown
- Confluence 페이지 자동 게시 (Bearer 토큰 인증)
- Jira 티켓 등록 (palantir-jira-gateway → Lambda → Jira REST API)
- `state/<repo>/vuln_registry.json` v2.0 갱신

보고서 구성:
```
1. 진단 개요 (서비스 유형, 진단 방식, 기간, 추가진단 필요여부)
2. 취약점 요약 테이블 (심각도별 건수)
3. 취약점 개요 (Claude 자동 생성 — 개발자 대상, 현황+보안위협+조치권고 2~3문장)
4. 취약점 상세 (정탐 findings만, expand 매크로로 접기)
5. 조치 권고 사항
```

### 2.5 vuln_registry v2.0

레포별 취약점 이력을 누적 관리하는 JSON 스키마:

```json
{
  "schema_version": "2.0",
  "service_meta": {
    "bb_project": "SKP",
    "bb_repo": "my-service-api",
    "service_characteristics": "Spring Boot 2.7 / OCB 포인트 API (B2C)",
    "additional_diagnosis_needed": false
  },
  "runs": [
    {
      "run_id": "20260609_1030",
      "confluence_url": "https://wiki.example.com/...",
      "finding_counts": { "injection": 2, "xss": 1, "data": 3, "sca": 2 }
    }
  ],
  "findings": [
    {
      "uid": "INJ-001-20260609",
      "status": "open",       // open | fixed | accepted_risk
      "history": [
        { "run_id": "20260609_1030", "review_status": "confirmed" }
      ]
    }
  ]
}
```

---

## 3. playbook (sec-audit-static) — 아키텍처 상세

### 3.1 Phase 1~4 워크플로

```
Phase 1: 자산 식별
  Task 1-1: Excel/JSON 자산 목록 파싱 (parse_asset_excel.py)
  → 진단 대상 서비스 목록, 우선순위, 담당자 정보 추출

Phase 2: 정적 분석 (병렬 실행)
  Task 2-1: API 인벤토리 추출 (scan_api.py)
    └── Controller 어노테이션(@GetMapping, @PostMapping 등) 기반 전체 엔드포인트 목록
    └── 글로벌 필터·인터셉터 확인 (XSS 필터, 인증 인터셉터)
  
  병렬 실행:
  Task 2-2: SQL/OS Command/SSI Injection (scan_injection_enhanced.py)
  Task 2-3: XSS 4종 (scan_xss.py v2.4.0)
  Task 2-4: 파일 처리 취약점 (scan_file_processing.py v1.0)
  Task 2-5: 데이터 보호 (scan_data_protection.py v1.1.0)
  
  SCA [필수]:
    Gradle: scan_sca_gradle_tree.py (전이적 의존성 트리)
    npm:    scan_sca_gradle_tree.py (package-lock.json v3)

Phase 3: LLM 심층진단
  Phase 3-1: 자동 "취약" 판정 → 코드 흐름 교차검증
    └── Controller → Service → Repository → SQL Builder 데이터흐름 추적
    └── 사용자 입력 도달 가능성 / 타입 안전성 / 코드 활성화 여부
  
  Phase 3-2: "정보/수동검토" 판정 → LLM 심층진단
    └── DTO 래핑 역추적, 동적 SQL ID 추적
  
  Phase 3-SCA: CVE 관련성 검토
    └── 라이브러리별 소스코드 grep → 발생 조건 검증
    └── 판정: 적용 / 제한적 / 조건미충족(FP) / 확인불가
    └── 한국어 CVE 설명 작성

Phase 4: 보고서 생성 + Confluence 게시
  └── generate_finding_report.py → Markdown 보고서 (--anchor-style md2cf)
  └── publish_confluence.py → Confluence Server/DC REST API 게시
      SCA: <prefix>_sca.json + supplemental_sources: [<prefix>_sca_llm.json]

Phase 5 (정기진단 필수): SSC 정합성 검증
  └── fetch_ssc.py → Fortify SSC 결과 LLM 교차검증
  └── <prefix>_ssc_report.md → Confluence 게시
```

### 3.2 핵심 스캐너 스크립트 로직

#### scan_injection_enhanced.py — Positional Index Taint Tracking

```python
# 핵심 알고리즘 개념
def track_taint(source_param, controller_method):
    """
    HTTP 파라미터 → Service 메서드 → Repository 메서드 → SQL까지 추적
    Positional Index: 파라미터 위치(인덱스)로 추적 (이름 변환 대응)
    """
    # 1. Controller에서 @RequestParam index 식별
    param_index = find_param_index(controller_method, source_param)
    
    # 2. Service 호출 체인 추적
    service_call = find_service_call(controller_method)
    tainted_arg = service_call.args[param_index]
    
    # 3. Repository 호출까지 전파
    repo_call = find_repo_call(service_method, tainted_arg)
    
    # 4. MyBatis XML에서 ${}/${} 사용 확인
    if repo_call.uses_dollar_syntax():
        return Finding("SQL_INJECTION", severity="HIGH")
```

지원 기술 스택: Java / Kotlin · Spring · MyBatis · iBatis · JPA · QueryDSL · R2DBC

#### scan_data_protection.py — 7개 모듈 병렬 실행

```
모듈 구성:
  [cors]     @CrossOrigin(origins="*") 패턴 탐지
  [secrets]  정규식 기반 하드코딩 시크릿 탐지 (AWS, JWT, HMAC, DB 비밀번호)
  [jwt]      JWT 라이브러리 사용 패턴 + 알고리즘 검증
  [crypto]   취약 알고리즘 (MD5, SHA1, DES, ECB, SecureRandom)
  [logging]  log.*(정보필드) 패턴 탐지 → 운영로그/debug로그 구분
  [dto]      @ToString 어노테이션 + PII 필드 동시 존재 클래스 탐지
  [headers]  SecurityConfig에서 CSP/HSTS/X-Frame-Options 설정 여부
```

#### scan_sca_gradle_tree.py — OSV.dev 연동 SCA

```python
def run_gradle_dependencies(source_dir, subproject=None):
    """
    UUID 격리 작업 디렉토리에서 gradlew 실행
    전이적 의존성 트리 전체 추출 (직접 의존성 + transitive)
    """
    work_dir = f"/tmp/sca_{uuid.uuid4()}"
    # gradlew 실행 + 트리 파싱
    # "group:artifact:version -> resolved_version" 처리
    
def query_osv_batch(packages):
    """OSV.dev Batch API — 500개 단위 청크로 rate-limit 없이 대량 조회"""
    chunks = [packages[i:i+500] for i in range(0, len(packages), 500)]
    for chunk in chunks:
        resp = requests.post("https://api.osv.dev/v1/querybatch", ...)
```

#### publish_confluence.py — REST API 게시

```python
def publish(page_title, content, space_key, parent_id):
    """
    Confluence Server/DC REST API v2
    Bearer Token 인증 (PAT)
    Basic 인증 fallback
    """
    headers = {"Authorization": f"Bearer {os.environ['CONFLUENCE_TOKEN']}"}
    # 기존 페이지 존재 시 PUT (업데이트), 없으면 POST (신규)
    # SCA v2 렌더러: _json_to_xhtml_sca_v2() 별도 구현
    # LLM 검토 병합: sca_llm.json supplemental_sources 자동 로딩
```

### 3.3 Phase 3 LLM 교차검증 체계 (5단계)

```
1단계 — 데이터 흐름 확인
  질문: "HTTP 파라미터가 이 SQL/Command/Sink까지 실제로 도달하는가?"
  확인: 중간 계층(Service, DTO, Mapper)의 전달 경로 전수 추적

2단계 — 타입 안전성 확인
  질문: "전달 경로에서 타입이 변환되어 공격이 불가능해지는가?"
  확인: int/long 변환, PreparedStatement 바인딩 여부

3단계 — 코드 활성화 여부
  질문: "해당 코드 경로가 실제 실행 가능한가?"
  확인: 조건문 분기, 데드 코드 여부, 환경 설정 의존성

4단계 — 도달 가능성 확인
  질문: "공격자가 해당 엔드포인트에 인증 없이 접근 가능한가?"
  확인: Spring Security 설정, @PreAuthorize, 인터셉터

5단계 — 최종 판정
  정탐 조건: 1~4단계 모두 통과 (도달 가능 + 타입 취약 + 활성화 + 인증 우회 가능)
  오탐 처리: 어느 한 단계에서 차단 → 오탐으로 처리
```

오탐 제어 성과: 초기 패턴 매칭 10건 탐지 → LLM 교차검증 후 2건 확정 (오탐률 80% 제거)

---

## 4. AI 거버넌스 체계

### 4.1 데이터 분류 및 마스킹 정책

#### 데이터 분류 4등급

| 등급 | 예시 | AI 전달 가능 여부 |
|------|------|----------|
| Public | 오픈소스 코드, 공개 API 문서 | 허용 |
| Internal | 고객사 소스코드, 내부 설정 파일 | 마스킹 후 허용 |
| Confidential | DB 비밀번호, API 시크릿 키 | 금지 |
| Top Secret | 고객 PII, 금융 데이터 | 금지 |

#### 자동 마스킹 8개 패턴 (redact.py)

```python
REDACT_PATTERNS = [
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',              # IP 주소
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # 이메일
    r'(?i)(api[_-]?key|apikey)\s*[:=]\s*\S+',    # API Key
    r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',  # JWT
    r'\b01[016789]-\d{3,4}-\d{4}\b',              # 전화번호
    r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+',   # 비밀번호
    r'-----BEGIN\s+\w+\s+PRIVATE KEY-----',       # 인증서
    r'(?i)(secret|token|credential)\s*[:=]\s*\S+',  # 기타 크리덴셜
]
```

#### 5단계 데이터 클렌징 파이프라인

```
진단 완료 후 의무 실행 순서:

1단계: testbed 삭제
  → rm -rf testbed/<repo>/
  → 고객사 소스코드 로컬 완전 제거

2단계: state 감사
  → state/<repo>/ 내 원본 소스코드 스니펫 잔류 여부 확인
  → findings_*.json의 code_snippet 필드 길이 및 내용 점검

3단계: gitleaks redact
  → gitleaks detect --redact 옵션으로 시크릿 스캔
  → findings_*.json 내 하드코딩 시크릿이 redact 처리되었는지 확인

4단계: 세션 종료
  → 현재 Claude Code 세션 종료
  → 새 세션 시작 (기존 컨텍스트 초기화)

5단계: 완료 레지스트리 등록
  → Confluence 클렌징 이력 보드에 완료 표시
  → state/<repo>/llm_data_cleansing_registry.md 갱신
```

### 4.2 LLM 신뢰성 통제 (오탐 제어)

설계 원칙: **정규식 Auto-Scan이 "의심"하고, LLM이 "판단"하고, 사람이 "확정"한다**

```
Tier 1: 정규식 패턴 매칭 (scan_*.py)
  → 빠른 전수 탐지, 높은 재현율(recall), 낮은 정밀도(precision)
  
Tier 2: LLM 코드 흐름 분석 (교차검증)
  → 5단계 체계로 오탐 필터링 (오탐률 80% 제거)
  → 위험도 재확인 및 근거 생성

Tier 3: 진단자 최종 판정 (/sec-review)
  → finding별 정탐(1)/오탐(0) 결정
  → SCA는 LLM 검증 완료 시 일괄 정탐 처리
```

AI 결과 신뢰성 한계 명시:
- LLM 판단 결과는 `llm_checked: true` 마킹 후 사람 최종 검토 필수
- AI 생성 보고서 내용은 검증 전 최종 보고서 직접 사용 금지
- 실제 공격(Exploit) 코드 생성 목적 AI 사용 금지

### 4.3 감사 추적 체계

#### ai-manifest.yaml (세션 레벨)

```yaml
sessions:
  - session_id: "abc123"
    model: "claude-sonnet-4-6"
    started_at: "2026-06-01T10:00:00Z"
    ended_at: "2026-06-01T11:30:00Z"
    task_id: "sec-scan-injection"
    repo: "my-service-api"
    files_generated:
      - path: "state/my-service-api/injection/20260601_1000/findings_INJ.json"
        type: "task_output"
        ai_generated: true
        validated: true
```

#### llm_data_cleansing_registry.md (레포 레벨)

```markdown
| 레포 | 진단일 | testbed삭제 | state감사 | gitleaks | 세션종료 | 완료확인 |
|------|--------|------------|---------|---------|--------|---------|
| my-service-api | 2026-06-01 | ✅ | ✅ | ✅ | ✅ | ✅ |
```

---

## 5. 진단 실적 현황 (2026-06 기준)

### palantir 기준 진단 완료 레포

| 서비스 유형 | 진단 건수 | Critical | High | Medium | 보고서 게시 |
|------------|---------|---------|------|--------|----------|
| 커뮤니티 API | 13건 | 3 | 5 | 5 | ✅ |
| Webview API | 18건 | 0 | 8 | 10 | ✅ |
| 리워드 API | 15건 | 0 | 7 | 8 | ✅ |
| 조이 API | 8건 | 0 | 3 | 5 | ✅ |
| 메시지큐 워커 | 8건 | 1 | 4 | 3 | ✅ |
| 커뮤니티 SSR | 6건 | 0 | 2 | 4 | ✅ |
| 관리자 API | 4건 | 0 | 2 | 2 | ✅ |
| 기타 서비스 | (다수) | - | - | - | ✅ |
| **누계 (1단계)** | **72건+** | **4+** | **31+** | **37+** | **14개 레포** |

### 주요 발견 사례

**PII 운영 로그 노출** (가장 많이 발견)
- 커뮤니티 API: `log.info("userId: {}", userId)` 패턴 8파일
- Webview API: 운영 로그 46건+, API 응답 전화번호 평문 노출
- 메시지큐 워커: `@ToString` 55개 클래스 (카드번호·CI·주민번호 포함)

**하드코딩 시크릿**
- JWT Secret, AWS 자격증명, HMAC 키 등 application.properties/yml 내 평문 기재

**SCA CVE (실제성 검증 후)**
- Spring Security CVE 2건 (인증 우회 가능)
- Tomcat RCE CVE 1건 (PoC 실증 완료)

### playbook 기준 진단 실적 (2025년 Blackbox/Whitebox)

| 항목 | 내용 |
|------|------|
| 진단 서비스 수 | 22개+ 서비스 완료 |
| 진단 방식 | Blackbox + Whitebox 통합 |
| 주요 취약점 | IDOR, Stored XSS, 딥링크 하이재킹, CVE PoC 실증 |
| 보고서 게시 | 전체 Confluence 게시 완료 |

---

## 6. 기술 스택 요약

### 개발 도구 및 언어

| 분류 | 기술 | 활용 맥락 |
|------|------|---------|
| AI/LLM | Claude Code CLI, Anthropic API (claude-sonnet-4-6) | 모든 LLM 교차검증 및 자동화 |
| Python | 3.9+ | 모든 스캐너 스크립트, 파이프라인 구현 |
| Java/Kotlin | 진단 대상 | 취약점 패턴 분석 (MyBatis, Spring, JPA) |
| JavaScript/TypeScript | 진단 대상 | DOM XSS, postMessage, React 취약점 분석 |
| Bash | 보조 | JDK 설치, gitleaks 실행 |

### 외부 API/서비스 연동

| 서비스 | 용도 | 인증 방식 |
|--------|------|---------|
| Anthropic Claude API | LLM 교차검증, 보고서 생성 | API Key |
| Confluence Server REST API | 보고서 자동 게시 | Bearer Token (PAT) |
| OSV.dev Batch API | SCA CVE 조회 | 인증 불필요 |
| Bitbucket Server REST API | 소스코드 clone, 결과 push | HTTP Access Token |
| Jira REST API (via Lambda) | 취약점 티켓 등록 | Gateway 경유 |
| NIST NVD API | SCA CVE 보완 조회 | API Key (선택) |

### 보안 도구

| 도구 | 용도 |
|------|------|
| gitleaks | 소스코드 내 시크릿 탐지 + --redact 마스킹 |
| Fortify SSC | Phase 5 정합성 교차검증 |
| OWASP Dependency Check | SCA 보조 (레거시 JAR 기반) |

---

## 7. 삼성SDS 직무 매핑 — AI 보안정책 관련 경험

### JD 수행업무 ↔ 보유 경험

| JD 수행업무 | 보유 경험 | 구체적 근거 |
|------------|---------|-----------|
| AI 보안 정책 수립 및 운영 | AI_USAGE_POLICY.md 직접 수립, 데이터 분류 4등급 체계 설계 | playbook/ai/ 디렉토리 운영 |
| AI 보안성 검토 및 위험 평가 | LLM 오탐률 측정, 클렌징 완료율 추적, 세션 감사 추적 | ai-manifest.yaml 운영 |
| AI 활용에 대한 보안 심의 | 외부 LLM 전달 데이터 범위 정책, 금지 항목(Exploit 코드 생성) 명시 | AI_USAGE_POLICY.md |
| 임직원 AI 보안 교육 | 5단계 클렌징 절차 표준화, 진단 가이드 문서화 | CLAUDE.md, manual_scan_guide.md |

### JD 우대사항 ↔ 보유 경험

| 우대사항 | 보유 경험 | 상세 |
|---------|---------|------|
| MCP/Skills Agent 기반 AI 서비스 활용 경험 및 정책 이해 | Claude Code Skills 5개 설계·운영, MCP 아키텍처 이해 | palantir skill 아키텍처 직접 구현 |
| CSP AI 서비스 활용 경험 (Bedrock, Azure AI, Gemini) | Anthropic Claude API 심층 활용 | 교차검증 프롬프트 엔지니어링, 토큰 최적화 |
| NIST AI RMF 이해 | Govern/Map/Measure/Manage 4개 기능 실무 적용 | 데이터 분류·감사추적·오탐 측정·클렌징 관리 |
| ISO 42001 / MITRE ATLAS 이해 | 정책 문서 구조 (ISO42001 지향), AI 공격 시나리오 인식 | (학습 필요 — 기반 경험 보유) |

### 차별화 포인트

1. **"AI 정책을 직접 만들고 운영한" 유일한 보안 엔지니어**: AI 사용자가 아닌 AI 거버넌스 설계자
2. **기술과 정책의 동시 이해**: 스캐너 스크립트를 직접 구현하고, 그 결과물의 보안 리스크를 정책으로 통제한 경험
3. **Human-in-the-Loop 설계 경험**: AI 자율 실행 범위를 어디까지 허용할지, 어느 시점에 인간 개입이 필요한지를 실무에서 설계
4. **LLM 신뢰성 문제 직접 해결**: 할루시네이션·오탐 문제를 정량화하고 체계적으로 통제한 방법론 보유

---

*이 문서는 자택 고도화 및 입사지원 준비용입니다. 고객사 정보 및 실제 취약점 상세 내용은 포함하지 않았습니다.*
