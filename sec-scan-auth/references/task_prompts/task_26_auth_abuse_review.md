## Task: 2-6 인증/인가/어뷰징 검토 (LLM 수동진단 전담)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>/auth.json` (scan_auth_baseline.py 후보 태깅 결과 — 판정 없음, 전량 `needs_review: true`)
**출력 파일**: `state/<prefix>/task26_llm.json` (LLM 수동진단 — TP/FP·category·severity 최종 판정)
**게시 방식**: `findings_AUTH.json`으로 통합하여 `/sec-review` 대상으로 전달

---

### ⛔ HARD RULE — task26_llm.json 출력 전 반드시 준수

#### [RULE-1] Auto-Scan은 판정을 하지 않았다 — `candidate_type`을 `category`로 그대로 쓰지 말 것

`auth.json`의 `candidates[]`는 `IDOR_CANDIDATE`/`MISSING_AUTH_CANDIDATE`/`ABUSE_KEYWORD_CANDIDATE`/`NO_AUTHZ_ANNOTATION_CANDIDATE` 4종 태그만 붙어 있을 뿐, 실제 취약 여부·최종 category는 전혀 정해지지 않은 상태다. 이 문서의 절차를 거쳐 `vuln_taxonomy.md` §6 표준값(`AUTH_BYPASS`/`SESSION_MGMT`/`BRUTE_FORCE_PROTECTION`/`IDOR`/`MISSING_FUNCTION_ACCESS_CONTROL`/`MASS_ASSIGNMENT`/`RATE_LIMIT_ABSENT`/`IDEMPOTENCY_ABSENT`/`CLIENT_TRUSTED_LOGIC`)로 재분류한 뒤에만 finding으로 작성한다. 판정 결과 FP인 candidate는 finding으로 만들지 않는다(`findings[]`에서 제외, evidence_trail에만 기록).

#### [RULE-2] 판정 원칙 — "이론적 위험"이 아니라 "이 코드베이스에서 실제 도달 가능한가"

[[feedback_thirdparty_lib_reachability]]와 동일한 원칙을 인가/어뷰징 진단에도 그대로 적용한다: 패턴이 이론적으로 위험해 보이는지가 아니라, **이 저장소의 실제 코드 경로가 그 위험을 실현시키는지**를 코드로 직접 확인한 뒤 판정한다. 예: `auth_required: false` + POST라는 사실 하나만으로 즉시 TP 처리하지 않는다 — 해당 endpoint가 실제로 민감한 상태 변경을 수행하는지, 상위 게이트웨이/필터에서 별도 인증을 강제하는지까지 확인한다.

#### [RULE-3] 병합 규칙 — candidate 단위가 아니라 근본 원인 단위로 finding 작성

같은 원인(예: 전역 Security 설정에서 특정 경로 패턴 전체가 `permitAll()`)으로 여러 endpoint가 동시에 태깅된 경우, endpoint별로 나누지 말고 **설정 파일 기준 1개 finding**으로 병합하고 `affected_endpoints`에 목록을 나열한다. 개별 비즈니스 로직 결함(특정 API의 IDOR 등)은 endpoint 단위로 분리 작성한다.

---

### 진단 대상 순회 절차

`auth.json`의 `candidates[]`를 `candidate_type`별로 그룹핑하여 순회한다. 각 그룹은 아래 판정 기준을 적용한다.

---

### 1. IDOR / BOLA 판정 기준 (`candidate_type: IDOR_CANDIDATE` → `category: IDOR`)

**확인 절차**:
1. Controller 메서드에서 path parameter(리소스 ID)를 받는 지점 확인.
2. 해당 ID로 Service → Repository까지 taint 추적.
3. Repository/쿼리(JPA method, MyBatis SQL, QueryDSL 등)의 WHERE 절에 **현재 로그인 사용자 소유 여부**를 검증하는 조건(`mbrId = :currentUser`, `AND owner_id = :sessionUserId` 등)이 포함되는지 코드로 직접 확인.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 소유권 검증 조건 없이 path ID만으로 단건 조회/수정/삭제 | 취약 / High | 파라미터 조작만으로 타인 리소스 접근·변조 가능 (CWE-639) |
| 소유권 검증 조건이 WHERE 절에 명시적으로 포함 | 오탐 | 소유자 불일치 시 조회 결과 자체가 없음 — FP |
| ID가 사용자 소유 데이터가 아닌 공용/참조 리소스(코드값, 공지사항 등) | 오탐 | 애초에 소유권 개념이 없는 리소스 — IDOR 대상 아님 |
| 관리자 전용 API에서 관리자 권한 체크만 있고 대상 소유권 무관 | 오탐(별도 판단) | 관리자가 임의 사용자 데이터를 다루는 것은 설계 의도 — 단, 권한 체크 자체 부재는 §2 대상 |

---

### 2. 기능 수준 접근통제 누락 판정 기준 (`NO_AUTHZ_ANNOTATION_CANDIDATE` → `category: MISSING_FUNCTION_ACCESS_CONTROL` 또는 `AUTH_BYPASS`)

**확인 절차**:
1. 해당 endpoint가 관리자/운영자 전용 기능(회원 정지, 포인트 강제 조정, 벌크 처리, 설정 변경 등)인지 핸들러명·경로·비즈니스 맥락으로 판단.
2. Controller/Service 어디에도 role/권한 체크(`@PreAuthorize`, `hasRole`, 수동 `if (!user.isAdmin())` 등)가 없는지 확인.
3. 상위 Security 설정(`SecurityConfig`)에서 해당 경로 패턴이 이미 role 기반으로 제한되어 있는지 교차 확인(Controller 레벨엔 없어도 Config 레벨에 있으면 FP).

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 관리자 전용 기능인데 role 체크가 코드 어디에도 없음 (Config 포함) | 취약 / Critical | 일반 사용자도 관리자 기능 호출 가능 — 수직 권한상승 (CWE-862) |
| 일반 사용자 대상 기능(본인 정보 조회 등)이라 role 구분 자체가 불필요 | 오탐 | 인증만 되면 되는 기능 — 인가 애노테이션 부재가 결함이 아님 |
| Controller엔 없으나 Security 설정에서 경로 기반으로 role 제한 확인됨 | 오탐 | FP — Config 레벨 인가가 실질 통제 |
| 인증 자체가 없는 상태에서(anonymous 접근 가능) 관리자 기능 노출 | 취약 / Critical, `category: AUTH_BYPASS`로 재분류 | 인가 이전에 인증 자체가 우회됨 — 더 심각한 케이스 |

---

### 3. 인증 누락 판정 기준 (`MISSING_AUTH_CANDIDATE` → `category: AUTH_BYPASS` 또는 오탐)

**확인 절차**:
1. 해당 POST/PUT/DELETE/PATCH endpoint가 실제로 상태를 변경하는지(단순 조회성 POST — 검색 조건이 복잡해 GET 대신 POST를 쓰는 경우는 제외) 확인.
2. 인증이 필요 없는 것이 의도된 설계인지 확인(회원가입, 로그인, 공개 이벤트 응모, 비로그인 장바구니 등은 의도적으로 비인증).
3. 비의도적 인증 누락이라면, 상위 API Gateway(별도 레포)에서 인증을 대신 강제하는지 확인 — 이 저장소 코드만으로 판단 불가하면 `needs_review: true` 유지하고 게이트웨이 레포 확인 필요 명시.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 의도적 비인증 기능 (회원가입/로그인/공개 조회) | 오탐 | 설계상 인증 불필요 |
| 인증이 필요한 상태변경 기능인데 코드상 인증 체크 자체가 없고, 게이트웨이 레벨 강제도 확인 안 됨 | 취약 / High | 인증 우회로 임의 상태 변경 가능 (CWE-287) |
| 게이트웨이/프록시 레벨에서 인증 강제가 코드/설정으로 확인됨 | 오탐 | FP — 이 레포 코드만 보고 판단하면 안 됨, 확인한 근거를 review_note에 명시 |

---

### 4. Mass Assignment 판정 기준 (어뷰징/일반 그룹 공통 → `category: MASS_ASSIGNMENT`)

**확인 절차**:
1. `@RequestBody` DTO의 필드 목록 확인 — `role`/`isAdmin`/`status`/`point`/`balance`/`grade` 등 서버 전용/민감 필드가 DTO에 포함되어 있는지 확인.
2. 해당 DTO가 Entity에 바인딩되는 방식 확인: `BeanUtils.copyProperties()`, `ModelMapper`, JPA `save(entity)` 직접 전달 등 **화이트리스트 없이 그대로 매핑**되는지, 아니면 Service 레이어에서 필드별로 명시적으로 옮겨 담는지 확인.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 서버 전용 필드 포함 DTO를 화이트리스트 없이 그대로 Entity에 바인딩 | 취약 / High | 요청 바디에 `role: "ADMIN"` 추가만으로 권한 상승 가능 (CWE-915) |
| DTO에 서버 전용 필드가 애초에 없음(입력 DTO와 응답/Entity 필드가 분리) | 오탐 | 구조적으로 Mass Assignment 불가 |
| DTO에 필드는 있으나 Service에서 필드별 명시적 매핑(화이트리스트) 확인 | 오탐 | FP — 매핑 코드 근거를 review_note에 명시 |

---

### 5. Rate Limit / 멱등성 판정 기준 (`ABUSE_KEYWORD_CANDIDATE` → `category: RATE_LIMIT_ABSENT` 또는 `IDEMPOTENCY_ABSENT`)

**확인 절차 (reachability 우선 — §[RULE-2] 원칙 그대로 적용)**:
1. 해당 endpoint가 실제로 금전적 가치를 지급/차감하는 로직(포인트 적립 UPDATE/INSERT, 쿠폰 발급 INSERT, 이벤트 당첨 처리 등)까지 taint 확인. 단순 조회·안내성 API는 대상에서 제외.
2. **Rate Limit**: Redis 카운터, DB 기반 호출 이력 체크, API Gateway 레벨 rate limit 등 호출 빈도 제한 메커니즘이 코드에 존재하는지 확인.
3. **멱등성**: 멱등키(idempotency key) 검증, DB unique constraint(`1인 1회` 등 제약), 상태머신 체크(이미 지급된 상태면 재지급 차단) 등 중복 요청 차단 메커니즘이 존재하는지 확인.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 금전적 가치 지급 로직 확인 + Rate Limit·멱등성 메커니즘 모두 없음 | 취약 / High, `category: IDEMPOTENCY_ABSENT`(중복지급 위험이 핵심이면) 또는 `RATE_LIMIT_ABSENT`(단순 반복호출 소진이 핵심이면) | 동시요청/재시도로 중복 지급, 또는 반복호출로 리소스(포인트/쿠폰) 소진 |
| 금전적 가치 지급 로직은 있으나 unique constraint 또는 상태 체크로 중복 방지 확인 | 오탐 | FP — DB 제약조건/상태머신 코드를 review_note에 명시 |
| 키워드는 매칭되었으나 실제로는 조회성 API(포인트 조회 등)이고 지급 로직이 아님 | 오탐 | reachability 부재 — 지급 taint 자체가 없음 |
| Rate Limit은 없으나 1인 1회 unique constraint로 멱등성은 보장됨 | 정보 / Medium | 무제한 반복 호출 자체는 막히지 않으나(DoS성 소모는 가능) 중복 지급 위험은 없음 — Rate Limit 관점만 정보성으로 별도 기재 |

---

### 6. 클라이언트 신뢰 비즈니스 로직 판정 기준 (`category: CLIENT_TRUSTED_LOGIC`)

**확인 절차**:
1. 가격/수량/할인율/포인트 사용량 등이 요청 파라미터로 전달되는 endpoint 확인.
2. 서버가 해당 값을 그대로 신뢰해 결제/차감 로직에 사용하는지, 아니면 서버 측 원본 데이터(상품 마스터 가격 등)로 재계산·검증하는지 확인.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 클라이언트가 전달한 가격/금액을 서버 재계산 없이 결제 로직에 그대로 사용 | 취약 / Critical | 요청 조작만으로 결제금액 임의 변경 가능 (CWE-602) |
| 클라이언트 값은 참고용이고 서버가 상품ID 등으로 원본 가격을 재조회해 검증 | 오탐 | FP — 서버 측 재계산 코드를 review_note에 명시 |

---

### 7. 세션 관리 / Brute-force 판정 기준 (`category: SESSION_MGMT` / `BRUTE_FORCE_PROTECTION`)

이 두 유형은 Auto-Scan 후보 태깅 대상이 아니므로(구조적 설정 확인이 필요해 endpoint 단위 태깅에 부적합), Phase 1 자산식별 단계에서 발견한 `SecurityConfig`/로그인 관련 Controller를 LLM이 직접 확인해 발굴한다(`diagnosis_method: "수동진단(LLM)"`, `source: "llm-check(fn-detected)"`).

- **SESSION_MGMT**: 로그인 성공 시 세션ID 재발급(`request.changeSessionId()` 등) 여부, 세션 타임아웃 설정값(과도하게 긴 경우), 로그아웃 시 서버측 세션/토큰 무효화 여부.
- **BRUTE_FORCE_PROTECTION**: 로그인/OTP/비밀번호 재설정 endpoint에 실패 횟수 기반 계정 잠금 또는 Redis 기반 시도 제한이 있는지.

발견 시 위 §RULE-3 병합 규칙에 따라 설정 단위로 finding 1건 작성.

---

### 마스킹 및 공통 규칙

- `evidence.code_snippet`/`manual_review_note`에 실제 자격증명·토큰·개인정보 원문이 포함되지 않도록 [[feedback_conservative_security_policy]] 및 기존 skill들과 동일한 마스킹 원칙을 적용한다.
- Section 4-2 HARD RULE(`reviewed`/`review_status` 필드 미설정)을 반드시 준수한다 — `SKILL.md` Step 4-2 참조.
