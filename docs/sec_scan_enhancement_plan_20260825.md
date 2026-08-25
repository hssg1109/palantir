# sec-scan 진단기준 고도화 및 sec-scan-auth 신설 계획

> 작성일: 2026-08-25

## Context

지금까지 `/sec-review`로 27개+ 레포를 리뷰하면서 사용자가 그때그때 정정해준 판정 기준(하드코딩 자격증명 Critical 상한, mbrId 로그 2조건 판정, SQL `${}` 보수적 기준, SpEL StandardEvaluationContext, Proxy XSS, 프론트엔드 클라이언트 검증 비-보안경계, MIME reachability 체크 등)이 `feedback_*` 메모리에는 쌓여 있지만, 실제 스캔 단계에서 참조하는 `shared/references/*.md`·각 skill의 `task_prompts/*.md`에는 일부만 반영되어 있다. 특히 `sec-scan-data`의 mbrId 판정 로직은 2026-08-11에 이미 폐기된 구(舊) 3조건 AND 로직이 스캔 프롬프트에 그대로 남아있어 매번 사람이 리뷰 단계에서 수동으로 뒤집어야 하는 상태다. 이번 작업은 이런 "메모리에만 있고 스캔 기준 문서엔 없는" 지식을 실제 절차 파일에 박아 넣어, 다음 레포부터는 처음부터 정확한 판정이 나오게 하는 것이 목적이다.

동시에, 지금까지 5개 skill(injection/xss/file/data/sca)이 다루지 않는 인증 우회·인가(IDOR/BOLA/권한상승)·어뷰징(포인트·쿠폰 중복지급, rate limit 부재) 영역은 27개 레포 동적진단 우선순위 작업에서도 반복적으로 등장한 실제 위험(예: `event_resource` OTP 우회, `ocb-joy-api` 포인트 어뷰징, `ocbws-web-api`/`ocb-iam` 인증)인데도 SAST 단계에서 정식으로 다루는 skill이 없다. 이를 커버하는 신규 `/sec-scan-auth` skill을 기존 5개와 동일한 구조(Phase 1 자산식별 → Auto-Scan → LLM-Check → Summary → Phase C-1 cleansing log)로 신설한다.

사용자 확인 사항:
- skill 이름: **sec-scan-auth**
- 탐지 방식: 인가/어뷰징은 정규식으로 단정하기 어려운 영역이므로, Auto-Scan은 "판정"이 아니라 **LLM이 순회할 대상을 준비하는 인벤토리 보강** 역할만 하고, TP/FP·severity 판단은 LLM-Check(수동진단)가 전담한다.

---

## Part A — 기존 5개 skill 고도화

### A1. [최우선] `sec-scan-data/references/task_prompts/task_25_data_protection.md` §6-0 — mbrId 판정 로직 교체
현재 "3조건 AND"(식별자 + 클린데이터 + 업무맥락) 로직을 확정된 **2조건 AND**(① 식별자 존재 ② 금지유형 미해당)로 교체. 단순 진입 로그는 FP라는 정책 §16.2/§17 인용 명시. debug 레벨 운영활성 예외(운영 프로파일에서 DEBUG 활성 확인 시 Medium→High 상향)도 함께 반영.

### A2. `shared/references/severity_criteria.md`
- "디버그 로그 내 중요정보 노출 (info/warn/error/fatal) → Critical" 행을 실제 적용 기준인 **High(4)**로 정정하고 라벨을 "민감정보 운영 로그 노출(info/warn/error/fatal)"로 수정.
- PII Logging(debug/trace) → Informational 행에 운영 DEBUG 활성 시 High 상향 예외 각주 추가.
- HARDCODED_SECRET 행에 dev/prod 대조 규칙(동일=High, 상이=Medium, Critical 미부여 원칙) 각주 추가.

### A3. `sec-scan-data/references/task_prompts/task_25_data_protection.md` — HARDCODED_SECRET 판정 절차
dev/default 프로파일 finding 발견 시 반드시 운영 프로파일 설정값과 대조 후 High/Medium 분기하는 절차 명시.

### A4. `sec-scan-injection` — SQL `${}` 보수적 기준 반영
현재 소스 신뢰도와 무관하게 `${}`/문자열보간 삽입이면 취약/High가 기본이고, 유일한 예외는 int 캐스팅 값만 삽입되는 경우임을 명시하도록 판정 매트릭스 수정.

### A5. `sec-scan-injection` — SpEL StandardEvaluationContext 구분 추가
`StandardEvaluationContext` 사용 시 keyExpression이 상수라도 항상 취약/High. `SimpleEvaluationContext.forReadOnlyDataAccess()`에서만 기존 입력출처 판정 적용.

### A6. `sec-scan-xss/references/task_prompts/task_23_xss_review.md` — Proxy XSS 판정 기준 추가
외부 응답을 살균 없이 `text/html`로 반환하는 프록시 엔드포인트는 파라미터 반사 여부와 무관하게 취약/High.

### A7. `sec-scan-file` — 프론트엔드 클라이언트 검증 비-보안경계 기준 추가
순수 프론트엔드 레포의 클라이언트측 검증 부재 finding 생성 전, 백엔드(교차 레포 포함)의 동등 이상 검증 여부를 먼저 확인.

### A8. `sec-scan-file/references/task_prompts/task_24_file_handling.md` — MIME/magic bytes reachability 체크 추가
정적 스토리지 vs 실행환경 / ContentType 서버강제 vs 클라이언트기반 / 후속 재처리 로직 유무의 3조건 체이닝 확인 절차 추가.

### A9. [참고] `tools/new_scan.py` stale 참조
5개 SKILL.md의 clone 안내가 존재하지 않는 스크립트를 가리킴. 실제 명령은 `python3 tools/clone_repo.py <PROJECT> <REPO>`.

---

## Part B — 신규 `sec-scan-auth` skill 신설

### 구조
```
sec-scan-auth/
├── SKILL.md
└── references/task_prompts/task_26_auth_abuse_review.md
.claude/commands/sec-scan-auth.md
shared/scripts/scan_auth_baseline.py
```

### B1. `vuln_taxonomy.md` §6 — 인증/인가/어뷰징 분류표

| 취약점 유형 | category | cwe_id | owasp_category | 기본 severity | scope.type |
|---|---|---|---|---|---|
| 인증 우회 | AUTH_BYPASS | CWE-287 | A07:2021 | High | endpoint |
| 세션 관리 취약 | SESSION_MGMT | CWE-613 | A07:2021 | Medium | config |
| Brute-force 방지 부재 | BRUTE_FORCE_PROTECTION | CWE-307 | A07:2021 | Medium | endpoint |
| IDOR/BOLA | IDOR | CWE-639 | A01:2021 | High | endpoint |
| 기능 수준 접근통제 누락 | MISSING_FUNCTION_ACCESS_CONTROL | CWE-862 | A01:2021 | Critical | endpoint |
| Mass Assignment | MASS_ASSIGNMENT | CWE-915 | A08:2021 | High | endpoint |
| Rate Limit 부재 | RATE_LIMIT_ABSENT | CWE-799 | A04:2021 | Medium(금전가치 직접관련 시 High) | endpoint |
| 멱등성 부재 | IDEMPOTENCY_ABSENT | CWE-841 | A04:2021 | High | endpoint |
| 클라이언트 신뢰 비즈니스 로직 | CLIENT_TRUSTED_LOGIC | CWE-602 | A04:2021 | Critical(결제금액 조작 가능 시) | endpoint |

### B2. `severity_criteria.md`에 위 9종 매핑 행 추가

### B3. `sec-scan-auth/SKILL.md`
기존 5개 skill과 동일 골격. Auto-Scan은 `scan_api.py` 산출물(auth_required/parameters/handler)을 입력으로 받아 IDOR/인증누락/어뷰징/인가애노테이션 부재 후보를 태깅만 하고(TP/FP 판정 없음, 전부 needs_review:true), 최종 판정은 LLM-Check가 전담. Step 4-2 HARD RULE(reviewed/review_status는 /sec-review에서만 부여) 포함.

### B4. `task_26_auth_abuse_review.md`
IDOR(소유권 조건절 확인)/Mass Assignment(서버전용 필드 화이트리스트 매핑 확인)/Rate Limit·멱등성(실제 지급 로직까지 taint 확인) 판정 기준을 코드베이스 실도달성(reachability) 원칙으로 작성.

### B5. `.claude/commands/sec-scan-auth.md` — 기존 wrapper 패턴 그대로 신규 작성

### B6. `CLAUDE.md` Available Skills 표 갱신, `/sec-review` 진행순서에 auth 추가 위치 확정(sca 전/후는 실행 중 재확인)

---

## 실행 순서
1. Part A 8개 항목 순차 적용 (문서/프롬프트 Edit만).
2. Part B: taxonomy/severity 확장 → SKILL.md → task_26 → command wrapper → CLAUDE.md 갱신.
3. `scan_auth_baseline.py`는 `scan_api.py` 출력 스키마를 읽는 실동작 스크립트로 작성.

## 검증
- Part A: 각 수정 파일에서 구(舊) 문구가 실제로 치환되었는지 grep 확인.
- Part B: `scan_auth_baseline.py` 스모크 테스트로 JSON 정상 생성 확인.
