# PHP Diagnosis Criteria

`scan_php_baseline.py`가 태깅한 `candidate_type` → `vuln_taxonomy.md` 표준 `category`/`cwe_id`/
`owasp_category` 매핑표. LLM-Check(`task_php_llm_review.md`)가 최종 판정 시 이 표를 기준으로
category를 결정한다 — **`candidate_type`을 그대로 category에 남기지 않는다.**

---

## 0. 프레임워크 확인 (진단 시작 전 1회)

이 skill은 **프레임워크 없는 raw PHP**(라우터 없음, 파일=엔드포인트)를 전제로 설계되었다.
`composer.json`, `artisan`, `.htaccess`의 프론트 컨트롤러 rewrite 규칙 등이 발견되어
Laravel/CodeIgniter/Symfony 등 프레임워크 사용이 확인되면:

- 라우팅 테이블(`routes/web.php` 등)을 asset 인벤토리 소스로 우선 사용
- ORM(Eloquent/Query Builder) 사용 시 SQLI_CANDIDATE 판정 기준을 "raw query/`DB::raw()`/
  문자열 결합" 에만 한정 (파라미터 바인딩된 Query Builder 호출은 후보 태깅 대상에서 제외 —
  `scan_php_baseline.py`는 이 구분을 하지 않으므로 LLM-Check가 수동으로 필터링)
- 프레임워크 자체 XSS 이스케이프(Blade `{{ }}` 등) 사용 여부 확인 후 XSS_CANDIDATE 재평가

OCB-THP 6개 대상 레포는 사전 조사 결과 전부 `composer.json` 없는 raw PHP로 확인되었으나,
신규/미확인 레포 진단 시 이 판정을 생략하지 않는다.

---

## 1. candidate_type → category 매핑표

| `candidate_type` | `category` (표준값) | `cwe_id` | `owasp_category` | 기본 `severity` | `scope.type` |
|---|---|---|---|---|---|
| `SQLI_CANDIDATE` (사용자 입력 도달 확정) | `SQL인젝션` | `CWE-89` | `A03:2021 Injection` | `Critical` | `endpoint` |
| `SQLI_CANDIDATE` (wrapper 내부/내부값만) | `SQL인젝션` | `CWE-89` | `A03:2021 Injection` | `High` | `endpoint` |
| `CMD_INJECTION_CANDIDATE` (사용자 입력 도달 확정) | `OS Command Injection` | `CWE-78` | `A03:2021 Injection` | `Critical` | `endpoint` |
| `CMD_INJECTION_CANDIDATE` (내부값·설정값·Dead Code) | `OS Command Injection` | `CWE-78` | `A03:2021 Injection` | `Medium` | `file` |
| `LFI_RFI_CANDIDATE` (로컬 파일 경로 조작 — `../` 등) | `파일 다운로드 경로 조작` | `CWE-22` | `A01:2021 Broken Access Control` | `High` | `endpoint` |
| `LFI_RFI_CANDIDATE` (원격 URL 포함 가능 — `http://` 등 스킴 허용) | `원격 파일 포함` | `CWE-918` | `A10:2021 SSRF` | `High` | `endpoint` |
| `XSS_CANDIDATE` | `Reflected XSS` | `CWE-79` | `A03:2021 Injection` | `High` | `endpoint` |
| `HARDCODED_SECRET_CANDIDATE` | `HARDCODED_SECRET` | `CWE-798` | `A02:2021 Cryptographic Failures` | `High` | `file` |
| `WEAK_CRYPTO_CANDIDATE` | `WEAK_CRYPTO` | `CWE-327` | `A02:2021 Cryptographic Failures` | `High` | `file` |
| `PATH_TRAVERSAL_CANDIDATE` | `파일 다운로드 경로 조작` | `CWE-22` | `A01:2021 Broken Access Control` | `High` | `endpoint` |
| `EVAL_CANDIDATE` | `코드 인젝션` | `CWE-95` | `A03:2021 Injection` | `Critical` | `file` |

> `LFI_RFI_CANDIDATE`는 `include`/`require` 인자에 사용자 입력이 도달하는 경로가 확인되면
> **로컬 경로 조작**(`../etc/passwd` 등)인지 **원격 URL 포함**(`http://evil.com/shell.txt`)인지에
> 따라 category가 갈린다 — `allow_url_include` 설정 확인 여부와 무관하게, 인자에 URL 스킴을
> 허용하는지(화이트리스트 부재) 기준으로 판단한다.

### `코드 인젝션` (CWE-95) — 신규 taxonomy 행 추가 근거

`vuln_taxonomy.md` §1의 기존 카테고리(SQL인젝션/OS Command Injection/SSI Injection/SSTI)는
PHP `eval()`/`assert()`(문자열 인자)/`create_function()` 같은 **문자열을 코드로 실행**하는
패턴을 커버하지 못한다(SQL/OS Command는 각각 SQL·쉘 문법 전용, SSTI는 템플릿 엔진 전용).
`vuln_taxonomy.md` 자체가 "신규 유형이 필요하면 이 파일을 업데이트한다"고 명시하므로,
`코드 인젝션` / `CWE-95` 행을 §1에 추가했다. 이 카테고리는 `sec-scan-php` 전용이며 다른
skill에서는 사용하지 않는다.

---

## 2. 진단 시 자주 발생하는 판단 포인트

- **wrapper 함수 경유 SQL**: 레거시 PHP는 `function_db.inc.php` 같은 공용 wrapper(`db_query()` 등)를
  거쳐 `mysql_query`/`mysqli_query`를 호출하는 경우가 많다. `scan_php_baseline.py`는 wrapper 정의부만
  탐지하므로, LLM-Check는 **wrapper를 호출하는 모든 지점**까지 역추적해 사용자 입력 도달 여부를 확인한다.
- **`$_SERVER['DOCUMENT_ROOT']` 기반 include**: 절대경로 조합이라도 이어지는 하위 경로에 `$_GET`/`$_POST`가
  섞이면 LFI 후보로 취급한다. 순수 상수/설정값 조합(`SITE_HEAD_PATH.$const`)만 있으면 `정보`(FP 근접)로 낮출 수 있음.
- **`md5(`/`sha1(` 단독 사용**: 파일 체크섬/캐시 키 등 비밀번호·인증 토큰과 무관한 용도면 `정보`로 낮춘다.
  비밀번호 해싱·인증 토큰 생성 문맥이면 `WEAK_CRYPTO`/`High` 유지.
- **하드코딩 자격증명의 운영/개발 구분**: `feedback_hardcoded_credential_severity.md` 기준 그대로 적용
  (운영과 동일 자격증명=High, 별도 자격증명=Medium, Critical은 부여하지 않음).
