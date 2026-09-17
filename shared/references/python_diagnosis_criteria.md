# Python Diagnosis Criteria

Python(Django/FastAPI 등)은 `unsupported_lang_targets.md` 기준 자동 스캐너가 전혀 없는
유일한 언어다 — PHP(`scan_php_baseline.py` 후보 태깅)나 JS/TS(XSS/File/Data 자동 스캔)와
달리, Injection/XSS/File/Data/Auth **5개 도메인 전부** Auto-Scan 없이 이 문서의 기준에
따라 LLM이 API 목록 확보부터 취약점 판정까지 전량 수동으로 수행한다.

이 문서는 `task_11_asset_identification.md` §1-6(Python 판정)에서 참조되며,
`vuln_taxonomy.md`의 표준 category/cwe_id/owasp_category를 그대로 따른다 —
**category를 임의 문자열로 만들지 않는다.**

---

## 0. 프레임워크 탐지

```bash
# Django
find testbed/<repo>/ -maxdepth 3 -iname "manage.py" -o -iname "settings.py"

# FastAPI / Flask
grep -rl "from fastapi import\|FastAPI(" testbed/<repo>/ --include="*.py" | head -3
grep -rl "from flask import\|Flask(__name__)" testbed/<repo>/ --include="*.py" | head -3

# 의존성 매니페스트 확인 (SCA용, §5 참조)
find testbed/<repo>/ -maxdepth 3 -iname "requirements*.txt" -o -iname "Pipfile" -o -iname "pyproject.toml"
```

| 프레임워크 | 탐지 신호 |
|---|---|
| Django | `manage.py`, `settings.py`(또는 `settings/` 패키지), `django.conf.urls`/`django.urls` import |
| FastAPI | `from fastapi import FastAPI`, `requirements.txt`에 `fastapi` |
| Flask | `from flask import Flask`, `@app.route`/`@blueprint.route` |

프레임워크가 둘 이상 섞여 있으면(예: Django 어드민 + 별도 FastAPI 마이크로서비스) 디렉터리
단위로 분리해 각각 아래 §1 방법론을 따로 적용한다.

---

## 1. API 리스팅 방법론

Auto-Scan의 `scan_api.py`(Java/Kotlin 전용)에 대응하는 절차가 없으므로, 아래 방법으로
`endpoints[]` 인벤토리(method/path/file/line/handler)를 **수동으로 구성**한 뒤 §2~§4
진단의 순회 대상으로 삼는다. 스키마는 기존 skill들의 `task_11` 산출물과 동일하게 맞춘다.

### 1-A. Django

```bash
# 각 app의 urls.py 탐색
find testbed/<repo>/ -iname "urls.py"

# urlpatterns 파싱 대상 함수/클래스 확인 (구/신 스타일 모두)
grep -n "^urlpatterns\|url(\|path(\|re_path(\|include(" testbed/<repo>/<app>/urls.py
```

1. 프로젝트 루트 `urls.py`에서 `include()`로 연결된 앱별 `urls.py`를 재귀적으로 추적한다.
2. 각 `url()`/`path()`/`re_path()` 라인에서 URL 패턴 문자열과 두 번째 인자(view 함수/
   `ClassName.as_view()`)를 추출한다. `django.conf.urls.url()`(구 스타일, `rwd_adm`에서
   확인됨)과 `django.urls.path()`(신 스타일) 둘 다 동일하게 처리한다.
3. view 함수/클래스로 이동해 `@login_required`/`@permission_required`/`@csrf_exempt`
   등 데코레이터, HTTP 메서드 분기(`request.method == 'POST'`)를 확인한다.
4. `include()`에 `namespace=`가 있으면 prefix에 반영한다.

### 1-B. FastAPI

```bash
# 라우터 선언 및 prefix
grep -rn "APIRouter(" testbed/<repo>/ --include="*.py"

# 라우트 데코레이터
grep -rn "@router\.\(get\|post\|put\|delete\|patch\)(" testbed/<repo>/ --include="*.py"

# 라우터 등록(prefix 조합)
grep -rn "include_router(" testbed/<repo>/ --include="*.py"
```

1. `APIRouter(prefix="...")` 선언부와 `app.include_router(xxx_router, prefix="...")`
   조합으로 최종 경로를 계산한다.
2. `@router.get/post/put/delete/patch(...)` 데코레이터가 붙은 함수의 파라미터 중
   Pydantic 모델(요청 바디 스키마)이 있으면 어떤 필드를 받는지 같이 기록한다 —
   §2 Auth의 Mass Assignment류 판단과 §4 File 판단에 필요.
3. `Depends(...)`로 걸린 인증/인가 의존성(`OAuth2PasswordBearer`, 커스텀 `get_current_user`
   등)이 있는지, 없는 라우트는 어디인지 표시한다.

### 1-C. Flask (발견 시)

`@app.route()`/`@blueprint.route()` 데코레이터를 grep, `methods=[...]` 인자로 HTTP 메서드
확인.

---

## 2. 기존 5개 카테고리 → Python 코드 패턴 매핑

각 카테고리는 §1에서 확보한 `endpoints[]`를 순회하며 진단한다. `category`/`cwe_id`/
`owasp_category`/기본 `severity`는 `vuln_taxonomy.md`의 표준값을 그대로 사용한다 —
아래 표는 "Python에서 이 카테고리를 어떤 코드 패턴으로 확인하는지"만 정리한 것이다.

### 2-1. Injection (`vuln_taxonomy.md` §1)

| 확인 대상 | Django | FastAPI |
|---|---|---|
| Raw SQL | `.raw()`, `.extra()`, `connection.cursor()` + `cursor.execute()` | `sqlalchemy.text()`, 직접 DB 드라이버(`pymysql` 등) 커서 사용 |
| **판정 핵심** | 파라미터 바인딩 유무가 아니라 **쿼리 문자열 자체가 어떻게 만들어지는지**를 호출부 단위로 확인한다. `cursor.execute(query, params)` 형태라도 `query` 변수가 f-string/`%`-format/`+`concat으로 외부 입력을 직접 포함하면 취약 — `params`가 커버하는 것은 그 안의 `%s` 플레이스홀더뿐이다. | 동일 |
| OS Command | `subprocess.*(shell=True, ...)`, `os.system()`, `os.popen()` | 동일 |
| 코드 실행 | `eval()`, `exec()` (사용자 입력 도달 시) | 동일 |

> **실사례**: `rwd_adm/statistic/views.py`의 `get_daily_stat_data()`는 `channel`/`ad_name`이
> `request.GET.get()`에서 그대로 `" AND channel='" + channel + "'"` 로 SQL 문자열에
> concat된 뒤 `QueryUtil.select_all(query, params)`로 실행된다 — `params`는 `start`/`end`
> 날짜만 커버해 SQLi가 성립한다. 반면 같은 저장소의 `cs/views.py`, `batch/views.py`는
> `where_cond += " AND CHANNEL = %s"` + `params.append(channel)` 식으로 안전하게
> 파라미터화되어 있다 — **같은 래퍼(`QueryUtil`)를 쓴다고 안전성이 같지 않다.** 래퍼
> 내부 구현이 안전해도 호출부가 쿼리 텍스트에 직접 concat하면 무의미하다.

### 2-2. XSS (`vuln_taxonomy.md` §2)

| 확인 대상 | Django | FastAPI |
|---|---|---|
| 템플릿 이스케이프 우회 | `\|safe` 필터, `mark_safe()`, `{% autoescape off %}` | 대부분 JSON API라 서버측 HTML 렌더링 자체가 없는 경우가 많음 — Jinja2를 직접 쓰는 경우만 동일 패턴 적용 |
| Reflected | 요청 파라미터를 이스케이프 없이 `HttpResponse(...)`에 직접 포함 | 요청 파라미터를 이스케이프 없이 HTML 응답에 포함 |
| DOM/API 응답 소비 | 응답 JSON을 프론트가 `innerHTML`/`dangerouslySetInnerHTML` 등 위험 싱크로 소비하는지 (프론트 코드가 같은 레포/별도 레포에 있으면 교차 확인) |

이 저장소들이 JSON 위주 API(FastAPI)이거나 관리자 페이지(Django 템플릿, `\|safe` 미사용
확인됨)라면 XSS 표면이 제한적일 수 있다 — 단, "표면이 없음"은 실제로 템플릿/렌더링 코드를
읽고 확인한 뒤에만 결론 내린다 (Auto-Scan 부재로 0건이 나온 것을 "취약점 없음"으로 오판한
`rwd_adm`의 선례를 반복하지 않는다).

### 2-3. File (`vuln_taxonomy.md` §5)

| 확인 대상 | Django | FastAPI |
|---|---|---|
| 업로드 파일명 처리 | `request.FILES[...]` → 저장 경로 조합 시 원본 파일명(`save_file.name`)을 그대로 쓰는지, UUID 등으로 치환하는지 | `UploadFile`/`File(...)` 파라미터 → 저장 경로 조합 방식 |
| 확장자/MIME 검증 | 화이트리스트 존재 여부, `python-magic` 등 매직바이트 검증 여부 | 동일 |
| Path Traversal | 저장/다운로드 경로에 사용자 입력이 `../` 필터링 없이 조합되는지 | 동일 |

> **실사례**: `rwd_adm/rwd_adm/utils/FtpUtils.py`는 함수에 따라 처리가 다르다 —
> `ftpDjangoMemoryFileUpload()` 내부는 `convert_file_name_uuid()`로 파일명을 UUID로
> 치환하지만, `upload_file()` → `handle_uploaded_file()` 경로는 `save_file.name`(원본
> 업로드 파일명)을 그대로 저장 경로에 concat한다(`FtpUtils.py:82,84`). 동일 파일 내에서도
> 함수별로 안전/불안전이 갈리므로 **호출 경로 단위**로 확인해야 한다 — 정확한 판정을 위해
> Django 버전별 `MultiPartParser`의 파일명 sanitize 동작(예: `os.path.basename` 적용 여부)도
> 함께 확인한다.

### 2-4. Data (`vuln_taxonomy.md` §4)

| 확인 대상 | Django | FastAPI |
|---|---|---|
| 하드코딩 시크릿 | `settings.py`/`settings/*.py`의 `SECRET_KEY`, DB 비밀번호, 서드파티 API 키 리터럴 | `.env` 로드 코드 주변 fallback 리터럴, 소스에 직접 박힌 `SECRET_KEY`/API 키 |
| PII 로그 | `logger.debug/info(f"...")`, `print()`에 개인정보/토큰 포함 | 동일 |
| CORS | `django-cors-headers`의 `CORS_ORIGIN_ALLOW_ALL`/`CORS_ALLOWED_ORIGINS` | `CORSMiddleware(allow_origins=..., allow_credentials=...)` |
| JWT | (DRF-JWT 등 사용 시) 서명키/알고리즘 처리 | `python-jose`/`pyjwt` 사용부 — 서명키 하드코딩, `algorithm` 검증 누락 |

> **실사례**: `rwd_adm/rwd_adm/settings/base.py`에 `SECRET_KEY`/`DEBUG=True`/FTP 계정이,
> `prod.py:61`·`dev.py:49`에 환경별 DB 비밀번호가 하드코딩됨 —
> 하드코딩 자격증명 severity 기준(운영 동일=High, 별도=Medium)에 따라 운영 DB 비번은 High.
> `ocb-api-with-python/app/deploy/api/app.py`는 `CORSMiddleware(allow_origins=["*"],
> allow_credentials=True)`로 와일드카드 오리진+credentials를 동시 허용(`CORS_MISCONFIG`,
> CWE-346). 같은 레포 `admin_router.py`의 JWT `SECRET_KEY = 'qwerasdfzxcvtgbyhn1'`은
> `HARDCODED_SECRET`(CWE-798)이며, 알고리즘 검증까지 취약하면 `JWT_INCOMPLETE`도 함께
> 판정한다.

### 2-5. Auth (`vuln_taxonomy.md` §6)

| 확인 대상 | Django | FastAPI |
|---|---|---|
| 인증 데코레이터/의존성 누락 | `@login_required`/`permission_classes` 누락 endpoint | `Depends(get_current_user)` 등 인증 의존성 없는 라우트 |
| 하드코딩 인증 우회 | 특정 아이디/비번 리터럴 비교로 정상 인증 로직을 대체하는 패턴 → `AUTH_BYPASS`(CWE-287) | 동일 |
| IDOR | URL/쿼리의 리소스 ID로 소유권 검증 없이 접근 | 동일 |

> **실사례**: `ocb-api-with-python/api/routers/admin_router.py`의 `/apiadmin/login`은
> `mappers.user_id == 'suadmin' and mappers.user_pw == '1q2w3e4r!@'` 평문 리터럴 비교로
> 관리자 로그인을 처리한다 — 정상 인증 로직을 완전히 우회하는 하드코딩 백도어이므로
> `AUTH_BYPASS`(CWE-287, High 이상 — 관리자 권한 탈취 가능성 고려 시 Critical 권고)로
> 판정한다.

---

## 3. Python/프레임워크 특화 추가 항목 (기존 5개 도메인에 이미 존재하는 taxonomy로 흡수)

아래는 "기존 5개 skill에 없는 새 카테고리"가 아니라, **Python 코드에서 특히 자주
발견되는데 자동 스캐너 부재로 지금까지 완전히 누락돼 온 패턴들**이다. category는 모두
`vuln_taxonomy.md`의 기존 표준값을 그대로 사용한다 (신규 taxonomy 행 추가는 §3-1
`DEBUG_MODE_ENABLED` 1건뿐).

| 항목 | 패턴 | 적용 category |
|---|---|---|
| 안전하지 않은 역직렬화 | `pickle.load()`/`pickle.loads()`, `yaml.load()`(`Loader=` 미지정 또는 `FullLoader`가 아닌 경우) | `UNSAFE_DESERIALIZATION` (CWE-502, §4 데이터보호) |
| SSTI | Jinja2 `render_template_string()`/`Template(user_input)`에 사용자 입력 직접 전달 | `SSTI` (CWE-94, §1 Injection) |
| JWT 하이진 | `algorithm='none'` 허용, `verify=False`, 서명키 길이/엔트로피 부족 | `JWT_INCOMPLETE` (CWE-347, §4 데이터보호) |
| CORS 오설정 | §2-4 표 참조 | `CORS_MISCONFIG` (CWE-346, §4 데이터보호) |
| 하드코딩 인증우회 | §2-5 실사례 참조 | `AUTH_BYPASS` (CWE-287, §6 인증/인가) |
| **설정 하이진(디버그 모드 노출)** | 아래 §3-1 참조 | **`DEBUG_MODE_ENABLED` (신규)** |

### 3-1. `DEBUG_MODE_ENABLED` — 신규 taxonomy 행 추가 근거

기존 `vuln_taxonomy.md` §4(데이터 보호)의 `SECURITY_HEADER`는 HTTP 응답 헤더(HSTS/CSP
등) 결함을 다루고, `HARDCODED_SECRET`은 값 자체의 하드코딩을 다룬다 — 어느 쪽도 **프레임워크
디버그 모드가 운영에 도달 가능한 설정으로 남아있는 문제**(스택트레이스/내부 경로/환경변수
노출로 이어짐, CWE-215)를 명확히 포괄하지 않는다. PHP 진단 시 `코드 인젝션`(CWE-95)을
추가했던 것과 동일한 근거로, 아래 행을 `vuln_taxonomy.md` §4에 추가한다:

| 취약점 유형 | `category` | `cwe_id` | `owasp_category` | 기본 `severity` | `scope.type` |
|---|---|---|---|---|---|
| 디버그 모드 운영 노출 (`DEBUG=True`, `ALLOWED_HOSTS=['*']`, 프레임워크 debug 모드) | `DEBUG_MODE_ENABLED` | `CWE-215` | `A05:2021 Security Misconfiguration` | `Medium` (스택트레이스에 시크릿/쿼리 노출 확인 시 `High`) | `config` |

판정 시 확인 사항:
- Django: `DEBUG = True`가 **운영 배포 설정에도 도달 가능한지**(`settings/prod.py`가
  별도로 `DEBUG=False`를 명시하는지, 아니면 `base.py`의 `True`를 상속하는지) 반드시
  확인한다 — dev 전용 설정 파일에만 있으면 severity를 Low~Medium으로 낮출 수 있다.
- Django: `ALLOWED_HOSTS = ['*']` 또는 빈 배열도 동일 카테고리로 함께 판정.
- FastAPI: `FastAPI(debug=True)`가 실제 운영 실행 진입점(`uvicorn.run(..., reload=...)`
  등)에서도 유지되는지 확인.

> **실사례**: `rwd_adm/rwd_adm/settings/base.py:30` `DEBUG = True`(prod.py가 별도로
> `False`를 재정의하는지 미확인 — 재진단 시 확인 필요), `ocb-api-with-python/api/app.py`
> `app = FastAPI(debug=True)`.

---

## 4. Python SCA (의존성 CVE) — 수동 절차 한정

`shared/scripts/scan_sca_gradle_tree.py`는 Gradle 전용이고, npm은 `/sec-scan-sca`가
자동 지원하지만 **pip 계열(`requirements.txt`/`Pipfile`/`pyproject.toml`) 자동 스캔
스크립트는 존재하지 않는다.** 이번 계획 범위에서는 신규 스크립트를 만들지 않고, 아래
수동 절차로 한정한다:

1. `requirements.txt`/`Pipfile.lock`/`poetry.lock` 등에서 패키지명+버전 목록을 추출한다.
2. 버전이 고정되지 않은 패키지(`fastapi`처럼 버전 미명시)는 "고정 버전 관리 부재"로
   별도 지적하고, CVE 판정은 실제 설치된 버전을 알 수 없으므로 보류한다.
3. 버전이 고정된 패키지는 알려진 주요 CVE(예: `pyjwt` 알고리즘 confusion 이력,
   `python-jose` 관련 이슈, 오래된 `openai` SDK 등)를 LLM 지식 기준으로 검토하고,
   확신이 없으면 "수동 검증 필요"로 표기한다 — Auto-Scan처럼 CVE DB를 조회하는 것이
   아니므로 과신하지 않는다.
4. `/sec-review` 단계에서는 SCA 기본 제외 정책과 동일하게 기본 보고서에서 제외하고,
   필요 시 `--include-sca`로만 포함한다.

> **실사례**: `ocb-api-with-python/app/deploy/requirements.txt`는 `fastapi`, `sqlalchemy`,
> `uvicorn` 등 대부분 버전 미고정, `openai==0.28`만 구버전 고정 — 버전 미고정 자체를
> "재현성/보안 패치 추적 불가" 리스크로 언급하되, CVE 확정 판정은 보류한다.

---

## 5. 실행 모델 — 전량 LLM 수동 진단, 도메인별 skill 분담

PHP처럼 baseline 태깅 스크립트가 없으므로 `/sec-scan-php` 같은 전담 skill을 신설하지
않는다. 대신 **기존 5개 skill이 Phase 1에서 Python을 만나면 그 skill이 담당하는
카테고리만 이 문서 기준으로 직접 수동 진단**한다 (`task_11_asset_identification.md`
§1-6 참조):

1. `/sec-scan-injection` 실행 중 Python 감지 → §1(API 리스팅) + §2-1(Injection) 진단
2. `/sec-scan-xss` → §1 + §2-2(XSS)
3. `/sec-scan-file` → §1 + §2-3(File)
4. `/sec-scan-data` → §1 + §2-4(Data) + §3의 CORS/JWT/DEBUG_MODE_ENABLED (아래 참고)
5. `/sec-scan-auth` → §1 + §2-5(Auth) + §3의 AUTH_BYPASS/하드코딩 백도어

**§3의 신규 발견 항목 귀속**: `UNSAFE_DESERIALIZATION`/`SSTI`는 성격상 Injection·Data
어느 쪽에서 발견되든 해당 카테고리(taxonomy 기준)로 그대로 기록하면 되므로 특별한 라우팅
규칙이 필요 없다. `DEBUG_MODE_ENABLED`/`CORS_MISCONFIG`/`JWT_INCOMPLETE`는 데이터
보호(§4) 소관이므로 `/sec-scan-data`가 1차 담당하되, 다른 도메인 skill이 먼저 실행되며
발견한 경우 findings에 포함하고 note에 "§3 신규 발견 — 타 skill 중복 확인 불필요"를
남겨 중복 진단을 막는다.

findings 저장 스키마는 기존 skill과 동일 (`findings_<SKILL>.json`, `result`/`severity`/
`scope`/`evidence` 등 표준 필드) — Python이라고 별도 파일 포맷을 쓰지 않는다.

완료 후 절차는 기존과 동일: `/sec-review <repo>` → 인터랙티브 정탐/오탐 판정 → 클렌징 →
최종보고서 게시.
