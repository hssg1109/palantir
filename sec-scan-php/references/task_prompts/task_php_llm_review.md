## Task: PHP LLM-Check (수동진단 전담)

**역할**: 당신은 보안 진단 전문가입니다.
**입력 파일**: `state/<prefix>/php.json` (scan_php_baseline.py 후보 태깅 결과 — 판정 없음, 전량 `needs_review: true`)
**출력 파일**: `state/<prefix>/task_php_llm.json` (LLM 수동진단 — TP/FP·category·severity 최종 판정)
**게시 방식**: `findings_php.json`으로 통합하여 `/sec-review` 대상으로 전달 (`finding_id` prefix `PHP-`, 예: `PHP-001`)

---

### ⛔ HARD RULE — findings_php.json 출력 전 반드시 준수

#### [RULE-1] Auto-Scan은 판정을 하지 않았다 — `candidate_type`을 `category`로 그대로 쓰지 말 것

`php.json`의 `candidates[]`는 `SQLI_CANDIDATE`/`CMD_INJECTION_CANDIDATE`/`LFI_RFI_CANDIDATE`/`XSS_CANDIDATE`/`HARDCODED_SECRET_CANDIDATE`/`WEAK_CRYPTO_CANDIDATE`/`PATH_TRAVERSAL_CANDIDATE`/`EVAL_CANDIDATE`/`INSECURE_TLS_CLIENT_CANDIDATE` 9종 태그만 붙어 있을 뿐, 실제 취약 여부·최종 category는 전혀 정해지지 않은 상태다(`INSECURE_TLS_CLIENT_CANDIDATE`는 2026-09-16 ocb_game_biz PHP-010 사후발견으로 추가된 9번째 후보 — 그 전까지는 8종). 이 문서의 절차를 거쳐 `php_diagnosis_criteria.md` §1 매핑표의 표준값(`SQL인젝션`/`OS Command Injection`/`파일 다운로드 경로 조작`/`원격 파일 포함`/`Reflected XSS`/`HARDCODED_SECRET`/`WEAK_CRYPTO`/`코드 인젝션`/`INSECURE_TLS_CLIENT`)으로 재분류한 뒤에만 finding으로 작성한다. 판정 결과 FP인 candidate는 finding으로 만들지 않는다(`findings[]`에서 제외, `evidence_trail[]`에만 기록).

#### [RULE-2] 판정 원칙 — "이론적 위험"이 아니라 "이 코드베이스에서 실제 도달 가능한가"

[[feedback_thirdparty_lib_reachability]]와 동일한 원칙을 PHP 진단에도 그대로 적용한다: 정규식이 이론적으로 위험해 보이는 패턴을 매칭했다는 사실 하나만으로 즉시 TP 처리하지 않는다. **이 저장소의 실제 코드 경로가 그 위험을 실현시키는지**를 코드로 직접 확인한 뒤 판정한다. PHP는 라우터가 없어 파일 자체가 웹 진입점이므로, 해당 파일이 실제로 웹 요청으로 직접 접근 가능한지(포함 전용 조각 파일이라 단독 접근이 불가능한 것은 아닌지)까지 확인 대상에 포함한다.

#### [RULE-3] 병합 규칙 — candidate 단위가 아니라 근본 원인 단위로 finding 작성

같은 파일/같은 wrapper 함수에서 동일 원인으로 여러 줄이 동시에 태깅된 경우(예: 공용 `function_db.inc.php`의 `db_query()` wrapper를 호출하는 지점이 파일 여러 곳에 흩어져 있는 경우), 줄 단위로 나누지 말고 **wrapper/파일 기준 1개 finding**으로 병합하고 `evidence.affected_files[]` 또는 `evidence.lines[]`에 목록을 나열한다. 서로 다른 파일·서로 다른 근본 원인은 파일 단위로 분리 작성한다.

---

### 진단 대상 순회 절차

`php.json`의 `candidates[]`를 `candidate_type`별로 그룹핑하여 순회한다. 각 그룹은 아래 판정 기준을 적용하며, category/cwe_id/owasp_category/기본 severity는 `php_diagnosis_criteria.md` §1 표를 그대로 인용한다.

---

### 1. SQL Injection 판정 기준 (`SQLI_CANDIDATE` → `category: SQL인젝션`)

**확인 절차**:
1. `mysql_query()`/`mysqli_query()` 호출부의 SQL 문자열 조합 방식 확인 — 문자열 결합(`.`)/보간(`"...{$var}..."`)에 변수가 직접 섞여 들어가는지, 아니면 상수/설정값만 결합되는지 확인.
2. 해당 변수가 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`에서 직접 왔는지, 아니면 내부 로직(루프 카운터, 하드코딩 배열 등)에서만 왔는지 taint 역추적.
3. **wrapper 함수 경유 확인 필수**(`task_php_asset_identification.md` Step 3의 `db_wrapper_files` 참조): `db_query()` 같은 공용 함수를 호출하는 모든 지점까지 역추적해, wrapper 자체가 아니라 **호출부**에서 사용자 입력이 섞이는지 확인.
4. Prepared Statement(`mysqli_prepare`/`PDO::prepare`) 또는 최소한의 이스케이프(`mysqli_real_escape_string`, `intval()` 캐스팅 등) 경유 여부 확인.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| `$_GET`/`$_POST` 값이 이스케이프/바인딩 없이 쿼리 문자열에 직접 결합 | 취약 / Critical | 쿼리 조작으로 데이터 탈취·변조 가능 (CWE-89) |
| 사용자 입력이 wrapper 함수를 거쳐 도달하나 wrapper 호출부 어디에도 이스케이프 없음 | 취약 / Critical | wrapper 통과 여부는 방어수단이 아님 — 실제 sink 도달 확인됨 |
| 변수가 있으나 내부 상수/설정값·정수 캐스팅(`(int)`, `intval()`)만 결합 | 오탐 | 사용자 입력 도달 경로 없음 — reachability 부재 |
| `mysqli_real_escape_string()` 또는 Prepared Statement 바인딩 경유 확인 | 오탐 | FP — 이스케이프/바인딩 코드를 evidence에 명시 |

---

### 2. OS Command Injection 판정 기준 (`CMD_INJECTION_CANDIDATE` → `category: OS Command Injection`)

**확인 절차**:
1. `system`/`exec`/`shell_exec`/`passthru`/`popen`/`proc_open`/백틱 연산자에 들어가는 변수의 출처 확인.
2. 사용자 입력이 명령어 문자열에 직접 결합되는지, `escapeshellarg()`/`escapeshellcmd()` 경유 여부 확인.
3. 실행 파일 경로/옵션이 고정값이고 변수는 인자 값 일부(예: 파일명)에만 쓰이는 경우, 화이트리스트 검증(확장자·정규식) 여부 확인.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 사용자 입력이 이스케이프 없이 셸 명령 문자열에 직접 결합 | 취약 / Critical | 임의 명령 실행 가능 (CWE-78) |
| `escapeshellarg()`/`escapeshellcmd()` 경유 확인 | 오탐 | FP — 이스케이프 코드를 evidence에 명시 |
| 변수가 내부 설정값·상수 조합뿐이고 사용자 입력 도달 경로 없음(Dead Code 포함) | 정보 / Medium | reachability 부재하나 향후 변경 시 위험 소지 있어 정보성 기록 |
| 사용자 입력이 화이트리스트(허용된 값 목록) 검증을 통과한 뒤에만 명령어 일부로 사용 | 오탐 | FP — 화이트리스트 검증 코드를 evidence에 명시 |

---

### 3. LFI / RFI 판정 기준 (`LFI_RFI_CANDIDATE` → `category: 파일 다운로드 경로 조작` 또는 `원격 파일 포함`)

**확인 절차**:
1. `include`/`include_once`/`require`/`require_once` 인자에 들어가는 변수의 출처(`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` 직접, 또는 `$_SERVER['DOCUMENT_ROOT']` 등 상수와의 조합) 확인.
2. 변수에 `../` 등 경로 조작 문자열이 필터링 없이 도달 가능한지, 또는 `http://`/`https://`/`ftp://` 같은 URL 스킴이 그대로 허용되는지 확인 — **`php_diagnosis_criteria.md` §1 각주대로 `allow_url_include` 설정 여부와 무관하게 인자에 URL 스킴 화이트리스트 부재 여부로 로컬/원격 구분**.
3. 화이트리스트 배열(`$allowed_pages = ['home','list']`) 대조 후 include하는 패턴인지 확인 — 있으면 FP.
4. `$_SERVER['DOCUMENT_ROOT']` 기반 조합이라도 이어지는 하위 경로에 사용자 입력이 섞이면 로컬 경로 조작 후보로 취급(`php_diagnosis_criteria.md` §2).

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 사용자 입력이 필터링 없이 include 경로에 도달, `../` 등으로 임의 로컬 파일 포함 가능 | 취약 / High, `category: 파일 다운로드 경로 조작` (`CWE-22`) | 로컬 파일 포함으로 소스코드/설정파일 노출 가능 |
| 사용자 입력이 include 경로에 도달하며 URL 스킴 허용(화이트리스트 없음) | 취약 / High, `category: 원격 파일 포함` (`CWE-918`) | 원격 코드 포함·실행 가능 (RFI) |
| include 인자가 화이트리스트 배열 대조를 거친 뒤에만 결정됨 | 오탐 | FP — 화이트리스트 코드를 evidence에 명시 |
| 변수는 있으나 상수(`SITE_HEAD_PATH.$const`)만 결합되고, **해당 코드가 향후 유지보수 시 사용자 입력이 유입될 개연성이 있는 애플리케이션 코드**(재사용 빈도 높은 공통 include 헬퍼 등) | 정보 / Medium | reachability 부재하나 구조상 향후 위험 소지 있음 — recommendation에 "코드리뷰 시 사용자 입력 유입 여부 확인" 등 **구체적 잔존 조치**를 반드시 명시 |
| 변수는 있으나 상수만 결합되고, **벤더/서드파티 라이브러리 내부 코드**이거나 향후 변경 개연성이 없는 완전 고정 경로(예: cron 전용 배치 스크립트의 자기참조 include) | 오탐 | FP — "정보"로 남기지 않는다. 잔존 조치가 없는데 정보로 두면 보고서에 "정보 — 조치 불필요" 같은 자기모순 문구가 발생함(2026-09-14 homeshopping PHP-005/006 재분류 선례) |

---

### 4. Reflected XSS 판정 기준 (`XSS_CANDIDATE` → `category: Reflected XSS`)

**확인 절차**:
1. `echo`/`print`가 출력하는 값에 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`가 섞여 있는지, `htmlspecialchars()`/`htmlentities()` 경유 여부를 스크립트가 이미 확인했으나(`_XSS_SANITIZED_RE`는 같은 줄만 검사) **여러 줄에 걸쳐 사전 이스케이프된 변수를 재사용하는 경우**는 스크립트가 놓칠 수 있으므로 LLM이 직접 위쪽 코드를 확인한다.
2. 출력 컨텍스트 확인 — HTML 본문, `<script>` 블록 내부, HTML 속성값 등 컨텍스트에 따라 `htmlspecialchars()`만으로 충분한지(속성값 내부라면 따옴표 처리 여부까지) 판단.
3. `[[feedback_conservative_security_policy]]` 원칙에 따라, 전역 XSS 필터가 별도로 없는 저장소에서 개별 케이스만 안전해 보여도 전역 필터 부재 자체를 별도 finding으로 병합 고려.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| `$_GET`/`$_POST` 값을 필터링 없이 HTML 본문에 직접 echo | 취약 / High | 스크립트 삽입으로 세션 탈취 등 가능 (CWE-79) |
| `htmlspecialchars()` 경유하나 속성값 컨텍스트에서 따옴표 인코딩 옵션(`ENT_QUOTES`) 누락 | 취약 / Medium | 속성 이탈을 통한 부분적 XSS 가능성 |
| `htmlspecialchars()`/`htmlentities()` 경유 확인(적절한 컨텍스트) | 오탐 | FP — 이스케이프 코드를 evidence에 명시 |
| 출력값이 사용자 입력이 아닌 서버 생성 고정 문자열/상수 | 오탐 | reachability 부재 |

---

### 5. Hardcoded Secret 판정 기준 (`HARDCODED_SECRET_CANDIDATE` → `category: HARDCODED_SECRET`)

**확인 절차**:
1. 매칭된 변수/배열키가 실제 자격증명(DB 비밀번호, API 키, Redis 비밀번호 등)인지, 단순히 이름에 `token`/`pass` 문자열이 포함된 비민감 변수(`$csrf_token_field_name`, `$password_hint_text` 등)인지 구분.
2. 실제 자격증명이면 해당 값이 운영 환경과 동일한지, 별도 개발/테스트 전용 계정인지 확인(git history, 인접 주석, 변수명의 `dev`/`test`/`local` 접두어 등으로 판단).

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 실제 자격증명이며 운영과 동일 계정으로 확인 | 취약 / High | `feedback_hardcoded_credential_severity.md` 기준 — 소스 유출 시 운영 시스템 직접 침해 (CWE-798) |
| 실제 자격증명이나 개발/테스트 전용 별도 계정으로 확인 | 취약 / Medium | 동일 기준 — 운영 영향 제한적이나 여전히 하드코딩 결함 |
| 변수명에 민감 키워드가 포함됐으나 실제로는 UI 라벨/필드명 등 비민감 값 | 오탐 | FP — 실제 자격증명이 아님 |
| Critical 상향 요청이 있어도 부여하지 않음 | (해당 없음) | `feedback_hardcoded_credential_severity.md`: 즉시 노출 증거 없는 한 상한 High |

---

### 6. Weak Crypto 판정 기준 (`WEAK_CRYPTO_CANDIDATE` → `category: WEAK_CRYPTO`)

**확인 절차**:
1. `md5()`/`sha1()` 호출의 용도 확인 — 비밀번호 해싱, 인증 토큰/세션ID 생성, 파일 체크섬, 캐시 키, ETag 생성 등 문맥 구분.
2. 비밀번호/인증 관련 문맥이면 salt 사용 여부, `password_hash()`/`password_verify()` 같은 대체 함수 존재 여부 확인.
3. **벤더/서드파티 라이브러리 코드 여부 확인** — 파일이 `_EXCLUDE_DIR_RE`에 등재되지 않은 다른 이름(예: `lib/<LibraryName>/`)으로 번들된 서드파티 라이브러리인지, 파일 상단 `@package`/`@copyright`/`@version` 등 오픈소스 라이브러리 고유 docblock이 있는지 확인. 해당하면 즉시 새 벤더 라이브러리명을 `scan_php_baseline.py`의 `_EXCLUDE_DIR_RE`와 `task_php_asset_identification.md` grep 패턴 두 곳에 추가하고, 이번 finding은 아래 표의 "벤더 라이브러리" 행으로 판정한다.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 비밀번호 해싱 또는 인증 토큰 생성에 `md5()`/`sha1()` 단독 사용(salt 없음) | 취약 / High | 레인보우테이블·충돌공격에 취약 (CWE-327) |
| **벤더/서드파티 라이브러리 내부 코드**에서 캐시 키/객체 해시/식별자 생성 용도로 사용 | 오탐 | FP — 애플리케이션 코드가 아니며 잔존 조치가 없음. "정보"로 남기지 않는다(2026-09-14 homeshopping/trend-ad/trend-cms/trendissue PHP Weak Crypto 재분류 선례) |
| **애플리케이션(1st-party) 코드**에서 파일 체크섬, 캐시 키, ETag 등 인증/비밀번호와 무관한 용도로 사용 | 정보 / Medium | `php_diagnosis_criteria.md` §2 기준 — 보안 문맥 아니므로 정보성. recommendation에 "향후 인증/토큰 용도로 재사용되지 않도록 주의" 등 **구체적 잔존 조치**를 반드시 명시(단순 "조치 불필요"만 적으면 안 됨 → 아래 공통 규칙 참조) |
| 비밀번호 해싱이나 `password_hash()`로 이미 대체되어 있고 해당 `md5()`는 레거시 호환용 별도 필드 | 오탐(또는 정보) | 실사용 경로 확인 후 판단 — 실제 인증에 사용되면 취약 유지 |

> **⚠️ 공통 규칙 — "정보" 판정 시 잔존 조치 필수 (2026-09-14 추가)**: 위 표에서 "정보"로 판정하는 모든 경우, `recommendation`은 개발팀이 실제로 취할 수 있는 구체적 행동을 포함해야 한다. `recommendation`이 (수식어를 걷어내면) "조치 불필요"로만 귀결되고 잔존 실질 조치 항목이 전혀 없다면, 그 finding은 "정보"가 아니라 **오탐(양호)**으로 판정한다 — "정보"이면서 조치가 불필요한 것은 논리적 모순이며, 개발팀에게 전달되는 보고서에 "정보 — 조치 불필요합니다" 같은 자기모순적 문구가 남게 된다. 이 규칙은 Weak Crypto/LFI-RFI뿐 아니라 이 문서의 모든 candidate_type 판정에 동일하게 적용한다.

---

### 7. Path Traversal 판정 기준 (`PATH_TRAVERSAL_CANDIDATE` → `category: 파일 다운로드 경로 조작`)

**확인 절차**:
1. `fopen`/`file_get_contents`/`readfile`/`unlink` 인자에 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`가 직접 결합되는 경로 확인.
2. `basename()`/`realpath()` + 허용 디렉터리 접두어 검증(`strpos($path, $base_dir) === 0`) 등 경로 정규화·검증 로직 존재 여부 확인.
3. `unlink()` 대상이면 파일 삭제라는 더 높은 영향도(가용성 침해)까지 description에 명시.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 사용자 입력이 필터링 없이 파일 경로에 직접 결합, `../` 통제 없음 | 취약 / High | 임의 파일 읽기/삭제 가능 (CWE-22) |
| `basename()` 또는 허용 디렉터리 접두어 검증 경유 확인 | 오탐 | FP — 정규화/검증 코드를 evidence에 명시 |
| 대상 함수가 `unlink()`이고 검증 없이 사용자 입력 경로 그대로 삭제 | 취약 / High (설명에 "임의 파일 삭제 가능" 명시) | 가용성 침해까지 포함 |

---

### 8. Eval / 코드 인젝션 판정 기준 (`EVAL_CANDIDATE` → `category: 코드 인젝션`)

**확인 절차**:
1. `eval()`/`assert()`(문자열 인자 버전)/`create_function()` 인자에 사용자 입력이 도달하는지 taint 확인.
2. 사용자 입력이 아니라 내부 설정값(직렬화된 캐시 데이터 등)만 실행하는 경우라도, 해당 설정값의 출처가 외부에서 쓰기 가능한지(파일 업로드, DB 등) 추가 확인.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 사용자 입력이 필터링 없이 `eval()`/`assert()`/`create_function()`에 도달 | 취약 / Critical | 임의 PHP 코드 실행 (RCE) 가능 (CWE-95) |
| 내부 설정값만 실행하나 그 설정값이 외부 쓰기 가능한 저장소(업로드된 파일, 사용자 수정 가능 DB 필드)에서 옴 | 취약 / Critical | 간접 경로를 통한 RCE — 근본 원인은 해당 저장소 쓰기 지점에서 별도 finding으로도 병행 고려 |
| 완전히 고정된 내부 문자열만 `eval()`에 전달(사용자 입력·외부 쓰기 경로 전혀 없음) | 정보 / Medium | reachability 부재하나 `eval()` 사용 자체가 유지보수 리스크 |

---

### 9. Insecure TLS Client 판정 기준 (`INSECURE_TLS_CLIENT_CANDIDATE` → `category: INSECURE_TLS_CLIENT`)

> 2026-09-16 ocb_game_biz PHP-010 추가진단으로 신설 — 결제(danal)·게임 API 연동 curl 요청 25개 파일 64개소에서
> `CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST`를 false/0으로 설정한 패턴이 발견됐으나, 당시 8종 후보에
> 없어 `scan_php_baseline.py` 태깅 단계에서부터 누락돼 있었다. 이후 재발 방지를 위한 절차.

**확인 절차**:
1. `curl_setopt`/`curl_setopt_array` 호출에서 `CURLOPT_SSL_VERIFYPEER`가 `false`/`0`으로, 또는 `CURLOPT_SSL_VERIFYHOST`가 `0`/`1`(2 미만)으로 설정되는지 확인.
2. 값이 리터럴(`false`/`0`)이 아니라 변수/조건식(예: `!$insecure`, `$config['verify_ssl']`)이면, 그 변수의 **기본값**과 **외부에서 제어 가능한지**(CLI 플래그, GET/POST 파라미터 등)를 추적한다.
3. 변수 기본값이 검증 활성(true/2)이고, 검증을 끄려면 명시적 opt-in(운영자 전용 CLI 플래그, 별도 인증된 관리자 파라미터 등)이 필요한 진단/디버그 목적 코드인지 확인.
4. 해당 curl 요청의 통신 대상이 결제/과금 연동, 회원 인증, 개인정보 전송 등 민감 데이터를 다루는지 확인 — 영향도 판단 및 recommendation 우선순위 근거로 사용.

**판정**:
| 케이스 | 판정 | 근거 |
|---|---|---|
| 리터럴 `false`/`0`으로 검증 비활성화(조건 없이 항상 적용) | 취약 / Medium | TLS 인증서 미검증 → MITM 공격 가능 (CWE-295). `vuln_taxonomy.md` INSECURE_TLS_CLIENT 기본 severity(Medium) 적용 — 임의 상향 근거 없는 한 유지 |
| 검증 비활성화가 일반 사용자가 도달 불가능한 명시적 opt-in 플래그(기본값은 검증 활성)로만 켜지는 진단/테스트 전용 코드 | 오탐 | FP — 운영 경로가 아니며 기본 동작은 안전. evidence에 기본값과 opt-in 조건을 명시 |
| 결제/인증/개인정보 연동 curl에 해당 패턴이 존재 | 취약 / Medium (recommendation에서 최우선 조치 대상으로 명시) | severity 자체를 상향하지 않되(taxonomy 기본값 유지, 선례 없음), 조치 우선순위만 결제 모듈을 앞세운다 |
| 동일 근본 원인(같은 헬퍼 함수/공통 curl 래퍼)이 여러 파일에서 반복 | 파일 간 병합(단일 finding, `evidence.affected_files`에 전체 지점 나열) | [[feedback_finding_group_merge_policy]] — HARDCODED_SECRET/DTO_EXPOSURE와 동일하게 cross-file 병합 적용 |

---

### 마스킹 및 공통 규칙

- `evidence.code_snippet`/`manual_review_note`에 실제 자격증명·토큰·개인정보 원문이 포함되지 않도록 [[feedback_conservative_security_policy]] 및 기존 skill들과 동일한 마스킹 원칙을 적용한다(예: `'pass'=>'thzptxptmxm01'` → `'pass'=>'***REDACTED***'`).
- **PEM/SSH 개인키 등 블록형 시크릿은 `-----BEGIN...-----`/`-----END...-----` 헤더·푸터까지 포함해 블록 전체를 하나의 placeholder로 치환한다** — 본문(base64)만 `***REDACTED***`로 바꾸고 헤더/푸터 줄은 그대로 남기지 않는다. 헤더 리터럴 문자열 자체가 palantir_result(Bitbucket) 업로드 시 플랫폼 자체 DLP를 독자적으로 트리거해 보안 알림이 발생한 사고가 있었다(2026-09-15, ocb_game_biz_matgo/ocb_game_biz_matgo_php_real — 실제 키 값은 유출되지 않았으나 헤더 텍스트만으로 오탐성 알림 발생). 표기 예: `$gameinfo['privateKey'] = "[REDACTED PEM PRIVATE KEY BLOCK]";` (동일 계열 레포 `ocb_game_biz_admin`에서 실제 사용된 `'***REDACTED(RSA PRIVATE KEY PEM BLOCK)***'` 표기도 동일 취지 — 둘 다 허용되나 `-----BEGIN`/`-----END` 리터럴은 절대 남기지 않는다).
- `SKILL.md` Step 4-2 HARD RULE(`reviewed`/`review_status` 필드 미설정)을 반드시 준수한다 — 이 문서(LLM-Check)는 `result`/`category`/`severity`/`llm_verdict`까지만 채우고, `reviewed`/`review_status`는 `/sec-review`의 사람 판정 전용 필드로 남긴다.
- 9종 candidate_type 모두 순회 완료 후에만 `findings_php.json`을 완성본으로 간주한다 — 일부만 판정하고 중단 시 `task_php_llm.json`에 진행 상태를 남겨 재개 가능하게 한다.
