# 미지원 언어 진단 대상 목록

> palantir 스캐너는 Java/Kotlin을 완전 지원하며, TypeScript/JavaScript 프론트엔드는 XSS/File/Data 스캔 자동 지원 + SCA(npm) 지원.
> 이 파일은 **PHP 등 지원 언어 스캐너가 없어 자동 진단이 불가한 언어**와 향후 스캐너 구현 요구사항을 명세합니다.
>
> PHP 진단 보류 대상 repo 목록: `shared/references/project_ocb_php_targets.md` 참조.

---

## PHP (미지원)

### 현재 처리 방식

자동 스캔 전량 skip. Phase 1 자산 식별 결과에 "PHP 언어 미지원 — 추후 진단 예정" 기록.

### 향후 PHP 스캐너 구현 요구사항

**구현 대상 스크립트**:

| 스크립트 | 역할 | 우선순위 |
|---|---|---|
| `scan_api_php.py` | PHP 라우터(Laravel/CodeIgniter/순수 PHP) API 엔드포인트 추출 | 🔴 |
| `scan_injection_php.py` | SQL Injection: PDO/MySQLi 쿼리 빌더 탐지, `$_GET/$_POST` taint | 🔴 |
| `scan_xss_php.py` | Reflected XSS: `echo $_GET[...]`, `htmlspecialchars` 미적용 패턴 | 🔴 |
| `scan_data_protection_php.py` | 하드코딩된 자격증명, 평문 세션/쿠키, `error_reporting` 노출 | 🟡 |
| `scan_file_processing_php.py` | `move_uploaded_file`, `include $_GET[...]` LFI 패턴 | 🟡 |

**PHP 주요 취약 패턴 참조**:

```php
// SQL Injection — 직접 쿼리 빌드
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysql_query($query);

// Reflected XSS — 미인코딩 출력
echo "<p>" . $_GET['name'] . "</p>";

// LFI — 동적 include
include($_GET['page'] . '.php');

// 하드코딩 자격증명
$db_password = 'admin1234';
define('DB_PASSWORD', 'secret');

// 명령 인젝션
system("ls " . $_GET['dir']);
```

**OCB-THP 프레임워크 분석 필요**:
- ocb_fun_real, ocb_game_biz 등: 레거시 PHP인지 Laravel/CodeIgniter 기반인지 fetch 후 확인
- PHP 버전 확인: PHP8 converting 브랜치 존재 → PHP 7→8 마이그레이션 중

---

## 지원 언어 현황

| 언어 / 프레임워크 | 지원 수준 | 주요 스캔 항목 | Task |
|---|---|---|---|
| Java (Spring MVC / Spring Boot) | ✅ 완전 지원 | Injection / XSS / File / DataProtection / SCA | 2-1~2-5 |
| Kotlin (Spring Boot) | ✅ 완전 지원 | Injection / XSS / File / DataProtection / SCA | 2-1~2-5 |
| TypeScript (React / Next.js / Turborepo) | ✅ 자동 스캔 부분 지원 | FE-XSS(자동) / FE-File(자동) / FE-Data(자동) / SCA-npm(자동) | 자동 스캔 + LLM 검증 |
| JavaScript (Node.js / React) | ✅ 자동 스캔 부분 지원 | FE-XSS(자동) / FE-File(자동) / FE-Data(자동) / SCA-npm(자동) | 자동 스캔 + LLM 검증 |
| PHP | ❌ 미지원 | — | — |
| Python | ❌ 미지원 | — | — |
| Go | ❌ 미지원 | — | — |

**TypeScript/JavaScript 스킬별 자동 스캔 지원 현황** (v1.5 기준):

| Skill | 자동 스캔 지원 | 탐지 항목 | 비고 |
|-------|---------------|-----------|------|
| `/sec-scan-injection` | ❌ skip | — | JS/TS Injection은 LLM 수동 진단 |
| `/sec-scan-xss` | ✅ 지원 | DOM XSS / Redirect XSS | `frontend-llm` 모드 자동 전환 |
| `/sec-scan-file` | ✅ 지원 | FormData 업로드 / FileReader 싱크 / Blob 다운로드 | `frontend` 모드 자동 전환 (v1.1) |
| `/sec-scan-data` | ✅ 지원 | console PII / localStorage / 하드코딩 시크릿 / NEXT_PUBLIC_ | `frontend` 모드 자동 전환 (v1.5) |
| `/sec-scan-sca` | ✅ 완전 지원 | npm CVE (package.json / package-lock.json) | Gradle/npm 자동 감지 |

> **프론트엔드 모드 자동 전환 기준**: Java/Kotlin 파일 < 5개 + `package.json` 존재 → 스크립트가 `_is_frontend_repo()` 함수로 자동 판별, 별도 플래그 불필요.
