## Task: PHP 자산 식별 (Asset Identification)

**역할**: 당신은 보안 진단 전문가입니다.
**입력**: 로컬 소스코드 (`testbed/<project>/`)
**출력 파일**: `state/<prefix>/task_php_asset.json`

---

### 컨텍스트

`task_11_asset_identification.md`의 "1-5. PHP 판정" 분기는 PHP를 **미지원 언어로 skip**하도록
설계되어 있다. 이 문서는 그 반대 — `/sec-scan-php` 실행 시 PHP를 **정식 진단 대상으로 삼아
전수 나열**하는 절차다. 라우터/프레임워크가 없으므로 "엔드포인트 목록"은
Java/Kotlin의 `scan_api.py` 산출물이 아니라 **웹루트 하위 `.php` 파일 목록 그 자체**다.

---

### Step 1: 프레임워크 확인 (php_diagnosis_criteria.md §0)

```bash
find testbed/<project>/ -maxdepth 3 -iname "composer.json" -o -iname "artisan"
```

- 발견되면 `references/php_diagnosis_criteria.md` §0 절차(라우팅 테이블 기반 인벤토리)로 전환한다.
- OCB-THP 6개 대상 레포는 사전 확인상 전부 미발견(raw PHP) — 아래 Step 2로 그대로 진행.

### Step 2: PHP 파일 전수 나열

```bash
# 비-PHP 자산(vendor/JS 번들 등) 제외 목록: scan_php_baseline.py의 _EXCLUDE_DIR_RE와 동일 기준
find testbed/<project>/ -name "*.php" \
  | grep -vE "(^|/)(\.git|node_modules|vendor|styleup[^/]*|common/js|PHPExcel|aci-tree)(/|$)" \
  | sort
```

- 결과 파일 수를 `total_php_files`로 기록
- 특이 디렉터리(예: `styleup2024/`, `common/js/`)가 새로 발견되면 위 grep 제외 패턴에 없는지 확인하고,
  `scan_php_baseline.py`의 `_EXCLUDE_DIR_RE`와 여기 두 곳 모두 갱신 필요 여부를 기록

### Step 3: DB/외부 연동 설정 확인

```bash
# DB 접속 정보 wrapper 파일 위치 확인 (하드코딩 자격증명 후보)
grep -rl "mysql_connect\|mysqli_connect\|new PDO\|new mysqli" testbed/<project>/ \
  --include=*.php | head -20

# 공용 DB wrapper 함수 존재 여부 (LLM-Check가 역추적할 대상)
grep -rl "function db_query\|function db_conn\|function_db" testbed/<project>/ --include=*.php
```

### Step 4: Git 메타데이터 수집

```bash
git -C testbed/<project>/ log -1 --format="%H %an %ae %ad %s" --date=short
git -C testbed/<project>/ remote get-url origin 2>/dev/null || echo "remote not set"
git -C testbed/<project>/ log --format="%an %ae" -20 | sort | uniq -c | sort -rn | head -5
```

---

### Step 5: 출력

```json
{
  "task_id": "php-asset",
  "status": "completed",
  "findings": [
    {
      "asset_type": "Web Application (Legacy PHP, No Framework)",
      "repo_type": "backend",
      "tech_stack": ["PHP"],
      "framework": "none",
      "language": "PHP",
      "total_php_files": 64,
      "web_root": "testbed/<project>/ocb_php",
      "db_wrapper_files": ["ocb_php/common/function_db.inc.php"],
      "source_code_path": "testbed/<project>/"
    }
  ],
  "metadata": {
    "source_repo_url": "https://code.skplanet.com/scm/ocb-thp/<repo>.git",
    "branch": "master",
    "commit": "5ca54f5",
    "commit_date": "2026-03-18",
    "commit_message": "최종 커밋 메시지",
    "responsible_person": "미확인 (최종 커밋: 홍길동)"
  },
  "executed_at": "",
  "claude_session": ""
}
```

**`web_root`**: `scan_php_baseline.py` 실행 시 `<src>` 인자로 그대로 사용
**`db_wrapper_files`**: LLM-Check가 SQLI_CANDIDATE 역추적 시 우선 확인할 파일 목록

---

### 금지사항
- Excel 파일, 고객 제공 문서 없이도 실행 가능해야 함 (소스코드만 사용)
- 추측으로 자산 추가 금지 (소스코드에서 확인된 것만)
- 민감정보(API 키, 시크릿, 비밀번호) 포함 금지
