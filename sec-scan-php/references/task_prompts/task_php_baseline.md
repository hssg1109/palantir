# Task PHP-Baseline — Auto-Scan(후보 태깅) 실행 절차

## 목적

`scan_php_baseline.py`로 PHP 소스 디렉터리를 직접 순회하며 8종 취약 패턴 후보를 태깅한다.
**판정(TP/FP/category/severity)은 수행하지 않는다** — 전량 `result: "정보"`,
`needs_review: true`로 출력하고 `task_php_llm_review.md` 절차의 LLM-Check가 전담한다.

---

## 실행

```bash
python3 shared/scripts/scan_php_baseline.py <web_root> \
    -o state/<prefix>/php.json
```

- `<web_root>`: `task_php_asset_identification.md` Step 5 출력의 `web_root` 값
  (예: `testbed/ocb_game_biz_matgo/ocb_php`)
- 스크립트가 `.git`/`node_modules`/`vendor`/`styleup*`/`common/js` 하위는 자동 제외한다.
  `task_php_asset_identification.md` Step 2에서 새로운 비-PHP 자산 디렉터리를 발견했다면
  `shared/scripts/scan_php_baseline.py`의 `_EXCLUDE_DIR_RE`에도 반영이 필요한지 확인한다.

## 출력 구조 (`state/<prefix>/php.json`)

```json
{
  "version": "1.0.0",
  "task_id": "php",
  "status": "completed",
  "source_dir": "testbed/ocb_game_biz_matgo/ocb_php",
  "scanned_at": "2026-09-03T10:00:00",
  "summary": {
    "total_files_scanned": 64,
    "total_candidates": 106,
    "by_candidate_type": { "LFI_RFI_CANDIDATE": 75, "HARDCODED_SECRET_CANDIDATE": 4, "...": 0 },
    "note": "판정 없음 — LLM-Check가 전담"
  },
  "candidates": [
    {
      "candidate_id": "PHP-CAND-001",
      "candidate_type": "HARDCODED_SECRET_CANDIDATE",
      "reason": "자격증명 변수/키에 리터럴 문자열 대입: pass",
      "file": "channelcheck.php",
      "line": 19,
      "code_snippet": "$redis_info[] = array('host'=>'172.22.243.134', 'port'=>6379, 'pass'=>'thzptxptmxm01');",
      "result": "정보",
      "needs_review": true,
      "diagnosis_method": "",
      "llm_task_ref": "sec-scan-php/references/task_prompts/task_php_llm_review.md"
    }
  ],
  "findings": []
}
```

- `file`은 `<web_root>` 기준 상대경로다. LLM-Check가 `testbed/<repo>/...`로 Read할 때는
  `source_dir` 값과 조합해 절대/전체 경로를 재구성한다.
- `findings`는 이 단계에서 항상 빈 배열이다 — 값이 채워져 있다면 스크립트 오작동으로 간주하고
  재실행한다.

## 트러블슈팅

| 증상 | 원인 / 조치 |
|---|---|
| `total_files_scanned: 0` | `<web_root>` 경로 오지정 — `task_php_asset_identification.md`에서 확인한 실제 웹루트인지 재확인 |
| 특정 candidate_type이 0건인데 코드상 명백히 존재 | 정규식이 여러 줄에 걸친 호출(멀티라인 함수 호출)은 탐지하지 못함 — LLM-Check Phase에서 `Grep`으로 보완 탐색 필요 (누락 가능성을 `manual_review_note`에 기록) |
| `HARDCODED_SECRET_CANDIDATE` 과다 태깅 | 변수명에 `token`/`pass` 등이 포함된 비-민감 변수(`$csrf_token_field_name` 등)도 매칭됨 — LLM-Check가 FP로 정리 |
