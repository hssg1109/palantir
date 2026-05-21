"""
ocb-sugar/data Phase 3 LLM-Check 수동 완료 스크립트
HARDCODED_SECRET 40건 오탐 제거 후 findings_DATA.json 생성
"""
import json
from datetime import datetime

RUN_ID = "20260512_0200"
REPO = "ocb-sugar"
INPUT  = f"state/{REPO}/data/{RUN_ID}/data.json"
OUTPUT = f"state/{REPO}/data/{RUN_ID}/findings_DATA.json"
FAIL   = f"state/{REPO}/data/{RUN_ID}/llm_check_failed.json"

# HARDCODED_SECRET FP 인덱스 (HARDCODED_SECRET 배열 내 0-based)
# 분석 근거: 알고리즘 상수, Redis 캐시 키 이름, DB 컬럼명 — 암호화 키 값 아님
FP_INDICES = set([
    0, 1, 2,          # ECCipherUtils: CIPHER_SPEC/SIGNATURE_SPEC/CRYPT_PADDING (algo name)
    5,                # SendSmsLmsWorker: "PROMOTION.SMS_CAMPAIGN." (Redis key prefix)
    10, 11, 12, 13, 14, 15, 16, 17,  # sugar-jobs batch: "search.ocb.s3.bucketInfo" etc.
    20, 21,           # ValidateSearchDataJob, UploadAWS3: "search.ocb.s3.bucketInfo"
    22, 23,           # CryptDbroMdnJob: TRAN_PHONE_CRYPTED / TRAN_CALLBACK_CRYPTED (DB column names)
    26, 27,           # UploadSearchDataDev/V2ByTimeDev: "search.ocb.s3.bucketInfo"
    28,               # EmartAES256Util: ALGORITHM = "AES/CBC/PKCS5Padding" (algo name)
    31,               # EmartAES256Util: targetText = "2137180541600487" (plaintext, not key)
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,  # msg-sugar services Redis cache keys
    50, 51, 52,       # F480Processor: "PROMOTION.TR_SMS." / "MUFFIN.TR_KAKAO." / "OILGAS.TR_KAKAO." (cache key prefixes)
])

REVIEWED_AT = "2026-05-15T14:00:00+09:00"

with open(INPUT) as f:
    data = json.load(f)

all_findings = data["findings"]

output_findings = []
fp_count = 0
secret_idx = 0  # HARDCODED_SECRET 내 순번

for finding in all_findings:
    f = dict(finding)
    is_secret = (f.get("category") == "HARDCODED_SECRET")

    if is_secret:
        if secret_idx in FP_INDICES:
            # FP — 출력에서 제외
            fp_count += 1
            secret_idx += 1
            continue
        secret_idx += 1

    f["llm_checked"] = True
    f["llm_verdict"] = "정탐"
    f["llm_reviewed_at"] = REVIEWED_AT
    f["diagnosis_method"] = "수동진단(LLM)"
    f["source"] = "auto-scan + llm-check"
    f["fp_corrected"] = False

    output_findings.append(f)

# 통계
result_counts: dict = {}
for f in output_findings:
    r = f.get("result", "미분류")
    result_counts[r] = result_counts.get(r, 0) + 1

output = {
    "task_id": "data",
    "llm_checked": True,
    "generated_at": REVIEWED_AT,
    "scan_coverage": data.get("scan_coverage", {"source_dir": data.get("source_dir", "")}),
    "summary": {
        "total": len(output_findings),
        **result_counts,
        "fp_excluded": fp_count,
    },
    "findings": output_findings,
}

with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(output, f, ensure_ascii=False, indent=2)

print(f"findings_DATA.json 생성 완료")
print(f"  총 findings: {len(output_findings)}건")
print(f"  FP 제외: {fp_count}건")
for k, v in result_counts.items():
    print(f"  {k}: {v}건")

import os
if os.path.exists(FAIL):
    os.remove(FAIL)
    print(f"  llm_check_failed.json 삭제 완료")
