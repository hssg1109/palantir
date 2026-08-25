---
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
description: 인증/인가/어뷰징 취약점 진단 — Auth Bypass / IDOR / Mass Assignment / Rate Limit / 멱등성 / 클라이언트 신뢰 로직 — scan_api.py + scan_auth_baseline.py(후보 태깅) + LLM 전량 수동진단
---

# Sec Scan Auth

대상: $ARGUMENTS (미입력 시 testbed/ 내 대상 목록을 먼저 확인)

## 실행 절차

`sec-scan-auth/SKILL.md` 전체 내용을 읽고 절차대로 실행할 것.

1. `sec-scan-auth/SKILL.md` 읽기
2. `shared/references/task_prompts/task_11_asset_identification.md` 읽기
3. `sec-scan-auth/references/task_prompts/task_26_auth_abuse_review.md` 읽기
4. 공유 references (`shared/references/`) 필요 항목 읽기 — 특히 `vuln_taxonomy.md` §6
5. SKILL.md Phase 1 → Auto-Scan(판정 없는 후보 태깅) → LLM-Check(전량 수동진단) 순서대로 자율 완주
