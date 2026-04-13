---
allowed-tools: Read, Glob, Grep, Bash, Edit, Write, Agent, WebFetch
description: SQL Injection, OS Command Injection, SSI Injection 정적 진단 — scan_injection_enhanced.py + LLM 교차검증
---

# Sec Scan Injection

대상: $ARGUMENTS (미입력 시 testbed/ 내 대상 목록을 먼저 확인)

## 실행 절차

`sec-scan-injection/SKILL.md` 전체 내용을 읽고 절차대로 실행할 것.

1. `sec-scan-injection/SKILL.md` 읽기
2. `shared/references/task_prompts/task_11_asset_identification.md` 읽기
3. `sec-scan-injection/references/task_prompts/task_22_injection_review.md` 읽기
4. `sec-scan-injection/references/injection_diagnosis_criteria.md` 읽기
5. 공유 references (`shared/references/`) 필요 항목 읽기
6. SKILL.md Phase 1 → 2 → 3 순서대로 자율 완주
