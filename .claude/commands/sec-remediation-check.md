---
allowed-tools: Read, Glob, Grep, Bash, Edit, Write
description: 이행점검 — Jira 티켓에 명시된 조치대상 취약점이 최신 소스코드에서 실제로 조치되었는지 재검증
---

# Sec Remediation Check (이행점검)

인수: `$ARGUMENTS` = `<TICKET-KEY>` (예: `SECUFINDINGS-1234`)

## 실행 절차

`sec-scan-remediation/SKILL.md` 전체 내용을 읽고 절차대로 실행할 것.

1. `sec-scan-remediation/SKILL.md` 읽기
2. `sec-scan-remediation/references/remediation_verdict_criteria.md` 읽기
3. `sec-scan-remediation/references/task_prompts/task_31_remediation_verify.md` 읽기
4. SKILL.md Phase 0 → 1 → 2 → 3 → 4 순서대로 자율 완주
   - Phase 4는 Jira 코멘트 draft 생성 + 전이명 결정까지는 자율 진행하되, 실제 게시(POST) 직전 반드시 사용자 승인을 받는다 (dry-run 결과를 보여주고 승인 대기 — 유일한 예외 지점)
5. 승인 후 게시 완료 시 결과를 출력하고 대기 (다른 skill 자동 실행 금지)
