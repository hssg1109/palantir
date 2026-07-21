---
name: sec-scan-remediation
description: Jira 티켓 단위 이행점검(remediation verification) — 티켓에 명시된 조치대상 취약점이 최신 소스코드에서 실제로 조치되었는지 재검증. Use when asked to run 이행점검, remediation check, "조치 확인해줘", or verify a specific Jira ticket's vulnerabilities are fixed. Independent of the 5개 sec-scan-* SAST skill과 /sec-review — 이 skill은 신규 진단이 아니라 기존 finding의 사후 재검증만 수행한다.
tools: Read, Glob, Grep, Bash, Edit, Write
---

# Sec Scan Remediation (이행점검)

## Overview

이 skill은 **Jira 티켓 1건에 명시된 조치대상 취약점들이 실제로 조치되었는지**를 최신 clone 소스코드 기준으로 재검증한다.

전제:
- 대상 티켓은 `tools/create_jira_ticket.py`가 발행한 형식(description의 "2.2 취약점 요약 표", labels=[repo명])을 따른다.
- 신규 취약점 탐지가 아니다 — `state/<repo>/*/*/findings_*.json`에 이미 기록된 원본 finding을 기준으로 "그 자리가 여전히 취약한가"만 판정한다.
- Phase 4에서 Jira 코멘트 게시 + 상태 전이(조치대기/잔여 취약점 없음)까지 수행한다 — 단, 실제 게시(POST) 직전에는 반드시 사용자 승인을 받는다 (dry-run으로 내용 확인 후 승인 시에만 실제 API 호출).

독립 실행 가능: `sec-scan-remediation/` + `shared/scripts/fetch_jira_remediation_targets.py` + `tools/clone_repo.py` + `tools/audit_utils.py`

## Workflow

인수: `$ARGUMENTS` = `<TICKET-KEY> [--full]` (예: `SECUFINDINGS-1234`, `SECUFINDINGS-1234 --full`)

인수가 없으면 사용법을 안내하고 대기한다:
```
사용법: /sec-scan-remediation <TICKET-KEY> [--full]
예시:   /sec-scan-remediation SECUFINDINGS-1234
        /sec-scan-remediation SECUFINDINGS-1234 --full   (carry-forward 없이 전량 재검증)
```

- **2차 이상 실행 시 기본 동작(carry-forward)**: 동일 티켓으로 이미 이행점검을 돌린 적이 있으면,
  직전 회차에서 `조치완료`로 확정된 항목은 재검증을 건너뛰고 이전 판정을 그대로 이어받는다 —
  1차에서 미조치/부분조치/확인불가로 남은 항목만 최신 코드로 다시 검증한다. 절차는 Phase 1 참고.
- `--full`을 붙이면 이 carry-forward를 끄고 기존처럼 전체 대상을 처음부터 재검증한다
  (개발자가 관련 코드를 광범위하게 리팩터링했다고 알려온 경우 등에 사용).

### 실행 원칙 (CRITICAL — 반드시 준수)

> **자율 완주**: Phase 0→4를 확인 질문 없이 끝까지 진행한다. 스크립트 실패·매칭 실패 등은
> fallback(해당 항목 "확인불가"/"수동 확인 필요"로 표기) 후 계속 진행한다.
> 예외 1: Jira 인증정보(.env JIRA_TOKEN 등) 누락처럼 사람만 해결 가능한 경우 → 보고 후 대기.
> 예외 2: Phase 4의 실제 Jira 코멘트 게시/상태 전이 직전 → dry-run 결과를 보여주고 반드시
> 사용자 승인을 받은 후에만 실제 POST를 실행한다 (승인 없이 실제 게시 금지).
>
> **완료 후 자동 연결 금지**: 이 skill(Phase 4 포함) 완료 후 `/sec-review` 재실행,
> `ihaeng_compare.py` 실행 등 **다른 skill/스크립트로** 자동 이행하지 않는다. 판정 요약 출력 후 대기.
> (Jira 코멘트 게시·상태 전이는 이 skill 자체의 Phase 4에 포함된 절차이므로 이 금지 대상이 아님 —
> 단 위 예외 2의 승인 절차는 반드시 거친다.)

### Phase 0 — 티켓 조회 & 대상 파싱

```bash
python3 shared/scripts/fetch_jira_remediation_targets.py --ticket <TICKET-KEY>
```

- `state/<repo>/remediation/<TICKET-KEY>/targets.json` 생성됨 — repo명, 티켓 status, 대상 목록(Sub_No/결과/위험도/제목/분류/파일:라인/조치요약/dev_reply)
- repo명을 못 찾으면(labels 비어있음) 사용자에게 repo명을 물을 수밖에 없는 blocking 케이스 — 이때만 보고 후 대기
- targets가 0건이면 "2.2 요약표를 찾지 못함" 사유를 출력하고 종료 (검증할 대상이 없음)

### Phase 1 — Finding 매칭 & sec-review 교차검증

`targets.json`의 각 target에 대해:

1. `state/<repo>/*/*/findings_*.json` 전체를 Grep/Read하여 **(category + file:line)** 기준으로 원본 finding 매칭
   - file:line은 `scope.affected_file`/`scope.endpoint` + line 조합과 대조 (경로 표기가 다를 수 있으니 파일명 basename 기준 보조 매칭 허용)
   - Sub_No/title은 참고용 — 재계산 시 어긋날 수 있어 1차 키로 쓰지 않음
2. 매칭된 finding의 `review_status` 확인:
   - `오탐` 또는 `스킵` → **검증 대상 제외**, 결과에 "리뷰상 오탐 처리됨 — 검증 생략"으로 표기
   - `정탐` 또는 미기록(레거시 finding) → 검증 대상 유지
3. `state/audit_log.json`에서 해당 `finding_id`의 `event_type: finding_reviewed` 항목을 찾아 리뷰어의 코드분석 요약(`auditor.code_analysis_summary`)을 확보 — Phase 3 판정 시 참고자료로 사용
4. 매칭 실패 target은 "원본 finding 유실/이관 — 수동 확인 필요" 목록으로 분리
5. **carry-forward 판정 (`--full` 미지정 시에만)**: 매칭된 각 target에 대해
   ```python
   from tools.audit_utils import uid_for_finding, latest_ticket_verdict
   uid = uid_for_finding(repo, skill, finding)
   prior = latest_ticket_verdict(repo, uid, ticket)
   ```
   - `prior is not None and prior["verdict"] == "조치완료"` → target을 `carry_forward=true`로 표시,
     `prior["verdict"]`/`prior["note"]`/`prior["checked_at"]`을 보존 — **Phase 2(clone)·Phase 3(LLM-Check)
     대상에서 제외**한다 (Phase 4에서 이전 판정을 그대로 결과에 채운다).
   - `prior`가 없거나 `verdict`가 `미조치`/`부분조치`/`확인불가` → 기존과 동일하게 재검증 대상 유지
     (이것이 "1차 미완료 건만 2차 검증"의 실제 동작 지점).
   - `--full` 지정 시에는 이 단계 전체를 생략하고 모든 매칭 target을 재검증 대상으로 유지한다.

**전량 short-circuit**: 위 필터링 후 재검증 대상(carry-forward 아닌 target)이 0건이면 —
targets 자체가 0건이거나 전건이 carry-forward인 경우 — Phase 2(clone)와 Phase 3(LLM-Check)를
생략하고 곧바로 Phase 4로 이동한다. Phase 4에서는 "전 대상이 직전 회차에 조치완료로 확인됨 —
추가 검증 불필요"로 요약하고, 새 clone/재검증이 없었음을 결과 파일과 콘솔 출력에 명시한다.

> **references/remediation_verdict_criteria.md**의 "매칭 실패 처리", "2차 이상 이행점검 — Carry-forward 규칙" 절 참고.

### Phase 2 — 최신 소스 확보

> Phase 1에서 재검증 대상이 0건으로 확정된 경우(전량 carry-forward) 이 Phase는 생략한다.

```bash
python3 tools/clone_repo.py <PROJECT> <REPO> --force
```

- `<PROJECT>`는 `state/<repo>/*/scan_meta.json`의 `bb_project` 필드에서 확인 (없으면 `tools/list_ocb_repos.py` 등 기존 인벤토리로 조회)
- clone 직후 커밋 해시/일시를 확보해 `targets.json`에 병기 (개발자가 답한 "조치 일자" 이후 커밋인지 1차 정황 판단용 — `git -C testbed/<repo> log -1 --format='%H %cI'`)
- clone 실패는 blocking 오류 — 자격증명/네트워크 문제이므로 보고 후 대기

### Phase 3 — Finding별 조치 검증 (LLM-Check, in-context 수행)

> Phase 1에서 `carry_forward=true`로 표시된 target은 이 Phase에서 완전히 제외한다 — 이전
> verdict/note를 그대로 재사용하며 새로 코드를 열어보지 않는다. 재검증 대상이 0건이면 이 Phase
> 자체를 생략한다(Phase 2와 동일 조건).

`references/task_prompts/task_31_remediation_verify.md` 절차를 그대로 따른다. 요지:

검증 대상(carry-forward 아닌) finding마다:
1. 원본 evidence(`scope.affected_file`, `line`, `code_snippet`, `category`, `description`) 로드
2. 최신 clone(`testbed/<repo>/`)에서 동일 경로 확인
   - 경로 존재 → 해당 라인 ±15줄 Read
   - 경로 없음 → 파일명(basename) 기준 Glob으로 이동/리네임 여부 확인 → 그래도 없으면 `확인불가(파일 삭제/이동)`
3. skill별 기존 진단기준 문서를 그대로 재적용해 취약 패턴 잔존 여부 판단:
   - INJ → `sec-scan-injection/references/injection_diagnosis_criteria.md`
   - XSS → `sec-scan-xss/references/` 내 XSS 기준 문서
   - FILE → `sec-scan-file/references/` 내 기준 문서
   - DATA → `sec-scan-data/references/` 내 기준 문서
   - **SCA는 예외** — 코드가 아니라 `pom.xml`/`build.gradle(.kts)`/`package.json`의 버전을 재파싱해 원본 `evidence.fixed_version`과 기계적으로 비교 (LLM 판단 불필요)
4. 판정: `조치완료` / `미조치` / `부분조치` / `확인불가` — 판정 원칙은 `remediation_verdict_criteria.md` 준수 (보수적 판정 — 애매하면 `부분조치`/`확인불가`로, `조치완료` 남발 금지)
5. `dev_reply`(있는 경우)와 실제 코드 변경을 비교해 불일치 시 note에 명시

### Phase 4 — 결과 출력 & 기록

**콘솔 출력 (텍스트로 직접 작성 — echo/printf 금지)**: finding별 판정표 + 요약

```
| Sub_No | 분류 | 파일:라인 | 판정 | 비고 |
|--------|------|-----------|------|------|
| 1-1 | SQL Injection | UserService.java:42 | 조치완료 | (재검증 생략 — 2026-07-01 1차에서 조치완료 확인) |
| 1-2 | XSS/Persistent | BoardController.java:88 | 미조치 | 이스케이프 미적용 그대로 |

요약: 조치완료 1(재검증생략 1건 포함) / 미조치 1 / 부분조치 0 / 확인불가 0 / 검증생략(오탐) 0
```

- carry-forward(재검증 생략) 행은 비고를 위 예시처럼 `(재검증 생략 — <이전 checked_at> 1차에서 <판정> 확인)`으로 표기하고 판정 값 자체는 이전 값을 그대로 쓴다.
- 요약 줄의 각 판정 건수는 carry-forward 포함 합계이며, 조치완료 항목에만 `(재검증생략 M건 포함)`을 덧붙인다 (M=0이면 생략).
- **전량 short-circuit인 경우**: 위 표 대신 "전 대상(N건)이 직전 회차(<날짜>)에 조치완료로 확인됨 — 이번 회차는 신규 clone/재검증 없이 이전 결과를 그대로 확인만 함"으로 출력하고 아래 파일 저장은 그대로 수행한다(감사 추적 목적).

**파일 저장**:
- `state/<repo>/remediation/<TICKET-KEY>/result_<YYYYMMDD>.json` — finding_id별 판정/근거/note. 각 항목에 `"carried_forward": true|false`, carry-forward인 경우 `"carried_forward_from": "<이전 checked_at>"` 필드를 추가한다.
- `state/<repo>/remediation/<TICKET-KEY>/result_<YYYYMMDD>.md` — 사람이 읽는 결과 요약
- `state/<repo>/remediation/<TICKET-KEY>/jira_comment_<YYYYMMDD>.txt` — Jira 위키마크업 코멘트 draft (아래 템플릿)

**기록**:
```bash
python3 tools/audit_utils.py log-remediation \
  --repo <repo> --ticket <TICKET-KEY> \
  --verdicts '{"조치완료": N, "미조치": N, "부분조치": N, "확인불가": N, "검증생략": N}'
```
이 감사로그는 carry-forward 포함 이번 회차의 전체 verdict 분포를 그대로 기록한다 — 회차 자체가 감사 대상이므로 carry-forward라고 생략하지 않는다.

**새로 검증한(carry-forward가 아닌) 판정 finding에 대해서만** (Python 또는 Bash에서 반복):
```python
from tools.audit_utils import uid_for_finding, update_registry_remediation_status
uid = uid_for_finding(repo, skill, finding)
update_registry_remediation_status(repo, uid, verdict, ticket=ticket_key, note=note)
```
carry-forward 항목은 **다시 호출하지 않는다** — 이미 `vuln_registry.json`의 `remediation_checks`에 기록되어 있으므로, 재호출하면 동일 내용이 중복 append된다.

**Jira 코멘트 draft 작성** (`jira_comment_<YYYYMMDD>.txt`):

원본 티켓의 "2.2 취약점 요약 표" 9열(Sub_No/결과/위험도/제목/분류/파일:라인/조치 요약)을 그대로 유지하고
그 뒤에 *이행점검 판정*/*이행점검 비고* 열을 추가, 이어서 *조치 계획*/*조치 일자* 열을 배치한다
(조치완료 행은 계획/일자에 `-`, 미조치·부분조치 행만 `(입력 필요)`로 비워둠). **표는 `{panel}` 블록 밖에
둔다** — panel 매크로 박스는 폭이 넓은 표를 감싸면 표가 파란 테두리 밖으로 삐져나오는 렌더링 한계가 있음.

```
{panel:title=이행점검(Remediation Verification) 결과 — <YYYY-MM-DD>|borderStyle=solid|borderColor=#3b73af|titleBGColor=#3b73af|titleColor=#ffffff|bgColor=#f0f4ff}
검증 기준 커밋: {{<짧은 해시>}} (<커밋일시>, <브랜치>)

이행점검 결과 확인 후 미조치·부분조치 건만 조치 계획/조치 일자 입력 후 회신 바랍니다.
{panel}

|| Sub_No || 결과 || 위험도 || 제목 || 분류 || 파일:라인 || 조치 요약 || 이행점검 판정 || 이행점검 비고 || 조치 계획 || 조치 일자 ||
| ... (판정별 색상: 조치완료={color:green}, 부분조치={color:orange}, 미조치={color:red}) ...
| ... carry-forward 행의 "이행점검 비고"는 "(재검증 생략 — <이전 checked_at> 1차에서 조치완료 확인)"으로 시작 ...

*요약: 조치완료 N(재검증생략 M건 포함) / 미조치 N / 부분조치 N / 확인불가 N / 검증생략(오탐) N*

----

h4. {color:red}조치 미흡 — 확인 및 추가 조치 필요{color}
(미조치·부분조치 건이 있을 때만 — 각 건마다 *미흡사항* / *추가 조치 필요* bullet, 최상단 배치)

h4. 조치 완료
(조치완료 건마다 1줄 조치완료 사유)
```

미조치·부분조치가 0건이면 "조치 미흡" h4 섹션은 생략한다.

**주의 — carry-forward가 있는 2차 이상 회차도 이 h4 섹션 규칙은 동일 적용된다.** carry-forward
건이 섞여 있어 표 내용이 짧아 보여도, 미조치·부분조치가 1건이라도 있으면 "조치 미흡" h4는 반드시
작성한다 (2026-07-16 SECUFINDINGS-2132 2차에서 이 섹션을 빠뜨리고 게시했다가 사용자 지적으로
기존 코멘트를 `--edit-comment-id`로 사후 수정한 사례 있음 — carry-forward 예시가 간단하다고 표
아래 서술까지 생략하지 말 것).

**Jira 상태 전이 판단** (`references/remediation_verdict_criteria.md`의 "Jira 상태 전이 규칙" 참고):
- 미조치 == 0 AND 부분조치 == 0 AND 확인불가 == 0 → 전이명 `"잔여 취약점 없음(조치완료)"`
- 그 외 (미조치 > 0 또는 부분조치 > 0 또는 확인불가 > 0) → 전이명 `"이행점검 완료"` (→ 조치대기)

**게시 (승인 게이트 — CRITICAL)**:

- **전량 short-circuit(전건 carry-forward)인 경우 게시 여부부터 확인한다**: 이번 회차가 신규
  clone/재검증 없이 이전 결과를 그대로 확인만 한 경우, 무조건 재게시하지 말고 "이번 회차는 순수
  확인 재실행이며 판정 변경이 없다 — Jira 코멘트를 새로 남길지" 여부를 먼저 사용자에게 확인한다.
  (`feedback_remediation_jira_publish`의 "이력은 결과와 무관하게 항상 남아야 한다" 원칙은 *실제로
  검증을 수행한* 회차에 적용되는 것이지, 검증 자체를 생략한 회차까지 강제로 코멘트를 남기라는
  뜻은 아니다 — 단, 사용자가 남기길 원하면 그대로 아래 절차를 따른다.)
- **인증 계정**: `tools/post_jira_comment.py`는 기본적으로 `.env`의 `JIRA_TOKEN_REMEDIATION`(코멘트를
  실제로 남길 담당자 본인의 개인 PAT)으로 인증한다 — 공용/타 계정 PAT인 `JIRA_TOKEN`을 쓰면 코멘트
  작성자가 그 계정으로 찍히므로 절대 `--token-var`로 `JIRA_TOKEN`을 강제하지 않는다. `.env`에
  `JIRA_TOKEN_REMEDIATION`이 없으면 스크립트가 경고를 출력하고 `JIRA_TOKEN`으로 fallback하는데, 이
  경우 **실제 POST 전에 사용자에게 알리고** 개인 PAT 등록을 먼저 요청한다 (경고 무시하고 진행 금지).
- **담당자(assignee) 재할당 — 전이 종류에 따라 분기**: 이행점검 워크플로는 항상
  "개발자 → 감사자(핸드오프) → 감사자가 검토 → 전이" 순서라, 전이 직전 담당자는 항상 감사자 자신이다.
  기본 `--no-preserve-assignee` 미지정 동작("전이 직전 담당자로 복원")은 감사자 본인을 복원하는 것과
  같아 담당자가 개발자로 넘어가지 않는다 (2026-07-16 SECUFINDINGS-2132에서 실제로 "담당자
  유성근/보안진단실 유지됨"만 찍히고 개발자에게 안 넘어간 현상으로 확인 — 1차 때는 이를 사람이 수동으로
  재할당해 가려져 있었다). 이 문제를 `--reassign-to-developer`(changelog 역추적)로 해결하되,
  **전이명에 따라 사용 여부가 다르다**:
  - **`"이행점검 완료"`(→ 조치대기, 미조치/부분조치/확인불가가 남아 개발자의 추가 조치가 필요한 경우)**:
    `--reassign-to-developer`를 **반드시 추가**한다 — 개발자가 후속 조치를 해야 하므로 담당자가
    개발자로 넘어가야 한다.
  - **`"잔여 취약점 없음(조치완료)"`(→ Closed, 전건 조치완료로 더 이상 조치할 것이 없는 경우)**:
    `--reassign-to-developer`를 **붙이지 않는다** — 더 이상 개발자가 할 일이 없으므로 담당자는
    감사자(유성근/보안진단실) 자신으로 유지되어야 한다 (기본 담당자 보존 동작 그대로 사용).
    2026-07-16 SECUFINDINGS-2132 3차에서 이 전이에도 `--reassign-to-developer`를 붙였다가 사용자
    지적으로 정정한 사례 있음 — Closed 전이와 조치대기 전이를 동일하게 취급하지 말 것.
  - dry-run 출력에서 "이행점검 완료"는 "전이 후 담당자 재할당 대상(개발자, changelog 역추적): <이름>"이
    실제 개발팀 담당자와 일치하는지, "잔여 취약점 없음(조치완료)"은 담당자가 감사자 본인으로 유지된다는
    보존 메시지가 나오는지 확인한다.
- **코멘트는 전이와 무관하게 항상 남는다 — 원자적 결합 금지**: Jira REST의 "전이+코멘트 1콜"
  (`update.comment.add.body`)은 그 전이의 화면(screen)에 코멘트 필드가 없으면 응답이 200/204로
  성공해도 코멘트가 조용히 무시된다 (2026-07-15 SECUFINDINGS-2131 "잔여 취약점 없음(조치완료)"→Closed
  전이에서 실제로 발생 — 전이는 성공했으나 코멘트가 이력에 안 남음, 잔여 취약점이 없어 "게시할 내용이
  적다"고 코멘트를 생략하거나 결합해도 된다고 판단하면 안 됨). `post_jira_comment.py`는 이제
  **코멘트를 항상 `/comment`로 먼저 별도 POST하고, 그다음 `/transitions`를 별도 POST**하는 순차 방식으로
  동작한다 — 전이 화면 구성과 무관하게 코멘트 이력이 항상 보존된다. 조치완료 0건(잔여 취약점 없음)인
  경우에도 이행점검 이력 자체가 감사 근거이므로 코멘트 생략은 절대 금지.
1. 먼저 dry-run으로 실제 게시될 내용을 사용자에게 보여준다 — 전이명이 `"이행점검 완료"`이면
   `--reassign-to-developer`를 붙이고, `"잔여 취약점 없음(조치완료)"`이면 붙이지 않는다:
   ```bash
   # 전이명 = "이행점검 완료" (조치대기, 개발자 후속조치 필요)인 경우
   python3 tools/post_jira_comment.py --ticket <TICKET-KEY> \
     --file state/<repo>/remediation/<TICKET-KEY>/jira_comment_<YYYYMMDD>.txt \
     --transition-name "이행점검 완료" --reassign-to-developer --dry-run

   # 전이명 = "잔여 취약점 없음(조치완료)" (Closed, 담당자는 감사자 유지)인 경우
   python3 tools/post_jira_comment.py --ticket <TICKET-KEY> \
     --file state/<repo>/remediation/<TICKET-KEY>/jira_comment_<YYYYMMDD>.txt \
     --transition-name "잔여 취약점 없음(조치완료)" --dry-run
   ```
   dry-run 출력에서 "이행점검 완료"는 담당자 재할당 대상(`전이 후 담당자 재할당 대상(개발자,
   changelog 역추적): <이름>`)이 실제 개발팀 담당자와 일치하는지, "잔여 취약점 없음(조치완료)"은
   담당자가 감사자 본인으로 보존된다는 메시지가 나오는지 확인한다.
2. **사용자 승인을 받는다** (AskUserQuestion 등으로 명시적으로 확인) — 이 skill의 유일한 확인 질문 허용 지점.
3. 승인 시에만 위와 동일한 플래그 조합에서 `--dry-run`만 뺀 명령으로 실제 게시.
4. 게시 결과(코멘트 URL, 전이된 상태, 담당자 보존/재할당 메시지)를 출력한다.

**testbed 정리 (Phase 2에서 실제로 clone한 경우에만)**:

Phase 2가 short-circuit되지 않고 이번 회차에 실제로 `clone_repo.py`를 실행했던 경우에 한해,
Jira 게시가 끝난 직후 이 skill이 만든 clone을 정리한다. 전량 carry-forward로 Phase 2 자체를
생략한 회차에는 이 단계도 생략한다 — 이 skill이 만들지 않은 testbed 내용(다른 스캔이 진행
중이거나 SAST skill이 보존 중인 소스일 수 있음)은 건드리지 않는다.

```bash
rm -rf testbed/<repo>/
```

- `clone_repo.py`가 clone 시점에 `state/<repo>/repo_meta.json`에 Bitbucket 프로젝트/브랜치/커밋/
  담당자 메타데이터를 이미 영속 저장했으므로, testbed 삭제로 인한 정보 유실은 없다.
- 삭제 실패(권한 등)는 경고만 출력하고 계속 진행 — blocking 아님.
- 완료 출력에 `testbed 정리: ✅ testbed/<repo>/ 삭제` (또는 실패 시 사유) 한 줄을 추가한다.

완료 후 결과를 출력하고 **대기한다** — `/sec-review` 재실행 등 다른 skill로의 자동 이행은 하지 않는다.
