# 이행점검 판정기준

`/sec-scan-remediation`(이행점검) Phase 3에서 사용하는 4단계 판정값과 적용 원칙.

## 판정값 정의

| 판정 | 의미 | vuln_registry.status |
|---|---|---|
| 조치완료 | 원본 evidence 위치의 취약 패턴이 사라졌고, 대체 구현이 안전함을 코드로 확인 | `verified_fixed` |
| 미조치 | 원본 evidence 위치의 취약 패턴이 그대로 남아있음 | `still_open` |
| 부분조치 | 직접적인 패턴은 사라졌으나 우회 가능성·유사 경로가 남아있음 (예: 이 endpoint는 고쳤으나 동일 패턴이 인접 메서드에 존재) | `partially_fixed` |
| 확인불가 | 파일 삭제/이동, 모듈 제거 등으로 원본 위치를 특정할 수 없어 판단 근거 부족 | 변경 없음 (기존 status 유지) |

## 판정 원칙

1. **보수적으로 판정한다.** 애매하면 `조치완료`로 올리지 말고 `부분조치` 또는 `확인불가`로 내린다.
   `/sec-review`의 `feedback_conservative_security_policy` 기조와 동일하게, 확실한 반증이 없는 한
   "조치됐을 것"이라고 가정하지 않는다.
2. **원본 skill의 진단기준을 그대로 재적용한다.** 새로운 취약점 유형을 발굴하지 않는다 — 이 skill은
   재진단이 아니라 "그 자리가 여전히 원본 finding이 지적한 문제를 갖는가"만 확인한다.
3. **SCA는 코드가 아니라 버전으로 판정한다.** `pom.xml`/`build.gradle(.kts)`/`package.json`의 선언
   버전이 원본 finding의 `evidence.fixed_version` 이상이면 `조치완료`, 아니면 `미조치`. LLM 추론 불필요.
4. **개발자 회신(`dev_reply`)은 참고자료일 뿐, 판정 근거가 아니다.** 실제 코드를 봐서 판정하고,
   회신 내용과 실제 코드가 다르면 note에 그 불일치를 명시한다 (예: "PreparedStatement 적용했다고
   회신했으나 실제로는 문자열 결합 잔존").
5. **매칭 실패 처리.** 티켓의 target을 원본 finding과 (category + file:line)으로 매칭하지 못하면
   `확인불가` 처리하고 "원본 finding 유실/이관 — 수동 확인 필요"로 note에 남긴다. 임의로 파일을
   추측해 판정하지 않는다.
6. **오탐/스킵 finding은 검증하지 않는다.** `/sec-review`에서 이미 `오탐`으로 판정된 finding은
   애초에 "조치대상"이 아니므로 이행점검 대상에서 제외하고 "검증생략(오탐)"으로만 표기한다.

## Jira 상태 전이 규칙

Phase 4에서 판정 요약(조치완료/미조치/부분조치/확인불가 건수)을 바탕으로 아래 전이명을 결정한다
(`python3 tools/post_jira_comment.py --ticket <KEY> --list-transitions`로 실제 워크플로에 존재하는지
매 실행마다 확인 — 프로젝트별로 전이명이 다를 수 있음):

| 조건 | 전이명 | 결과 상태 |
|---|---|---|
| 미조치 == 0 AND 부분조치 == 0 AND 확인불가 == 0 (전건 조치완료) | `잔여 취약점 없음(조치완료)` | Closed |
| 그 외 (미조치 > 0 또는 부분조치 > 0 또는 확인불가 > 0 하나라도) | `이행점검 완료` | 조치대기 |

`확인불가`를 조치완료로 간주해 종결 전이를 타지 않는 이유: 원본 위치를 특정 못해 조치 여부를
확인할 수 없는 상태이므로 보수적 판정 원칙(1번)에 따라 "재확인 필요" 쪽(조치대기)으로 남긴다.

전이 실행 시 인증 계정(`JIRA_TOKEN_REMEDIATION` 필수)과 담당자 보존/복원 절차는 `SKILL.md`
Phase 4의 "게시 (승인 게이트 — CRITICAL)" 절 참고.

## 2차 이상 이행점검 — Carry-forward 규칙

동일 티켓으로 `/sec-remediation-check`를 두 번째 이상 실행할 때, 직전 회차에서 이미 `조치완료`로
확정된 항목까지 매번 clone+LLM 재검증하는 것은 낭비다. 아래 규칙으로 "1차에서 미완료로 남은
건만" 재검증한다 (`--full` 지정 시 이 절 전체를 적용하지 않고 기존처럼 전량 재검증).

**매칭 키**: Phase 1에서 계산하는 `uid = uid_for_finding(repo, skill, finding)`. Sub_No는 표
재생성 시 어긋날 수 있어 쓰지 않는다 (기존 "매칭 실패 처리" 절과 동일한 이유).

**판단 근거**: `tools/audit_utils.py`의 `latest_ticket_verdict(repo, uid, ticket)` — 이 uid의
`remediation_checks` 배열(이미 Phase 4에서 `update_registry_remediation_status`가 누적해온 값)
중 **동일 ticket**에 해당하는 항목만 필터링해 **리스트 마지막(append 순서상 최신)** 1건을 본다.
`remediation_checks`는 append-only이므로 리스트 순서로 최신을 가린다 — `checked_at`은 날짜
단위(YYYY-MM-DD)라 같은 날 재판정(예: 초회 `미조치` → 당일 `부분조치`로 정정, 실제
SECUFINDINGS-2132 2-1에서 발생)이 있으면 문자열 비교로는 최신을 구분할 수 없으므로 **`checked_at`
값으로 정렬/비교하지 않는다**.

**동일 티켓 한정**: 다른 티켓에서 같은 finding이 `조치완료`로 확인된 이력이 있어도, 이번 티켓
판단에는 쓰지 않는다 — 서로 다른 티켓은 검증 시점·브랜치가 다를 수 있어 섞으면 오판 위험이 있다.

**조건**:
| 직전 회차(동일 ticket) 최신 verdict | 이번 회차 처리 |
|---|---|
| `조치완료` | carry-forward — Phase 2(clone)·Phase 3(LLM-Check) 대상에서 제외, 이전 verdict/note/checked_at 그대로 재사용 |
| `미조치` / `부분조치` / `확인불가` | 재검증 대상 유지 (이것이 "1차 미완료 건 2차 검증"의 본 목적) |
| 이력 없음(최초 실행/registry 미동기화) | 재검증 대상 유지 (보수적 기본값 — 원칙 1과 동일 기조) |

**전량 short-circuit**: 매칭+carry-forward 필터링 후 재검증 대상이 0건이면(전건 carry-forward
또는 애초에 target 0건) Phase 2·3을 생략하고 곧바로 Phase 4로 이동한다. 이 경우 `vuln_registry.json`
갱신도, `update_registry_remediation_status()` 재호출도 하지 않는다 — 아무것도 새로 검증하지
않았으므로 기록할 새 판정이 없다. 다만 `log_remediation_check()` 감사로그와 `result_<날짜>.json`
파일은 "이번 회차 실행 사실 자체"의 감사 추적을 위해 그대로 남긴다.

**registry 중복 append 방지**: carry-forward 항목에는 `update_registry_remediation_status()`를
다시 호출하지 않는다 — 이미 기록된 동일 내용이 `remediation_checks`에 중복 누적되는 것을 막기
위함이며, 새로 검증한(carry-forward가 아닌) 항목에만 호출한다.
