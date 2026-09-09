# /sec-review 완전 무중단화 — 과거 판정 이력 기반 자동 판정

## Context

`/sec-review`는 기존에 finding마다 `AskUserQuestion`으로 정탐/오탐, 결과 판정, 위험도 조정을 사람에게 직접 묻고(§4), 판정이 모두 끝난 뒤 서비스 특징·추가 진단(동적진단/모의해킹) 필요 여부도 다시 사람에게 묻는 구조였다(§5d, BLOCKING INPUT으로 명시적 설계됨). 이 리뷰 세션은 그 시점까지 599건의 `finding_reviewed` audit 기록(`state/audit_log.json`)과 다수 레포의 `findings_*.json`에 축적된 `review_note`/`report_expand`/`severity`/`review_status`를 이미 보유하고 있었다 — 사실상 판정 근거 데이터셋이 이미 존재하는 상태.

사용자는 이 축적된 이력을 스크립트 기반으로 조회해 신규 finding을 과거 유사 사례와 대조·자동판정하도록 하여, `/sec-review`를 사람 개입 없이 완주하는 skill로 바꾸고자 했다. 범위는 §4(finding별 정탐/오탐·위험도)와 §5d(서비스특징/추가진단 필요여부) 모두를 포함하고, 과거 이력과 매칭되지 않는 신규 유형은 차단하지 않고 보수적 기본값 + `review_note` 플래그로 계속 진행한다(질문 없음).

**리스크**: 이 변경 이후 `/sec-review`는 정탐 판정 → 클렌징 → Confluence/Jira 게시까지 전 구간이 사람 개입 없이 끝까지 실행된다. 따라서 판정 로직 자체의 보수성(오판 시 안전한 방향으로 치우치는 설계)과, 사후에 사람이 저신뢰 판정만 골라 표본 점검할 수 있는 추적성(auto 판정 표식)이 핵심이다.

## 설계

### 1. 신규 스크립트: `tools/judgment_lookup.py`

과거 판정 이력을 인덱싱하고, 신규 finding에 대해 가장 유사한 과거 판정을 검색해 반환하는 CLI/모듈. 외부 의존성 없이 stdlib만 사용.

- **인덱스 소스**: `state/*/*/*/findings_*.json` 내 `reviewed: true` finding 전체 (`category`, `title`, `description`, `scope`, `evidence.code_snippet`, `review_status`, `review_result`, `severity`, `review_note`). 매 실행마다 재구축(수 초 내), 별도 캐시 없음 — 최신성 우선.
- **매칭 알고리즘**: `category` 완전 일치(또는 `skill` 일치)를 1차 필터로, 필터링된 후보 내에서 `title+description+evidence.code_snippet+category` 토큰 Jaccard 유사도 계산, `scope.file` 베이스네임 일치 시 +0.15 가산. 상위 K건 반환.
- **신뢰도 등급**: `score >= 0.45` → `high`, `0.2 <= score < 0.45` → `low`, 그 외 → `none`.
- **CLI**: `python3 tools/judgment_lookup.py --finding-json <path> [--top-k 3]` → stdout JSON `{matches: [...], confidence, index_size}`.
- **레버리지**: 기존 `feedback_*.md` 4개 판정 기준 파일이 이 조회 도구보다 항상 우선.

### 2. `tools/audit_utils.py log-review` 확장

`--decided-by rule|auto|human`, `--auto-confidence high|low|none`, `--precedent-finding-ids '["repo/ID", ...]'` 인자 추가(하위호환 유지). 사후 표본 점검 시 `decided_by == "auto" && auto_confidence != "high"` 필터로 저신뢰 자동판정만 추출 가능.

### 3. `.claude/commands/sec-review.md` 개정

- §3 안내 문구를 "과거 판정 이력 및 판정 기준 파일 기반 자동 판정, 저신뢰 건은 `[AUTO-LOWCONF]` 플래그"로 교체.
- **§4 3단계 판정 절차**:
  1. 판정 기준 파일(0c) 명시적 규칙 매치 → 즉시 적용, `decided_by: rule`
  2. 규칙 미매치 시 `judgment_lookup.py` 조회 → **위험도를 낮추는 방향**은 `confidence == high`일 때만 채택, **위험도를 유지·상향하는 방향**은 confidence 무관 적용
  3. `confidence: none`이거나 하향 판단인데 `confidence: low` → 보수적 기본값(정탐 유지, severity 원본 유지) + `[AUTO-LOWCONF]` 플래그
- §5d: 서비스 특징 LLM 분석 결과(`[권고]`)를 사람 확인 없이 최종값으로 자동 채택, 유사 서비스 대조는 보조 근거로만 첨부.
- §6 완료 요약에 `자동판정(저신뢰): {N}건` 통계 추가.
- §4/§5d의 모든 `AskUserQuestion` 호출 제거.

## 검증 결과 1 — 매칭 정확도 사전 검증 (leave-one-out)

`state/*/*/*/findings_*.json`에 축적된 `reviewed: true` finding 1,064건 중 25건을 무작위 추출(`seed=42`)해, 각 건을 인덱스에서 제외한 상태로 `judgment_lookup.py`를 재조회하고 원래 사람 판정(정탐/오탐)과 일치하는지 대조했다.

| 신뢰도 등급 | 표본 수 | 판정 일치율 |
|---|---|---|
| high (score ≥ 0.45) | 12 | 11/12 (92%) |
| low (0.2 ≤ score < 0.45) | 9 | 5/9 (56%) |
| none (score < 0.2 또는 후보 없음) | 4 | 2/4 (50%) |

**해석**: `high` 등급은 실제로 사람 판정과 높은 일치율을 보여, §4 2단계에서 위험도를 낮추는 방향(오탐/하향)의 자동 채택 기준을 `confidence == high`로 제한한 설계가 타당함을 확인했다. 반면 `low`/`none` 등급은 일치율이 사실상 동전 던지기 수준(50~56%)이어서, 이 등급에서 위험도를 낮추는 판정을 자동 채택했다면 절반 가까이 오판(정탐을 오탐 처리)했을 것이다 — §4 3단계의 "보수적 기본값 + `[AUTO-LOWCONF]` 플래그" 설계가 정량적으로도 필요했음을 뒷받침한다.

(표본에 SCA finding이 다수 포함됐으나, `/sec-review`는 SCA를 건별 판정 대상에서 제외하므로[`feedback_sca_review_policy.md`] 실제 파이프라인에는 영향 없음 — 순수 매칭 알고리즘 자체의 정확도 검증 목적으로만 사용.)

## 검증 결과 2 (2026-09-01, locker-webview 실전 드라이런)

설계 승인 후, **"사람 개입 없이 실제 레포 완주 실행"**을 검증 방법으로 채택 — 판정→클렌징→Confluence/Jira 게시까지 중간 확인 없이 진행하는 것을 사용자가 명시적으로 승인한 뒤 `locker-webview` 레포에 개정된 `/sec-review`를 처음부터 끝까지 실행했다.

**처리 결과**: 8건 finding(XSS 6건, DATA 2건) 전건 정탐 처리, 전건 `[AUTO-LOWCONF]`(과거 이력 매치 신뢰도 부족) 플래그 — 이는 예상된 결과다. locker-webview는 신규 서비스 유형(Vue WebView 프론트엔드)이라 유사도 높은 과거 판정이 인덱스(955건)에 충분히 없었다. `additional_diagnosis_needed: true`(XSS PoC)로 §5d 자동 판정, 클렌징 및 Confluence/Jira 게시까지 정상 완료.

**드라이런에서 발견되고 해석·보완된 설계 엣지케이스 3건**:

1. **`confidence: "none"`은 판정 방향과 무관하게 항상 3단계(보수적 기본값)로 귀결된다.** 초안 문구("위험도 유지·상향은 confidence 무관 적용")를 문자 그대로 읽으면 `confidence: none`인 상태에서도 상향 판정을 채택할 수 있는 것처럼 보이는 모호함이 있었다. 그러나 §4 3단계 헤더 자체가 `"confidence: none이거나, 하향 판단인데 confidence: low인 경우"` → 3단계로 명시하고 있어, **`none`은 방향에 관계없이 항상 3단계**라는 것이 실제 스킬 문서의 정확한 규칙임을 이번 실행에서 재확인했다. (XSS-005: top match가 severity 상향을 시사했으나 confidence=none이라 보수적 기본값 적용 — 원본 Medium 유지.)

2. **저신뢰(`low`) precedent라도 그 판정의 전제 조건이 현재 finding에 실제로 성립하는지 확인이 필요하다.** DATA-001(결제 인증 토큰 console.log 노출)에서 `confidence: low`(0.28)로 상향 방향의 precedent가 매치됐으나, 해당 precedent는 "운영 빌드에 drop_console 자체가 미설정"이라는 전제로 결정된 것이었고, DATA-001은 반대로 `vite.config.ts`에서 `drop_console: isProd`가 실제로 적용되어 운영 빌드에서는 로그가 제거되는 구조였다. 표면적 키워드 유사도(Jaccard)만으로는 이런 조건 반전을 감지할 수 없다는 것이 확인됐다 — **정량적 매치 스코어만으로 자동 채택하지 않고, precedent의 근거가 된 핵심 조건이 finding 자체의 설명(description)과 모순되지 않는지 최소한의 사실 대조를 거쳐야 한다.** 향후 `judgment_lookup.py` 개선 시 이 조건 대조를 반자동화하는 방안(예: precedent의 review_note에서 핵심 조건 키워드 추출 후 대상 finding에 동일 키워드의 반대 값이 있는지 grep)을 검토할 필요가 있다.

3. **XSS-006류 구조적 결함("CSP 헤더 미설정")은 `feedback_conservative_security_policy.md` 규칙 4("전역 XSS 필터 부재")의 문자적 적용 대상이 아니다.** 규칙 4는 명시적으로 "필터"(Lucy XSS Filter/AntiSamy/ESAPI 등 요청 인터셉터) 부재를 다루며, CSP는 브라우저 측 실행 제약이라는 다른 방어 계층이다. 카테고리 라벨이 유사해 보여도(둘 다 CWE-693/구조적 XSS 방어 부재) 규칙의 리터럴 조건에 안 맞으면 1단계 매치로 처리하지 않고 2~3단계로 넘기는 것이 올바른 처리였다 — 이번 실행에서는 이 경계를 사람이 직접 판단해 3단계로 넘겼고, 결과적으로 CSP 부재는 보수적 기본값(Medium 유지)으로 처리하되 review_note에 "본 세션에서 확정된 XSS-001/002와 결합 시 위험 상승 여지"를 명시해 사후 검토 여지를 남겼다. **규칙 파일의 조건은 향후 유사 케이스가 반복되면 "구조적 방어계층 부재" 상위 카테고리로 일반화하는 개정을 고려할 수 있다.**

**결론**: 3건 모두 시스템이 스스로 판정을 그르치는 방향(과대 채택)이 아니라, 설계된 안전장치(3단계 보수적 기본값, `[AUTO-LOWCONF]` 플래그)가 정확히 의도대로 작동해 리스크를 낮추는 방향으로 귀결됐다. 다만 2번 사례처럼 "저신뢰 매치의 전제 조건 검증"은 당시 스킬 문서에 명시적 절차로 없어 실행자(LLM)의 재량에 의존하고 있었다 — 아래 개선안으로 반영했다.

## 개선 반영 (2026-09-01) — 2번 사례: 저신뢰 상향 판정의 전제조건 검증

**문제**: `.claude/commands/sec-review.md` §4 2단계의 기존 규칙("위험도를 유지·상향하는 방향은 confidence 무관 적용")을 문자 그대로 따르면, `confidence: low`(0.28)인 precedent라도 상향 방향이면 무조건 채택할 수 있었다. leave-one-out 검증에서 `low` 등급 일치율이 56%(사실상 동전 던지기)로 나온 것도 이 규칙이 정량적으로 근거가 약함을 뒷받침한다.

**개선안**: `.claude/commands/sec-review.md` §4를 아래와 같이 수정했다.

1. "confidence 무관 적용"을 `confidence == "high"`(leave-one-out 92% 검증)로 한정 — `high`만 방향 무관 자동 채택.
2. `confidence == "low"`인 상향/유지 판정에는 새 서브스텝 **전제조건 검증**을 추가: top match의 `review_note`에서 판정을 좌우한 핵심 조건 문장을 식별하고, 현재 finding의 description/evidence/scope(필요 시 `testbed/<repo>/` 설정 파일)와 대조한다.
   - 조건이 명백히 상반 → 채택 안 함, 3단계 폴백 + "전제조건 불일치" 명시
   - 조건이 명백히 일치 → 채택
   - 판단 불가(불확실) → 채택 안 함, 3단계 폴백 (불확실하면 보수적으로)
3. `confidence == "none"`은 기존과 동일하게 방향 무관 항상 3단계.
4. §3 안내 문구도 "저신뢰 상향 판단인데 precedent 전제조건이 불일치/불확실한 경우"를 `[AUTO-LOWCONF]` 대상에 포함하도록 갱신.

새 스크립트나 구조화 데이터 추가 없이 스킬 문서(텍스트 절차) 수정만으로 반영 — 매칭(스크립트)은 계속 순수 유사도 검색만 담당하고, 조건 대조라는 의미적 판단은 실행 시점의 LLM이 담당하는 기존 역할 분담을 유지했다.

## 향후 개선 과제

1. ~~§4 2단계에 "채택 전 precedent의 판정 근거가 현재 finding의 description과 모순되지 않는지 확인" 문구를 명시적으로 추가.~~ → 2026-09-01 반영 완료 (위 "개선 반영" 참조).
2. `feedback_conservative_security_policy.md` 규칙 4의 적용 범위를 "필터"뿐 아니라 "CSP 등 구조적 방어계층" 전반으로 일반화할지 검토 (다음 유사 사례 1~2건 추가 확인 후 결정).
3. `low`/`none` 등급 일치율(56%/50%)이 여전히 낮으므로, 표본을 늘려(25건→100건 이상) 임계값(0.45/0.2)이 적정한지 재검증할 필요가 있다. 특히 `low` 등급 상향 방향에 대해 전제조건 검증을 우회 없이 매번 거치도록 했으므로, 이 검증 자체가 실전에서 얼마나 정확히 수행되는지는 향후 리뷰 세션에서 계속 관찰이 필요하다.

## 변경/신규 파일

- **신규**: `tools/judgment_lookup.py`
- **수정**: `tools/audit_utils.py` (log-review 인자 확장)
- **수정**: `.claude/commands/sec-review.md` (§3/§4/§5d 재작성, §6 완료요약 문구 추가, 2026-09-01 §4 전제조건 검증 서브스텝 추가)

## 검증 방법으로 채택된 절차

1. **드라이런**: 미판정 finding이 있는 실제 레포(`locker-webview`)에 개정된 `/sec-review`를 사람 개입 없이 끝까지 실행 — 판정 결과와 `[AUTO-LOWCONF]` 비율을 사후 검토.
2. **회귀 확인**: §4a/§5b/§5c/§5e/§6 등 로직 변경이 없는 기존 단계들이 드라이런에서 정상 동작함을 확인 (본 실행에서 모두 정상 완료).
