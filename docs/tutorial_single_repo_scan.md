# 튜토리얼 — 레포 1건 진단부터 최종 보고서까지

> 예시 레포: `ocb-webview-api` (프로젝트 키: `OCBWEBVIEW`)  
> 처음 진단을 수행하는 경우 이 문서를 순서대로 따라가면 된다.

---

## 전체 흐름 요약

```
[Phase A] 소스코드 받기      Windows PowerShell에서 clone_repo.py
[Phase B] 진단 자동 실행     WSL에서 run_scan.py 한 번 실행
                             → 세션 초기화 → 5개 skill 순차 진단
                             → findings 검증 → 1차 보고서 Draft 자동 생성
[Phase C] 리뷰 → 최종 보고서  Claude Code에서 /sec-review 로 오탐/정탐 판정
                             → approve_report.py 로 최종 보고서 생성 + Confluence 게시
```

---

## 사전 준비 (처음 한 번만)

### 1. `.env` 파일 확인

```bash
cat ~/palantir/.env
```

아래 항목이 모두 채워져 있어야 한다:

```env
BITBUCKET_BASE_URL=https://code.skplanet.com
CUSTOMER_BB_TOKEN=BBDC-...
CONFLUENCE_BASE_URL=https://wiki.skplanet.com
CONFLUENCE_TOKEN=...
```

없거나 비어 있으면 팀 내 담당자에게 요청.

---

## Phase A — 소스코드 받기 (Windows PowerShell)

> WSL에서 직접 clone 하면 `No route to host` 오류가 발생한다.  
> **반드시 Windows PowerShell 에서 실행한다.**

```powershell
# Windows PowerShell
cd C:\Users\<내계정>\palantir

# 기본 (main 브랜치)
python tools/clone_repo.py OCBWEBVIEW ocb-webview-api

# 브랜치 지정이 필요한 경우
python tools/clone_repo.py OCBWEBVIEW ocb-webview-api --branch develop
```

완료 메시지 확인:

```
[OK] testbed/ocb-webview-api  (branch: main, commit: abc1234)
```

소스코드는 `testbed/ocb-webview-api/` 에 저장된다.  
진단 완료 후에도 **삭제하지 않는다** — 1차 보고서 검토 및 담당자 audit 시 참조용.

---

## Phase B — 진단 자동 실행 (WSL)

WSL(Ubuntu) 터미널로 전환한 뒤 **단 한 줄** 실행한다.

```bash
cd ~/palantir

python3 tools/run_scan.py --repo ocb-webview-api
```

이 명령어 하나로 아래가 자동 수행된다:

1. 공통 RUN_ID 확정 및 state 디렉터리 생성 (5개 skill)
2. 5개 skill 순차 실행 (Auto-Scan → LLM-Check → findings_*.json 저장)
3. findings 스키마 검증 (`validate_findings.py`)
4. 1차 보고서 Draft 생성 (`logs/report_draft_<RUN_ID>.md`)

확인 질문 없이 자동 완주한다. skill별 오류는 fallback 처리 후 다음 skill로 계속 진행.

완료 시 출력 예시:

```
============================================================
[완료] RUN_ID = 20260506_1430  (42.3분)
[완료] 레포: ocb-webview-api
  ✓  injection
  ✓  xss
  ✓  file
  ✓  data
  ✓  sca

Draft 보고서: logs/report_draft_20260506_1430.md

다음 단계 — 오탐/정탐 검토:
  Claude Code에서: /sec-review 20260506_1430 ocb-webview-api
============================================================
```

**RUN_ID** (`20260506_1430`) 를 기록해 둔다 — 이후 모든 단계에서 사용한다.

### 선택 옵션

```bash
# 특정 skill만 실행
python3 tools/run_scan.py --repo ocb-webview-api --skills injection xss

# RUN_ID 직접 지정 (재시작 시 이어서 진행)
python3 tools/run_scan.py --repo ocb-webview-api --run-id 20260506_1430

# LLM 최대 턴 수 조정 (기본 60)
python3 tools/run_scan.py --repo ocb-webview-api --max-turns 80
```

### Draft 보고서 확인 (선택)

```bash
cat logs/report_draft_20260506_1430.md
```

레포별·skill별 finding 건수, Critical/High 상세 목록이 마크다운 표로 정리된다.

---

## Phase C — 리뷰 및 최종 보고서

### C-1. 오탐/정탐 인터랙티브 리뷰

Claude Code(VS Code 확장 또는 터미널)에서 실행:

```
/sec-review 20260506_1430 ocb-webview-api
```

실행하면 각 finding이 순서대로 제시된다:

```
=== 오탐/정탐 인터랙티브 리뷰 ===
RUN_ID : 20260506_1430
레포   : ocb-webview-api
대상   : 23건 (취약/정보 판정 findings)

판정 입력 방법:
  정탐 (실제 취약점)    → 1  또는  y
  오탐 (false positive) → 0  또는  n
  스킵 (나중에 판정)    → s  또는 Enter
  종료                  → q
  의견/질문             → 자유 텍스트 입력 → 코드 확인 후 분석
===================================

[1/23] injection — INJ-001
위험도 : High
제목   : PreparedStatement 미사용 쿼리 직접 조합
위치   : src/main/java/com/ocb/api/OrderController.java:142
...

판정 [1=정탐 / 0=오탐 / s=스킵 / q=종료 / 의견 입력]:
```

**판정 플래그만 입력할 경우**: 결과가 즉시 저장된다.  
**자유 텍스트(의견·질문)를 입력할 경우**: Claude가 `testbed/<repo>/` 의 실제 소스 파일을 읽고 코드 레벨에서 취약점 존재 여부를 분석한 뒤 답변한다. 이후 재판정 프롬프트가 표시된다. 추가 질문이 있으면 계속 대화한 뒤 최종 판정을 입력한다.

판정 결과는 finding 파일에 즉시 저장되므로 중단해도 진행 내용이 보존된다.

### C-2. 최종 보고서 생성 + Confluence 게시

리뷰 완료 후 아래 명령어로 최종 보고서를 생성하고 Confluence에 자동 게시한다:

```bash
python3 tools/approve_report.py \
    --run-id 20260506_1430 \
    --repo ocb-webview-api \
    --publish
```

자동으로 수행되는 작업:
1. 오탐 판정 finding의 `result` → `"양호"` 변경
2. `logs/report_final_20260506_1430.md` 생성
3. `~/palantir-reports/ocb-webview-api/20260506_1430/` 에 git 커밋
4. Confluence 페이지 자동 생성

Confluence 게시 위치:
- 부모 페이지: `https://wiki.skplanet.com/pages/viewpage.action?pageId=750459063`
- 페이지 제목: `ocb-webview-api-진단결과`

페이지 제목을 변경하려면:

```bash
python3 tools/approve_report.py \
    --run-id 20260506_1430 \
    --repo ocb-webview-api \
    --publish \
    --title "OCB Webview API 보안진단결과"
```

Confluence 게시 없이 보고서만 생성하려면 `--publish` 생략:

```bash
python3 tools/approve_report.py \
    --run-id 20260506_1430 \
    --repo ocb-webview-api
```

---

## 완료 — 결과물 목록

| 결과물 | 경로 |
|---|---|
| 진단 원시 데이터 | `state/ocb-webview-api/*/20260506_1430/` |
| 소스코드 (보존) | `testbed/ocb-webview-api/` |
| 1차 보고서 (Draft) | `logs/report_draft_20260506_1430.md` |
| 1차 보고서 (Final) | `logs/report_final_20260506_1430.md` |
| 보고서 이력 커밋 | `~/palantir-reports/ocb-webview-api/20260506_1430/` |
| 최종 보고서 | `logs/final_ocb-webview-api_20260506_1430.md` |
| Confluence 게시 | `{wiki.skplanet.com}/ocb-webview-api-진단결과` |

---

## 빠른 참조 — 전체 명령 순서

```powershell
# [Windows PowerShell] Phase A: 소스코드 받기
python tools/clone_repo.py OCBWEBVIEW ocb-webview-api
```

```bash
# [WSL] Phase B: 진단 자동 실행 (단일 트리거)
cd ~/palantir
python3 tools/run_scan.py --repo ocb-webview-api
# → RUN_ID 확인 (예: 20260506_1430)
# → logs/report_draft_20260506_1430.md 자동 생성
```

```
# [Claude Code] Phase C-1: 오탐/정탐 인터랙티브 리뷰
/sec-review 20260506_1430 ocb-webview-api
```

```bash
# [WSL] Phase C-2: 최종 보고서 생성 + Confluence 게시
python3 tools/approve_report.py \
    --run-id 20260506_1430 \
    --repo ocb-webview-api \
    --publish
```

---

## 재진단

같은 repo를 재진단하면 새 타임스탬프 디렉터리가 생성된다.  
소스코드가 이미 `testbed/ocb-webview-api/` 에 있으면 clone 없이 Phase B부터 시작한다.

```
state/ocb-webview-api/
├── injection/
│   ├── 20260506_1430/   ← 1차 진단
│   └── 20260513_0930/   ← 재진단
├── xss/
│   ├── 20260506_1430/
│   └── 20260513_0930/
...
```

---

## 막혔을 때

| 증상 | 원인 | 조치 |
|---|---|---|
| clone `No route to host` | WSL에서 clone 시도 | Windows PowerShell에서 실행 |
| clone 401 | Bitbucket 토큰 만료 | `.env` CUSTOMER_BB_TOKEN 재발급 |
| `[ERROR] 소스코드 없음` | testbed/ 미존재 | Phase A clone 먼저 실행 |
| skill 실행 중 오류 | 일시적 LLM 오류 | 동일 RUN_ID로 `--run-id` 지정 후 재실행 |
| `findings 없음` 경고 | RUN_ID 불일치 | `ls state/ocb-webview-api/injection/` 로 실제 타임스탬프 확인 |
| Confluence 401 | API 토큰 만료 | `.env` CONFLUENCE_TOKEN 재발급 |
