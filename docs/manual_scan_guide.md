# palantir 무중단 보안 진단 절차

> palantir v0.4+ 기준 | 대상 환경: code.skplanet.com (Bitbucket Server)  
> **무중단(Non-stop)**: 소스코드는 보존하며, SAST → LLM-Check → 정/오탐 판정 → 보고서 생성 → Confluence 게시까지 전 과정 연속 수행.

---

## 전체 흐름

```
[Windows PowerShell]         [WSL / Claude Code]
  ① Clone                    ② 세션 초기화
  (Bitbucket → testbed/)     (new_scan.py × 5 skill)
                             ③ SAST 진단 × 5 skill
                               (skill → Auto-Scan → LLM-Check
                                → findings_*.json → Summary)
                             ④ 1차 보고서 Draft
                             ⑤ /sec-review — 정/오탐 판정
                             ⑥ approve_report.py
                                → 최종 보고서 + Confluence 게시
```

---

## 사전 준비

### `.env` 필수 항목

```env
BITBUCKET_BASE_URL=https://code.skplanet.com
CUSTOMER_BB_TOKEN=BBDC-...          # Bitbucket personal access token
CONFLUENCE_BASE_URL=https://wiki.skplanet.com
CONFLUENCE_TOKEN=...                # Confluence API token (Bearer)
```

---

## ⚠️ 소스코드 Clone — Windows PowerShell 필수

> WSL에서 직접 clone하지 말 것.  
> `code.skplanet.com`은 WSL 네트워크에서 라우팅 불가 (`No route to host`).  
> **Clone은 반드시 Windows PowerShell에서 실행한다.**

```powershell
# Windows PowerShell에서 실행
cd C:\path\to\palantir

python tools/clone_repo.py <PROJECT_KEY> <REPO_SLUG>
# 예: python tools/clone_repo.py OCBWEBVIEW ocb-webview-api

# 브랜치 지정이 필요한 경우
python tools/clone_repo.py OCBWEBVIEW ocb-webview-api --branch develop
```

Clone 완료 후 → `testbed/<repo>/` 에 소스코드 저장  
이후 모든 작업은 **WSL** 에서 수행.

> **소스코드 보존 정책**: `testbed/<repo>/` 는 진단 완료 후에도 삭제하지 않는다.  
> 1차 보고서 검토 및 담당자 audit 시 소스코드 참조용으로 보존.

---

## Step 1: 진단 세션 초기화

진단 시작 전 5개 skill 상태 경로를 **한 번에** 생성하여 공통 RUN_ID를 확정한다.

```bash
cd ~/palantir

REPO=ocb-webview-api   # ← 레포 슬러그로 교체

# 5개 skill 상태 경로 동시 생성 (같은 분 내 실행 → 동일 RUN_ID)
for SKILL in injection xss file data sca; do
    python3 tools/new_scan.py $REPO --skill $SKILL
done
```

출력 예시:
```
state/ocb-webview-api/injection/20260506_1430/  created.
state/ocb-webview-api/xss/20260506_1430/        created.
state/ocb-webview-api/file/20260506_1430/       created.
state/ocb-webview-api/data/20260506_1430/       created.
state/ocb-webview-api/sca/20260506_1430/        created.
```

> **RUN_ID = `20260506_1430`** — 이후 모든 단계에서 이 값을 사용한다.

---

## Step 2: SAST 진단 — 5개 skill 순차 실행

Claude Code에서 아래 skill을 순서대로 실행한다.  
각 skill에 **소스코드 경로**와 **상태 경로**를 입력한다.

| skill 명령 | 소스코드 경로 | 상태 경로 |
|---|---|---|
| `/sec-scan-injection` | `testbed/ocb-webview-api` | `state/ocb-webview-api/injection/20260506_1430` |
| `/sec-scan-xss` | `testbed/ocb-webview-api` | `state/ocb-webview-api/xss/20260506_1430` |
| `/sec-scan-file` | `testbed/ocb-webview-api` | `state/ocb-webview-api/file/20260506_1430` |
| `/sec-scan-data` | `testbed/ocb-webview-api` | `state/ocb-webview-api/data/20260506_1430` |
| `/sec-scan-sca` | `testbed/ocb-webview-api` | `state/ocb-webview-api/sca/20260506_1430` |

### 각 skill 실행 결과 (정상 완료 시)

```
state/ocb-webview-api/<skill>/20260506_1430/
├── <auto-scan>.json          # Auto-Scan 원시 결과
├── <llm-check>.json          # LLM 교차검증 결과
├── findings_INJ.json         # ← /sec-review 판정 대상
├── findings_XSS.json
├── findings_FILE.json
├── findings_DATA.json
├── findings_SCA.json
└── summary_<skill>.md        # skill별 요약
```

**자율 완주 원칙**: 각 skill은 Auto-Scan → LLM-Check → findings_*.json → Summary까지  
확인 질문 없이 자동 완주한다. 스크립트 오류는 fallback 적용 후 계속 진행.

---

## Step 3: 1차 보고서 Draft 생성

현재까지의 모든 findings를 포함하는 draft 보고서. 진행 현황 확인용.

```bash
python3 tools/generate_report.py \
    --run-id 20260506_1430 \
    --type draft

# 특정 레포만 포함하려면:
python3 tools/generate_report.py \
    --run-id 20260506_1430 \
    --type draft \
    --repos ocb-webview-api
```

출력: `logs/report_draft_20260506_1430.md`

---

## Step 4: 정/오탐 인터랙티브 판정

Claude Code에서 `/sec-review` skill로 각 finding을 검토하고 정탐/오탐을 확정한다.

```
/sec-review 20260506_1430 ocb-webview-api
```

판정 방법:
- `1` / `y` → 정탐 (실제 취약점)
- `0` / `n` → 오탐 (false positive)
- `s` / Enter → 스킵 (나중에 판정)
- 자유 텍스트 → Claude가 `testbed/<repo>/` 실제 코드를 읽고 분석 후 재판정 요청

판정 결과는 finding 파일에 즉시 저장되므로 중단해도 진행 내용이 보존된다.

---

## Step 5: 최종 보고서 생성 + Confluence 게시

```bash
# 보고서 생성 + Confluence 자동 게시
python3 tools/approve_report.py \
    --run-id 20260506_1430 \
    --repo ocb-webview-api \
    --publish

# Confluence 게시 없이 보고서만 생성
python3 tools/approve_report.py \
    --run-id 20260506_1430 \
    --repo ocb-webview-api
```

자동으로 수행되는 작업:
1. 오탐 판정 finding의 `result` → `"양호"` 변경
2. `logs/report_final_20260506_1430.md` 생성
3. `~/palantir-reports/ocb-webview-api/20260506_1430/` 에 git 커밋
4. Confluence 페이지 자동 생성 (`--publish` 시)

**Confluence 게시 설정 (기본값)**:
- 부모 페이지: `https://wiki.skplanet.com/pages/viewpage.action?pageId=<YOUR_PARENT_PAGE_ID>`
- 페이지 제목: `ocb-webview-api-진단결과`

제목을 변경하려면:
```bash
python3 tools/approve_report.py \
    --run-id 20260506_1430 \
    --repo ocb-webview-api \
    --publish \
    --title "OCB Webview API 보안진단결과"
```

출력: `logs/final_ocb-webview-api_20260506_1430.md`

---

## 결과물 요약

| 파일 | 경로 | 설명 |
|---|---|---|
| Auto-Scan 결과 | `state/<repo>/<skill>/<RUN_ID>/*.json` | 스크립트 자동 판정 원시 결과 |
| findings | `state/<repo>/<skill>/<RUN_ID>/findings_*.json` | LLM-Check 완료, /sec-review 판정 대상 |
| skill 요약 | `state/<repo>/<skill>/<RUN_ID>/summary_*.md` | skill별 마크다운 요약 |
| 소스코드 | `testbed/<repo>/` | 진단 완료 후 보존 — 담당자 참조용 |
| 1차 보고서 (draft) | `logs/report_draft_<RUN_ID>.md` | 진행 중 현황 보고서 |
| 1차 보고서 (final) | `logs/report_final_<RUN_ID>.md` | 정/오탐 확정 항목 집계 |
| palantir-reports 커밋 | `~/palantir-reports/<repo>/<RUN_ID>/` | final 보고서 누적 저장소 |
| Confluence 게시본 | `logs/final_<repo>_<RUN_ID>.md` | 최종 보고서 (Confluence :::expand 포함) |

---

## 빠른 참조 — 전체 명령 순서

```bash
# [Windows PowerShell] Clone
python tools/clone_repo.py OCBWEBVIEW ocb-webview-api

# [WSL] Step 1: 세션 초기화
cd ~/palantir
for SKILL in injection xss file data sca; do
    python3 tools/new_scan.py ocb-webview-api --skill $SKILL
done
# → RUN_ID 확인 (예: 20260506_1430)

# [Claude Code] Step 2: skill 순차 실행
# /sec-scan-injection  → state/ocb-webview-api/injection/20260506_1430
# /sec-scan-xss        → state/ocb-webview-api/xss/20260506_1430
# /sec-scan-file       → state/ocb-webview-api/file/20260506_1430
# /sec-scan-data       → state/ocb-webview-api/data/20260506_1430
# /sec-scan-sca        → state/ocb-webview-api/sca/20260506_1430

# [WSL] Step 3: Draft 보고서
python3 tools/generate_report.py --run-id 20260506_1430 --type draft

# [Claude Code] Step 4: 정/오탐 판정
# /sec-review 20260506_1430 ocb-webview-api

# [WSL] Step 5: 최종 보고서 + Confluence 게시
python3 tools/approve_report.py \
    --run-id 20260506_1430 \
    --repo ocb-webview-api \
    --publish
```

---

## 재진단

같은 repo를 재진단하면 새 타임스탬프 디렉터리가 생성된다.

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

재진단 시 소스코드가 이미 `testbed/<repo>/` 에 있으면 clone 없이 Step 1부터 진행.

---

## 문제 해결

| 증상 | 원인 | 조치 |
|---|---|---|
| clone 401 | Bitbucket 토큰 만료 | `.env` CUSTOMER_BB_TOKEN 재발급 |
| clone 404 | 프로젝트/레포 슬러그 오타 | Bitbucket URL 확인 |
| `No route to host` | WSL에서 clone 시도 | Windows PowerShell에서 실행 |
| `findings 없음` 경고 | RUN_ID 불일치 | `ls state/<repo>/*/` 로 실제 타임스탬프 확인 |
| Confluence 401 | API 토큰 만료 | `.env` CONFLUENCE_TOKEN 재발급 |

---

## 관련 도구

| 도구 | 용도 |
|---|---|
| `tools/new_scan.py` | 진단 세션 초기화, state 경로 생성 |
| `tools/clone_repo.py` | Bitbucket 소스코드 clone |
| `tools/generate_report.py` | 1차 보고서 생성 (draft) |
| `tools/approve_report.py` | 정/오탐 반영 최종 보고서 생성 + Confluence 게시 |
| `tools/commit_report.py` | palantir-reports 수동 커밋 |
| `tools/pipeline_runner.py` | 전체 파이프라인 자동화 (다수 repo 배치 진단 시) |
