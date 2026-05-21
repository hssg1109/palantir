# OCB SAST 야간 자동진단 + 주간 리뷰 워크플로 가이드

> **목적**: 평일 저녁 진단 대상 설정 → 야간 자동 실행 → 주간 리뷰·보고서 게시  
> **적용 전략**: B (야간 배치) + C (/sec-scan-* = 리뷰 전용) + D (scan_targets.yaml 주간 관리)

---

## 진단 대상 관리 아키텍처

두 파일이 역할을 분리한다:

| 파일 | 역할 | 누가 편집하나 |
|---|---|---|
| `docs/ocb_scan_plan.md` (= Confluence 746439687) | **마스터 현황표** — skill별 ✅/❌ 진실의 원천 | `approve_report.py --publish` 후 수동 업데이트 |
| `trigger/scan_targets.yaml` | **이번 주 배치 선정** — 실행할 repo만 active: true | 저녁 준비 단계에서 편집 |

**선정 흐름:**

```
ocb_scan_plan.md에서 ❌ 확인
        ↓
  이번 주 진단할 repo 선택
        ↓
scan_targets.yaml에서 해당 repo active: true
        ↓
testbed/ 에 clone 없으면 Step 1-A (Windows PowerShell)
        ↓
pipeline_runner.py --dry-run 확인 → 퇴근
```

> `scan_targets.yaml`은 **모든 미완료 repo를 `active: false`로 등록**해 두어, 주간 선정 시 간단히 `true`로 변경하면 즉시 실행할 수 있게 되어 있다.

---

## 전체 워크플로

```
[저녁 17:30 이전]          [야간 23:00 자동]           [주간 오전]
scan_targets.yaml       pipeline_runner.py          /sec-review
active: true  ──────►  5개 skill × N repo  ──────►  정탐/오탐 판정
clone 확인               state/ 결과 저장            approve_report.py
                         logs/ 로그 기록               Confluence 게시
```

---

## 역할 분담 원칙

| 도구 | 역할 | 사용 시점 |
|---|---|---|
| `pipeline_runner.py` | 대규모 진단 (5 skill × N repo) | 야간 cron 자동 실행 |
| `/sec-scan-*` 슬래시 커맨드 | 단일 finding 심층 분석 | 주간 리뷰 중 코드 재확인 필요 시 |
| `/sec-review` | finding별 정탐/오탐 판정 | 야간 배치 완료 후 주간에 |
| `scan_targets.yaml` | 이번 주 진단 대상 관리 | 저녁 준비 단계에서 편집 |

---

## Phase 0 — cron 등록 (최초 1회)

```bash
# 현재 등록된 cron 확인
crontab -l
```

정상 등록 상태:
```
# palantir 야간 SAST 자동 진단 — 매일 23:00 (trigger/scan_targets.yaml active:true 대상)
0 23 * * * /usr/bin/python3 /home/geunsolo/palantir/tools/pipeline_runner.py --no-clone >> /home/geunsolo/palantir/logs/cron_nightly.log 2>&1
```

미등록 시 등록 방법:
```bash
(crontab -l 2>/dev/null; echo "0 23 * * * /usr/bin/python3 /home/geunsolo/palantir/tools/pipeline_runner.py --no-clone >> /home/geunsolo/palantir/logs/cron_nightly.log 2>&1") | crontab -
```

> **주의**: `--no-clone` 플래그 필수 — clone은 WSL에서 불가, Windows PowerShell에서 별도 수행.

---

## Phase 1 — 저녁 준비 절차 (평일 17:30 이전)

### Step 1-A: 신규 repo clone (Windows PowerShell에서 실행)

```powershell
# palantir 디렉토리로 이동
cd ~\palantir

# testbed/<repo>/ 가 없는 repo만 clone (있으면 skip)
python3 tools/clone_repo.py <PROJECT_KEY> <repo>

# 예시: python3 tools/clone_repo.py OCBSUGAR ocb-iam
```

**현재 clone 필요 목록 (P1-A 프론트엔드, 나머지는 이미 testbed에 있음):**

```powershell
python3 tools/clone_repo.py OCBWEBVIEW ocb-fnc-webview-frontend
python3 tools/clone_repo.py OCBWEBVIEW ocbws-web-ui
python3 tools/clone_repo.py OCBWEBVIEW ocbws-frontend
python3 tools/clone_repo.py OCBWEBVIEW ocb-service-frontend
python3 tools/clone_repo.py OCBWEBVIEW ocb-ogeul-admin-frontend
python3 tools/clone_repo.py OCBWEBVIEW ocb-charge-publish
python3 tools/clone_repo.py OCBWEBVIEW ogog-admin-mcp-server
python3 tools/clone_repo.py OCBWEBVIEW ogog-admin-mcp
python3 tools/clone_repo.py OCBWEBVIEW ocb-admin-frontend
```

> **P1-B(OCBSUGAR 17개), P1-C(OCBRWD 2개), P1-D(LIVECM 18개)는 testbed에 이미 clone 완료** — 별도 clone 불필요.  
> `testbed/<repo>/` 디렉토리가 이미 있으면 skip.

### Step 1-B: scan_targets.yaml 편집 — 핵심 진단 지시

`trigger/scan_targets.yaml`이 **이번 야간 배치의 진단 명령서**다.  
`active: true`로 표시된 repo만 cron이 실행하므로, 오늘 밤 진단할 repo만 true로 켜면 된다.

```bash
code trigger/scan_targets.yaml   # WSL에서 VSCode로 편집
```

**미완료 repo는 이미 모두 `active: false`로 등록되어 있다** — 해당 repo를 찾아서 `true`로 바꾸기만 하면 된다.  
(마스터 현황표 `docs/ocb_scan_plan.md` → ❌인 repo 선택 → yaml에서 그 repo `active: true`)

**편집 예시 — 이번 주 진단 대상 2개 활성화**:

```yaml
# ── 전역 기본값 ──────────────────────────────────────────────────────────────
defaults:
  provider: claude-cli      # Claude Pro 구독 사용 (별도 API 키 불필요)
  max_budget_usd: 3.0       # skill당 예산 상한
  max_turns: 80             # skill당 최대 LLM 턴

# ── 진단 대상 목록 ───────────────────────────────────────────────────────────
targets:

  - repo: ocb-community-api
    project: OCBWEBVIEW
    active: true            # ← 오늘 밤 진단 대상

  - repo: ocb-fnc-webview-api
    project: OCBWEBVIEW
    active: true            # ← 오늘 밤 진단 대상

  - repo: ocb-sugar
    project: OCBSUGAR
    active: false           # 이번 주 제외 → 다음 주로 미룸
```

**선택 필드 (필요 시만 추가)**:

| 필드 | 기본값 | 사용 예 |
|---|---|---|
| `skills` | 전체 5종 | `skills: [injection, sca]` — 특정 skill만 재실행 |
| `repo_type` | 소스코드로 자동 감지 | `repo_type: frontend` — xss+sca만 실행 |
| `modules` | 없음 | `modules: [api, batch]` — 대형 멀티모듈 repo 분리 |
| `max_budget_usd` | defaults 값 | 대형 repo에만 높게 설정 |

> **규칙**: 야간 배치 완료 후 해당 repo를 반드시 `active: false`로 복원할 것.  
> 방치하면 다음 날 밤에도 재실행됨.

### Step 1-C: 실행 계획 사전 확인

```bash
cd ~/palantir
python3 tools/pipeline_runner.py --dry-run
```

출력 예시:
```
[DRY-RUN] 진단 계획
  provider  : claude-cli
  대상 repo : 2개
  실행 skill: injection, xss, file, data, sca (각 repo별)
  예상 소요 : ~3~4시간

  ocb-community-api   → testbed 확인: ✓
  ocb-fnc-webview-api → testbed 확인: ✓
```

testbed 누락 repo가 있으면 Step 1-A로 돌아가 clone 수행.

### Step 1-D: 퇴근 전 최종 확인

```bash
# cron 활성화 확인
crontab -l | grep pipeline_runner

# 디스크 여유 확인 (testbed + state 합계)
df -h /home/geunsolo
```

---

## Phase 2 — 야간 자동 실행 (cron, 매일 23:00)

아래는 cron이 자동으로 수행하는 내용 (개입 불필요):

```
23:00  pipeline_runner.py 시작
  └─ active:true repo만 선택
  └─ repo 1 (예: ocb-community-api)
      ├─ sec-scan-injection  → state/ocb-community-api/injection/<RUN_ID>/
      ├─ sec-scan-xss        → state/ocb-community-api/xss/<RUN_ID>/
      ├─ sec-scan-file       → state/ocb-community-api/file/<RUN_ID>/
      ├─ sec-scan-data       → state/ocb-community-api/data/<RUN_ID>/
      └─ sec-scan-sca        → state/ocb-community-api/sca/<RUN_ID>/
  └─ repo 2 ...
완료 → logs/pipeline_<RUN_ID>_summary.json 생성
```

**생성 파일 위치**:

| 파일 | 내용 |
|---|---|
| `logs/cron_nightly.log` | 배치 전체 진행 로그 |
| `logs/pipeline_<RUN_ID>.log` | pipeline_runner 상세 로그 |
| `logs/pipeline_<RUN_ID>_summary.json` | 결과 요약 (성공/실패/repo별 RUN_ID) |
| `state/<repo>/<skill>/<RUN_ID>/findings_*.json` | 각 skill별 취약점 목록 |

---

## Phase 3 — 아침 결과 확인 (출근 후 09:00)

### 빠른 상태 확인

```bash
# 최신 요약 JSON 확인
ls -t ~/palantir/logs/pipeline_*_summary.json | head -1 | xargs python3 -m json.tool

# 또는 로그 마지막 50줄
tail -50 ~/palantir/logs/cron_nightly.log
```

요약 JSON 예시:
```json
{
  "run_id": "20260520_2300",
  "repos": {
    "ocb-community-api": {
      "status": "completed",
      "skills": {"injection": "ok", "xss": "ok", "file": "ok", "data": "ok", "sca": "ok"}
    },
    "ocb-fnc-webview-api": {
      "status": "completed",
      "skills": {"injection": "ok", "xss": "ok", "file": "ok", "data": "ok", "sca": "ok"}
    }
  }
}
```

### 실패 repo 대응

```bash
# 특정 skill만 재실행 (LLM-Check 단계부터)
python3 tools/pipeline_runner.py --repos ocb-community-api --skills injection --no-clone
```

---

## Phase 4 — 주간 리뷰 절차

### Step 4-A: /sec-review 실행

```
/sec-review <RUN_ID> <repo>
```

예시:
```
/sec-review 20260520_2300 ocb-community-api
```

**판정 입력 방법**:

| 입력 | 의미 |
|---|---|
| `1` 또는 `y` | 정탐 (실제 취약점) — 보고서에 포함 |
| `0` 또는 `n` | 오탐 (false positive) — 보고서에서 제외 |
| `s` 또는 Enter | 스킵 (나중에 재판정) |
| 자유 텍스트 | 코드 분석 요청 → LLM이 답변 후 재판정 유도 |
| `q` | 종료 (진행상황 자동 저장) |

**검토자 의견 (review_note) Confluence 반영 규칙**:

정탐/오탐 판정 후 "메모 (Enter 스킵):" 프롬프트에 입력한 내용은 `review_note` 필드로 finding JSON에 저장된다.  
이 값은 `approve_report.py --publish` 실행 시 Confluence 페이지에 **반드시 별도 블록으로 반영**된다:

| review_note 상황 | Confluence 표시 방식 |
|---|---|
| 한 줄 메모 (예: "4개 프로파일 전체 동일 시크릿") | `> **검토자 의견**: ...` 인라인 블록 |
| 여러 줄 또는 `## ` 헤더 포함 | `:::expand 검토자 의견` 펼침 블록 |

> **주의**: 의견을 입력하지 않고 Enter만 누르면 `review_note`가 빈 문자열로 저장되어 Confluence에 표시되지 않는다.  
> 이 블록은 자동 생성된 "상세 검증 결과" expand와 **별개로** 추가 출력된다 — 겹치지 않음.

> 리뷰 중 특정 finding 코드 재확인 필요 시 `/sec-scan-injection` 등 슬래시 커맨드로 별도 심층 분석.

### Step 4-B: 최종 보고서 생성 + Confluence 게시

```bash
# 보고서 생성 및 Confluence 동시 게시
python3 tools/approve_report.py \
  --run-id 20260520_2300 \
  --repo ocb-community-api \
  --publish
```

출력:
```
[보고서] logs/final_ocb-community-api_20260520_2300.md 생성
[Confluence] 페이지 ID 752826752 업데이트 완료
[palantir-reports] 자동 커밋
```

### Step 4-C: scan_targets.yaml 정리 + scan_plan.md 업데이트

```bash
# 완료된 repo active: false 복원 (필수 — 안 하면 다음 날 밤 재실행됨)
code trigger/scan_targets.yaml

# docs/ocb_scan_plan.md 수동 업데이트 후 Confluence 게시
python3 tools/publish_confluence.py docs/ocb_scan_plan.md
```

체크리스트 컬럼: `❌` → `✅ YYYY-MM-DD`

---

## 월간 진행 관리

### 현재 미완료 현황 (2026-05-19 기준)

| 그룹 | 대상 repo 수 | testbed 상태 | 비고 |
|---|---|---|---|
| P1-A (OCBWEBVIEW) SCA-only | 8개 | ❌ clone 필요 | 프론트엔드 — skills: [sca] |
| P1-A ocb-admin-frontend | 1개 | ❌ clone 필요 | INJ+XSS+SCA 미완료 |
| P1-B (OCBSUGAR) | 17개 | ✅ testbed 있음 | 전체 skill 미완료 |
| P1-C (OCBRWD) | 2개 | ✅ testbed 있음 | 전체 skill 미완료 |
| P1-D (LIVECM) | 18개 | ✅ testbed 있음 | 전체 skill 미완료 |

### 권장 배치 계획

| 주차 | 대상 repo | 준비 필요 사항 |
|---|---|---|
| 5/19~23 | P1-B OCBSUGAR 그룹 (4~5개/회) | 없음 (testbed 준비 완료) |
| 5/26~30 | P1-B OCBSUGAR 나머지 + P1-C OCBRWD | 없음 (testbed 준비 완료) |
| 6/2~6   | P1-D LIVECM 그룹 (4~5개/회) | 없음 (testbed 준비 완료) |
| 6/9~    | P1-A SCA-only 프론트엔드 | Windows PS에서 clone 9개 |

> **이번 주 (5/19~23) 시작 추천**: P1-B OCBSUGAR — testbed 준비 완료, 즉시 배치 가능  
> 예시: `ocb-iam`, `ocb-epm`, `ocb-wp-api`, `ocb-wp-frontend` active: true → 오늘 밤 실행

---

## 트러블슈팅

### claude-cli 인증 만료

```bash
claude auth login
```

### 특정 skill 실패 재시도

```bash
# 해당 repo·skill만 재실행 (완료된 skill은 자동 skip)
python3 tools/pipeline_runner.py \
  --repos <repo> \
  --skills <skill> \
  --no-clone
```

### 디스크 부족 (testbed 정리)

```bash
# 리뷰 완료된 repo testbed 삭제
python3 tools/cleanup_testbed.py <repo> --force
```

### 배치 중단 후 재개

```bash
# state/ 파일 존재 여부로 완료 판단 — 이미 완료된 skill은 자동 skip
python3 tools/pipeline_runner.py --no-clone
```

---

## 빠른 참조 — 일간 체크리스트

**저녁 (퇴근 전)**
- [ ] Windows PowerShell에서 신규 repo clone 완료 (`tools/clone_repo.py`)
- [ ] `trigger/scan_targets.yaml` — 오늘 밤 대상 `active: true`, 나머지 `false`
- [ ] `python3 tools/pipeline_runner.py --dry-run` 실행 확인 (testbed 체크)

**아침 (출근 후)**
- [ ] `tail -50 logs/cron_nightly.log` 로 배치 결과 확인
- [ ] 실패 repo 있으면 `--repos <repo> --skills <skill> --no-clone` 재실행

**주간 (리뷰)**
- [ ] `/sec-review <RUN_ID> <repo>` 실행 (finding별 판정 + 검토자 의견 입력)
- [ ] `python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish`
- [ ] `trigger/scan_targets.yaml` 완료 repo `active: false` 복원 ← **반드시**
- [ ] `docs/ocb_scan_plan.md` 체크리스트 업데이트 → Confluence 게시
