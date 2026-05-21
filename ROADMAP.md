# palantir — Roadmap & Todo

> 트리거 자동화 로드맵 (단기 A → 중장기 B+D)
> 대상 환경: code.skplanet.com (Bitbucket Server/Data Center, 사내망)

---

## 현황 (v0.3.0 기준)

| 항목 | 상태 |
|---|---|
| 5개 SAST skill (Auto-Scan Phase) | ✅ 완료 |
| LLM-Check Phase 프롬프트 5종 | ✅ 완료 |
| finding 정규화 (`auto_findings[]`) | ✅ 완료 |
| `findings_<skill>.json` 표준 스키마 | ✅ 완료 |
| severity 통일 (주요기반시설 고시 기준) | ✅ 완료 |
| Phase 명칭 통일 | ✅ 완료 |
| `/sec-review` 인터랙티브 판정 | ✅ 완료 |
| `approve_report.py` 최종 보고서 | ✅ 완료 |
| 트리거 자동화 | ⬜ 미착수 |

---

## Phase A — 단기: 수동 로컬 실행 (현재)

```
진단 요청 → code.skplanet.com에서 clone → palantir 5개 skill 실행 → findings_*.json
          → /sec-review 판정 → approve_report.py → 최종 보고서 + Confluence 게시
```

**Todo**
- [x] `testbed/` 폴더에 대상 repo clone 절차 문서화 (`docs/manual_scan_guide.md`)
- [x] Bitbucket access token 설정 가이드 (`.env` 항목 추가)
- [x] `tools/clone_repo.py` — CUSTOMER_BB_TOKEN 기반 Bitbucket Server clone
- [x] `/sec-review` 인터랙티브 오탐/정탐 판정 skill
- [x] `tools/approve_report.py` — 최종 보고서 생성 + Confluence 자동 게시

---

## Phase B — 중기: Bitbucket Webhook 자동 트리거

### 아키텍처

```
code.skplanet.com
  PR 생성 / Merge ──POST──▶ webhook_server.py (사내망 서버)
                                  │
                          ┌───────┴────────┐
                          │  변경 파일 분석  │
                          │  (Diff API)    │
                          └───────┬────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  palantir_runner.py         │
                    │  Claude API (Messages API)  │
                    │  skill 선택 → 진단 실행      │
                    └─────────────┬─────────────┘
                                  │
                          findings_*.json
                                  │
                          approve_report.py
                          (+ Confluence 게시)
```

### 트리거 이벤트 (Bitbucket Server Webhook)

| 이벤트 | Bitbucket Server 이벤트 키 | 동작 |
|---|---|---|
| PR 생성 | `pr:opened` | diff 기반 부분 스캔 → PR 코멘트로 결과 |
| PR Merge | `pr:merged` | diff 기반 부분 스캔 → findings 저장 → 보고서 자동 생성 |

### 변경 파일 기반 스캔 범위 결정

```python
SKILL_TRIGGERS = {
    "sec-scan-injection": [".java", ".kt", ".xml", ".properties", ".yml"],
    "sec-scan-xss":       [".java", ".kt", ".jsp", ".html", ".js", ".ts", ".vue"],
    "sec-scan-file":      [".java", ".kt"],
    "sec-scan-data":      [".java", ".kt", ".properties", ".yml", ".yaml"],
    "sec-scan-sca":       ["build.gradle", "build.gradle.kts", "package.json",
                           "package-lock.json", "yarn.lock"],
}
```

변경된 파일 확장자 → 실행할 skill 결정 → 해당 파일들만 스캔

### Claude 실행 방식: Anthropic Python SDK (Messages API)

- `anthropic.Anthropic().messages.create()` 직접 호출
- SKILL.md → system prompt
- 변경 파일 목록 + diff → user message
- `tool_use` 블록으로 Read/Grep/Bash 도구 호출
- 응답에서 `findings_*.json` 추출 → `approve_report.py` 보고서 생성

### 구현 파일 목록

```
palantir/
├── trigger/
│   ├── webhook_server.py        # Flask/FastAPI webhook receiver
│   ├── palantir_runner.py       # Claude API 기반 skill 실행기
│   ├── bitbucket_client.py      # Bitbucket Server REST API 클라이언트
│   │                            # (Diff, PR Comment, Clone)
│   └── skill_selector.py        # 변경 파일 → skill 매핑
├── docs/
│   ├── webhook_setup_guide.md   # Bitbucket Webhook 설정 방법
│   └── manual_scan_guide.md     # Phase A 수동 실행 가이드
└── .env                         # ANTHROPIC_API_KEY, BITBUCKET_TOKEN 등
```

### .env 추가 항목

```env
# Bitbucket Server
BITBUCKET_BASE_URL=https://code.skplanet.com
BITBUCKET_TOKEN=<personal_access_token>

# Claude API
ANTHROPIC_API_KEY=<api_key>
ANTHROPIC_MODEL=claude-sonnet-4-6

# webhook
WEBHOOK_SECRET=<hmac_secret>
WEBHOOK_PORT=8765
```

**Todo**
- [ ] `trigger/bitbucket_client.py` — PR Diff API, PR Comment API, clone
- [ ] `trigger/skill_selector.py` — 변경 파일 확장자 → skill 목록 매핑
- [ ] `trigger/palantir_runner.py` — Claude API Messages API 기반 skill 실행기
- [ ] `trigger/webhook_server.py` — FastAPI webhook receiver (HMAC 검증 포함)
- [ ] `docs/webhook_setup_guide.md` — Bitbucket Server webhook 설정 절차
- [ ] Bitbucket Server webhook payload 포맷 검증 (Server vs Cloud 차이)
- [ ] PR 코멘트 포맷 설계 (결과 요약 마크다운 → Bitbucket 코멘트)
- [ ] 동시 실행 제어 (같은 PR 중복 트리거 방지)

---

## Phase D — 장기: 야간 Cron 전체 스캔

### 아키텍처

```
cron (매일 02:00) ──▶ cron_runner.py
                           │
                    repo 목록 순회 (scan_targets.yaml)
                           │
                    full clone → 전체 5개 skill 실행
                           │
                    findings_*.json → approve_report.py
                    + 주간 보고서 생성 (summary_weekly.md)
```

### 구현 파일 목록

```
palantir/
├── trigger/
│   ├── cron_runner.py           # 야간 전체 스캔 실행기
│   └── scan_targets.yaml        # 진단 대상 repo 목록
└── docs/
    └── cron_setup_guide.md      # cron 스케줄 설정 방법
```

### scan_targets.yaml 구조

```yaml
targets:
  - project: PROJ_KEY
    repo: repo-name
    branch: main
    skills: [injection, xss, file, data, sca]
    modules: []          # 빈 배열 = 전체 모듈
  - project: PROJ_KEY2
    repo: another-repo
    branch: develop
    skills: [sca]
    modules: [api, core]
```

**Todo**
- [ ] `trigger/scan_targets.yaml` — 진단 대상 repo 목록 정의
- [ ] `trigger/cron_runner.py` — 야간 전체 스캔 실행기
- [ ] 주간 보고서 생성 로직 (skill별 통계 집계 → markdown)
- [ ] cron 스케줄 등록 (`crontab` 또는 systemd timer)
- [ ] 중복 실행 방지 (lock file 또는 PID 관리)
- [ ] 실행 이력 로그 (`logs/cron_YYYYMMDD.log`)

---

## 공통 인프라 Todo

- [ ] `requirements.txt` 업데이트 (`anthropic`, `fastapi`, `uvicorn`, `httpx`, `pyyaml`)
- [ ] Docker 컨테이너화 (webhook 서버 + cron 격리)
- [ ] 실행 로그 수집 구조 (파일 또는 syslog)
- [ ] 에러 알림 (Slack webhook 또는 이메일)
- [ ] API key 로테이션 가이드

---

## 마일스톤

| 단계 | 목표 | 시작 가능 조건 |
|---|---|---|
| A | 수동 스캔 + /sec-review 판정 + 보고서 생성 | ✅ 완료 |
| B-1 | webhook 수신 + 변경 파일 diff 추출 | Bitbucket token 확보 |
| B-2 | Claude API skill 실행 + PR 코멘트 | ANTHROPIC_API_KEY 확보 |
| B-3 | findings 자동 보고서 생성 | B-2 완료 후 |
| D | 야간 cron 전체 스캔 | B-3 완료 후 |
