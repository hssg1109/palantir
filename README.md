# palantir

LLM 기반 SAST(정적 분석) 보안 진단 도구 모음.  
Claude Code를 진단 에이전트로 활용하여 소스코드에서 취약점을 탐지하고, 보고서를 자동 생성한다.

---

## 전체 워크플로

```
[1] Clone          [2] SAST 진단          [3] 리뷰          [4] 보고서
Bitbucket  ──▶  sec-scan-* skills  ──▶  /sec-review  ──▶  approve_report.py
  (repo)       (개별 or 통합 실행)     (정탐/오탐 판정)    (Confluence 게시)
```

---

## 1. Clone — 소스코드 다운로드

> **Windows PowerShell에서만 실행** (WSL 환경은 Bitbucket 네트워크 미지원)

```powershell
python3 tools/clone_repo.py <PROJECT_KEY> <REPO_SLUG>
# 결과: testbed/<repo>/ 에 소스코드 저장
```

---

## 2. SAST 진단 — sec-scan-* Skills

Claude Code 슬래시 커맨드로 실행한다. 각 skill은 **독립 실행** 또는 **파이프라인 통합 실행** 모두 지원.

### 개별 실행

```
/sec-scan-injection  <repo>    # SQL / OS Command / SSI Injection
/sec-scan-xss        <repo>    # XSS 4종
/sec-scan-file       <repo>    # 파일 처리 취약점
/sec-scan-data       <repo>    # 데이터 보호
/sec-scan-sca        <repo>    # 오픈소스 CVE
```

각 skill 내부 실행 순서:

```
자산 식별 (task_11)
  └▶ Auto-Scan  (Python 스크립트 — 패턴 매칭)
       └▶ LLM-Check  (Claude — 오탐 필터링, 코드 교차 검증)
            └▶ Summary  (findings_*.json 생성)
```

### 통합 실행 (야간 배치)

```bash
# trigger/scan_targets.yaml 에서 active: true 인 repo만 자동 처리
python3 tools/pipeline_runner.py

# 옵션
python3 tools/pipeline_runner.py --dry-run                   # 계획 확인 (실행 없음)
python3 tools/pipeline_runner.py --repos my-service-api      # 특정 repo만
python3 tools/pipeline_runner.py --skills injection sca      # 특정 skill만
python3 tools/pipeline_runner.py --no-clone                  # clone 건너뜀
```

---

## 3. Skills 상세

### `/sec-scan-injection` — Injection 취약점

| 항목 | 내용 |
|---|---|
| 진단 대상 | SQL Injection, OS Command Injection, SSI Injection |
| 지원 언어 | Java / Kotlin (Spring), PHP |
| 스크립트 | `shared/scripts/scan_injection_enhanced.py` |
| 탐지 방식 | Taint-flow 추적 (사용자 입력 → DB/OS 호출 경로) |

외부 입력(HTTP 파라미터, 헤더, 바디)이 쿼리 문자열이나 시스템 명령에 비검증 상태로 도달하는 경로를 탐지한다.

---

### `/sec-scan-xss` — Cross-Site Scripting

| 항목 | 내용 |
|---|---|
| 진단 대상 | Persistent XSS, Reflected XSS, DOM XSS, Open Redirect |
| 지원 언어 | Java / Kotlin (Spring), JavaScript / TypeScript (React, Vue) |
| 스크립트 | `shared/scripts/scan_xss.py` |
| 탐지 방식 | 출력 인코딩 누락 + DB 저장 경로 추적 |

사용자 입력이 HTML/JS 컨텍스트에 인코딩 없이 출력되거나 DB를 거쳐 재출력되는 경로를 탐지한다.

---

### `/sec-scan-file` — 파일 처리 취약점

| 항목 | 내용 |
|---|---|
| 진단 대상 | File Upload (확장자/MIME 미검증), File Download (경로 조작), LFI, RFI |
| 지원 언어 | Java / Kotlin (Spring), PHP |
| 스크립트 | `shared/scripts/scan_file_processing.py` |
| 탐지 방식 | 파일명/경로 파라미터 검증 여부, 저장 위치, 실행 가능 여부 |

업로드 파일의 확장자·MIME 검증 누락, 다운로드 경로에 `../` 조작 가능 지점, 원격 파일 포함 경로를 탐지한다.

---

### `/sec-scan-data` — 데이터 보호

| 항목 | 내용 |
|---|---|
| 진단 대상 | CORS 설정 오류, 하드코딩 Secrets, JWT 취약점, 암호화 취약점, PII 로깅 |
| 지원 언어 | Java / Kotlin, JavaScript / TypeScript |
| 스크립트 | `shared/scripts/scan_data_protection.py` |
| 탐지 방식 | 설정 파일 + 코드 패턴 분석, API 응답 PII 노출 추적 |

CORS 와일드카드, 소스코드 내 API 키·비밀번호 하드코딩, 약한 암호 알고리즘(MD5/SHA1), 로그에 개인정보 출력 등을 탐지한다.

---

### `/sec-scan-sca` — 오픈소스 CVE

| 항목 | 내용 |
|---|---|
| 진단 대상 | 오픈소스 라이브러리 알려진 취약점 (CVE) |
| 지원 빌드 | Gradle (`build.gradle`, `gradle/libs.versions.toml`), npm (`package.json`) |
| 스크립트 | `shared/scripts/scan_sca_gradle_tree.py` |
| 탐지 방식 | 의존성 트리 파싱 → CVE DB 조회 → LLM 관련성 검증 |

라이브러리 버전을 CVE DB와 대조하고, LLM이 소스코드와 교차 검증하여 실제 영향 여부(관련 API 호출 유무)를 판정한다.

---

## 4. 인터랙티브 리뷰 — `/sec-review`

5개 skill 완료 후 실행. finding별 정탐/오탐을 판정한다.

```
/sec-review <RUN_ID> <repo>
# 예: /sec-review 20260521_1030 my-service-api
```

| 입력 | 의미 |
|---|---|
| `1` 또는 `y` | 정탐 (실제 취약점) |
| `0` 또는 `n` | 오탐 (false positive) |
| `s` 또는 Enter | 스킵 (나중에 판정) |
| `q` | 종료 (진행 내용 저장) |
| 자유 텍스트 | 코드 분석 요청 → Claude가 소스코드 확인 후 답변 |

---

## 5. 최종 보고서 생성

```bash
# 보고서 생성만
python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo>

# 보고서 생성 + Confluence 게시
python3 tools/approve_report.py --run-id <RUN_ID> --repo <repo> --publish
# → logs/final_<repo>_<YYYYMMDD>.md
```

---

## 디렉토리 구조

```
palantir/
├── sec-scan-injection/     # Injection skill 정의 (SKILL.md + references/)
├── sec-scan-xss/           # XSS skill 정의
├── sec-scan-file/          # 파일 처리 skill 정의
├── sec-scan-data/          # 데이터 보호 skill 정의
├── sec-scan-sca/           # SCA skill 정의
├── shared/
│   ├── references/         # 공유 진단 기준, 스키마, 정책 문서
│   └── scripts/            # 공유 Python 스캐너 (패턴 매칭 엔진)
├── tools/                  # 보조 도구 (clone, approve_report, pipeline_runner 등)
├── trigger/
│   ├── scan_targets.yaml          # 운영용 (gitignore — 고객사 정보 포함)
│   └── scan_targets.example.yaml  # 공개 예시 템플릿
├── testbed/                # 고객사 소스코드 (gitignore)
├── state/                  # 진단 결과 JSON (gitignore)
└── logs/                   # 최종 보고서 Markdown (gitignore)
```

---

## 요구사항

```bash
pip install -r requirements.txt
```

- Python 3.10+
- [Claude Code CLI](https://claude.ai/code) (`claude` 명령어, Claude Pro 구독)
- Confluence API 토큰 → `.env` 파일에 `CONFLUENCE_TOKEN=Bearer <token>` 설정

---

## 관련 레포

| 레포 | 역할 |
|---|---|
| **palantir** (이 레포) | 진단 도구 및 skill |
| palantir-testbed (`testbed/`) | 고객사 소스코드 clone 저장소 |
| palantir-state (`state/`) | 진단 결과 JSON / 중간 산출물 |
