#!/usr/bin/env python3
"""
run_skill.py — Claude 세션 없이 sec-scan skill 실행 (멀티 provider 지원)

동작 흐름:
  1. Auto-Scan   : Python 스캐너를 직접 실행 (LLM 불필요, 무료)
  2. LLM-Check   : LLM API로 교차검증 + findings/summary 출력
  3. Cleanup     : testbed 소스코드 삭제

사전 준비:
  pip install openai   # 모든 provider 공통 (OpenAI 호환 SDK)

  # provider별 API 키 환경변수
  export OPENAI_API_KEY=sk-...          # openai (기본)
  export GEMINI_API_KEY=AIza...         # gemini  (무료 1,500 req/day)
  export GROQ_API_KEY=gsk_...           # groq    (무료 14,400 req/day)
  export DEEPSEEK_API_KEY=sk-...        # deepseek (유료, 매우 저렴)
  # ollama: 키 불필요 (로컬 서버)

사용법:
  python3 tools/run_skill.py <skill> <src> <prefix> [옵션]

스킬:
  injection   SQL / OS Command / SSI Injection
  xss         XSS 4종 (Persistent / Reflected / DOM / Redirect)
  file        파일 처리 취약점 (Upload / Download / LFI / RFI)
  data        데이터 보호 (CORS / Secrets / JWT / Crypto / PII)
  sca         오픈소스 CVE (Gradle / npm)

예시:
  python3 tools/run_skill.py injection testbed/gws state/injection/gws/20260415_0915
  python3 tools/run_skill.py xss testbed/okick state/xss/okick/20260415_0915 --provider gemini
  python3 tools/run_skill.py injection testbed/gws state/injection/gws/20260415_0915 --provider groq
  python3 tools/run_skill.py xss testbed/okick state/xss/okick/20260415_0915 --provider ollama --model qwen2.5-coder:72b
  python3 tools/run_skill.py sca testbed/myapp state/sca/myapp/20260415_1200 --skip-upload

옵션:
  --provider PROVIDER   LLM provider (기본: openai)
                        선택: openai | gemini | groq | deepseek | ollama
  --model MODEL         모델명 (생략 시 provider 기본 모델 사용)
  --api-key KEY         API 키 (생략 시 환경변수 자동 탐지)
  --skip-scan           Auto-Scan 건너뜀 (이미 실행된 경우)
  --skip-llm            LLM-Check 건너뜀 (Auto-Scan만 실행)
  --skip-upload         (레거시) Cleanup 건너뜀
  --max-turns N         LLM 최대 턴 수 (기본: 60)
"""

import argparse
import glob as glob_module
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# ─── 기준 경로 ────────────────────────────────────────────────────────────────

PALANTIR_DIR = Path(__file__).resolve().parent.parent

# ─── .env 로드 ────────────────────────────────────────────────────────────────

def _load_env() -> None:
    """palantir/.env 파일을 읽어 os.environ에 주입 (이미 설정된 변수는 덮어쓰지 않음)."""
    env_path = PALANTIR_DIR / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if key and key not in os.environ:   # 환경변수 우선, .env는 fallback
            os.environ[key] = val

_load_env()

# ─── Provider 설정 ────────────────────────────────────────────────────────────
# 모든 provider가 OpenAI 호환 엔드포인트를 제공하므로 openai SDK 하나로 통일.
# base_url=None 이면 공식 OpenAI 엔드포인트 사용.

PROVIDERS: dict[str, dict] = {
    "claude-cli": {
        "base_url":    None,
        "default_model": "sonnet",   # claude-sonnet-4-6 alias
        "env_key":     None,         # Claude Pro OAuth — API 키 불필요
        "notes":       "Claude Pro 구독 토큰 사용 (claude CLI, WSL 세션)",
        "native":      "claude-cli",
    },
    "anthropic": {
        "base_url":    None,   # 네이티브 SDK 사용 (OpenAI 호환 아님)
        "default_model": "claude-sonnet-4-6",
        "env_key":     "ANTHROPIC_API_KEY",
        "notes":       "Claude Sonnet 4.6 — 권장. 프롬프트 캐싱 자동 적용",
        "native":      True,   # 네이티브 Anthropic SDK 플래그
    },
    "openai": {
        "base_url":    None,
        "default_model": "gpt-4o-mini",
        "env_key":     "OPENAI_API_KEY",
        "notes":       "GPT-4o-mini: $0.15/MTok — 유료",
    },
    "gemini": {
        "base_url":    "https://generativelanguage.googleapis.com/v1beta/openai/",
        "default_model": "gemini-2.0-flash",
        "env_key":     "GEMINI_API_KEY",
        "notes":       "1M context, 무료 1,500 req/day (Google AI Studio)",
    },
    "groq": {
        "base_url":    "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "env_key":     "GROQ_API_KEY",
        "notes":       "무료 14,400 req/day, 128K context, 초고속",
    },
    "deepseek": {
        "base_url":    "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "env_key":     "DEEPSEEK_API_KEY",
        "notes":       "DeepSeek-V3: $0.14/MTok — 코드 분석 최강, 준무료",
    },
    "ollama": {
        "base_url":    "http://localhost:11434/v1",
        "default_model": "qwen2.5-coder:32b",
        "env_key":     None,
        "notes":       "로컬 실행, 완전 무료 무제한. GPU 필요",
    },
    "openrouter": {
        "base_url":      "https://openrouter.ai/api/v1",
        "default_model": "qwen/qwen-2.5-coder-32b-instruct",
        "env_key":       "OPENROUTER_API_KEY",
        "notes":         "Qwen Coder 32B. 압도적 가성비 및 코딩 성능",
    },
}

# ─── 스킬별 설정 ──────────────────────────────────────────────────────────────

SKILL_CONFIG = {
    "injection": {
        "module": "sec-scan-injection",
        # primary_ref: LLM-Check 핵심 절차서 — system prompt에 반드시 포함됨
        "primary_ref": "sec-scan-injection/references/task_prompts/task_22_injection_review.md",
        # refs: LLM이 read_file로 on-demand 참조 가능한 보조 문서 목록
        "refs": [
            "sec-scan-injection/references/injection_diagnosis_criteria.md",
            "shared/references/output_schemas.md",
            "shared/references/severity_criteria.md",
            "shared/references/cross_verification.md",
            "shared/references/finding_writing_guide.md",
            "shared/references/taint_tracking.md",
            "shared/references/global_filters.md",
        ],
        "auto_scan": [
            # [스크립트, 인자...] — {src}, {prefix}, {repo} 플레이스홀더 사용
            ["python3", "shared/scripts/scan_api.py",
             "{src}", "-o", "{prefix}/api_scan.json"],
            ["python3", "shared/scripts/scan_injection_enhanced.py",
             "{src}", "--api-inventory", "{prefix}/api_scan.json",
             "-o", "{prefix}/injection.json"],
        ],
        "main_output": "injection.json",
        # llm_prompt는 _make_llm_prompt()가 런타임에 llm_input 존재 여부를 확인해 대체하므로
        # 여기서는 fallback(원본 전체 읽기) 형태로만 유지.
        "llm_prompt": (
            "Auto-Scan이 완료되었습니다. 소스코드: {src}  결과경로: {prefix}/\n"
            "메인 스캔 결과: {prefix}/injection.json\n\n"
            "시스템 프롬프트의 [LLM-Check 절차서 — task_22_injection_review.md] 를 기준으로\n"
            "반드시 아래 4단계를 순서대로 완료하세요.\n\n"
            "{step1}"
            "Step 2. LLM-Check Phase 1: '취약' 판정 건 → Controller→Service→Repository 흐름 교차검증, FP 재분류\n"
            "        LLM-Check Phase 2: needs_review=true / 정보 건 → 코드 직접 확인 후 취약 여부 판정\n"
            "        ※ 소스 확인 필요 시 read_file 또는 grep으로 해당 파일만 핀포인트 조회\n"
            "Step 3. write_file '{prefix}/findings_INJ.json' (최종 finding 목록)\n"
            "        write_file '{prefix}/summary_injection.md' (통계 + 테이블)\n"
            "Step 3. run_cleanup(prefix='{prefix}', repo='{repo}')\n"
            "prefix={prefix}, repo={repo}"
        ),
    },
    "xss": {
        "module": "sec-scan-xss",
        "primary_ref": "sec-scan-xss/references/task_prompts/task_23_xss_review.md",
        "refs": [
            "shared/references/output_schemas.md",
            "shared/references/severity_criteria.md",
            "shared/references/cross_verification.md",
            "shared/references/finding_writing_guide.md",
            "shared/references/taint_tracking.md",
            "shared/references/global_filters.md",
        ],
        "auto_scan": [
            ["python3", "shared/scripts/scan_api.py",
             "{src}", "-o", "{prefix}/api_scan.json"],
            ["python3", "shared/scripts/scan_xss.py",
             "{src}", "--api-inventory", "{prefix}/api_scan.json",
             "-o", "{prefix}/xss.json"],
        ],
        "main_output": "xss.json",
        "llm_prompt": (
            "Auto-Scan이 완료되었습니다. 소스코드: {src}  결과경로: {prefix}/\n"
            "메인 스캔 결과: {prefix}/xss.json\n\n"
            "시스템 프롬프트의 [LLM-Check 절차서 — task_23_xss_review.md] 를 기준으로\n"
            "반드시 아래 4단계를 순서대로 완료하세요.\n\n"
            "{step1}"
            "Step 2. LLM-Check Phase 1: '취약' 판정 건 → Controller→View 렌더링 흐름 교차검증\n"
            "        LLM-Check Phase 2: '정보/수동검토' 건 → taint 추적 후 취약 여부 판정\n"
            "        ※ 소스 확인 필요 시 read_file 또는 grep으로 해당 파일만 핀포인트 조회\n"
            "Step 3. write_file '{prefix}/findings_XSS.json'\n"
            "        write_file '{prefix}/summary_xss.md'\n"
            "Step 3. run_cleanup(prefix='{prefix}', repo='{repo}')\n"
            "prefix={prefix}, repo={repo}"
        ),
    },
    "file": {
        "module": "sec-scan-file",
        "primary_ref": "sec-scan-file/references/task_prompts/task_24_file_handling.md",
        "refs": [
            "shared/references/output_schemas.md",
            "shared/references/severity_criteria.md",
            "shared/references/cross_verification.md",
            "shared/references/finding_writing_guide.md",
            "shared/references/taint_tracking.md",
        ],
        "auto_scan": [
            ["python3", "shared/scripts/scan_file_processing.py",
             "{src}", "-o", "{prefix}/file.json"],
        ],
        "main_output": "file.json",
        "llm_prompt": (
            "Auto-Scan이 완료되었습니다. 소스코드: {src}  결과경로: {prefix}/\n"
            "메인 스캔 결과: {prefix}/file.json\n\n"
            "시스템 프롬프트의 [LLM-Check 절차서 — task_24_file_handling.md] 를 기준으로\n"
            "반드시 아래 4단계를 순서대로 완료하세요.\n\n"
            "{step1}"
            "Step 2. LLM-Check Phase 1: '취약' 판정 건 → 업로드 경로/확장자 검증 로직 교차검증\n"
            "        LLM-Check Phase 2: needs_review 건 → IDOR/우회기법/LFI 심층 확인\n"
            "        ※ 소스 확인 필요 시 read_file 또는 grep으로 해당 파일만 핀포인트 조회\n"
            "Step 3. write_file '{prefix}/findings_FILE.json'\n"
            "        write_file '{prefix}/summary_file.md'\n"
            "Step 3. run_cleanup(prefix='{prefix}', repo='{repo}')\n"
            "prefix={prefix}, repo={repo}"
        ),
    },
    "data": {
        "module": "sec-scan-data",
        "primary_ref": "sec-scan-data/references/task_prompts/task_25_data_protection.md",
        "refs": [
            "shared/references/output_schemas.md",
            "shared/references/severity_criteria.md",
            "shared/references/cross_verification.md",
            "shared/references/finding_writing_guide.md",
            "shared/references/secret_scanning.md",
        ],
        "auto_scan": [
            ["python3", "shared/scripts/scan_data_protection.py",
             "{src}", "-o", "{prefix}/data.json"],
        ],
        "main_output": "data.json",
        "llm_prompt": (
            "Auto-Scan이 완료되었습니다. 소스코드: {src}  결과경로: {prefix}/\n"
            "메인 스캔 결과: {prefix}/data.json\n\n"
            "시스템 프롬프트의 [LLM-Check 절차서 — task_25_data_protection.md] 를 기준으로\n"
            "반드시 아래 4단계를 순서대로 완료하세요.\n\n"
            "{step1}"
            "Step 2. LLM-Check Phase 1: '취약' 판정 건 교차검증\n"
            "           CORS: allowedOrigins 동적 반영 여부 / Secrets: 실제 비밀값 vs 플레이스홀더\n"
            "           JWT: alg 검증 / Crypto: 알고리즘 강도 / PII: 로그 레벨별 민감도\n"
            "        LLM-Check Phase 2: '정보/수동검토' 건 심층 확인\n"
            "        ※ 소스 확인 필요 시 read_file 또는 grep으로 해당 파일만 핀포인트 조회\n"
            "Step 3. write_file '{prefix}/findings_DATA.json'\n"
            "        write_file '{prefix}/summary_data.md'\n"
            "Step 3. run_cleanup(prefix='{prefix}', repo='{repo}')\n"
            "prefix={prefix}, repo={repo}"
        ),
    },
    "sca": {
        "module": "sec-scan-sca",
        "primary_ref": "sec-scan-sca/references/task_prompts/task_sca_llm_review.md",
        "refs": [
            "shared/references/output_schemas.md",
            "shared/references/severity_criteria.md",
        ],
        "auto_scan": [
            ["python3", "shared/scripts/scan_sca_gradle_tree.py",
             "{src}", "--project", "{repo}",
             "--output", "{prefix}/sca.json"],
        ],
        "main_output": "sca.json",
        "llm_prompt": (
            "Auto-Scan이 완료되었습니다. 소스코드: {src}  결과경로: {prefix}/\n"
            "메인 스캔 결과: {prefix}/sca.json\n\n"
            "시스템 프롬프트의 [LLM-Check 절차서 — task_sca_llm_review.md] 를 기준으로\n"
            "반드시 아래 4단계를 순서대로 완료하세요.\n\n"
            "{step1}"
            "Step 2. HIGH/CRITICAL CVE 전수 검토:\n"
            "           [1] 소스코드 실사용 여부 (grep으로 artifact명 검색)\n"
            "           [2] 취약 조건 부합 여부 (CVE 트리거 조건 코드 확인)\n"
            "           [3] 관련성 판정: 적용/제한적/조건미충족/확인불가\n"
            "           [4] 한국어 취약점 설명 (이 프로젝트 영향 범위 포함)\n"
            "Step 3. write_file '{prefix}/findings_SCA.json'\n"
            "        write_file '{prefix}/summary_sca.md'\n"
            "Step 3. run_cleanup(prefix='{prefix}', repo='{repo}')\n"
            "prefix={prefix}, repo={repo}"
        ),
    },
}

# ─── OpenAI 도구 스키마 ───────────────────────────────────────────────────────

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "파일 내용을 읽습니다. palantir 루트 기준 상대경로 또는 절대경로를 사용하세요.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "읽을 파일 경로"},
                    "offset": {"type": "integer", "description": "시작 라인 번호 (1-based, 생략 시 처음부터)"},
                    "limit":  {"type": "integer", "description": "최대 읽을 라인 수 (생략 시 전체)"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "state/ 하위 결과 디렉터리에 파일을 저장합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path":    {"type": "string", "description": "저장할 파일 경로 (state/ 하위여야 함)"},
                    "content": {"type": "string", "description": "저장할 내용"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep",
            "description": "소스코드에서 패턴을 검색합니다 (ripgrep 사용).",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "검색 패턴 (regex)"},
                    "path":    {"type": "string", "description": "검색할 디렉터리 또는 파일"},
                    "flags":   {"type": "string", "description": "rg 옵션 (예: -i -n -l -A 3 -B 1)"},
                },
                "required": ["pattern", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "glob",
            "description": "파일 패턴으로 파일 목록을 조회합니다.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "glob 패턴 (예: testbed/gws/**/*.java)"},
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_cleanup",
            "description": (
                "testbed 소스코드를 삭제합니다. "
                "Summary 출력 완료 후 마지막 단계로 호출하세요."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "prefix": {"type": "string", "description": "결과 경로 (예: state/gws/20260415_0915)"},
                    "repo":   {"type": "string", "description": "repo 슬러그 (예: gws)"},
                },
                "required": ["prefix", "repo"],
            },
        },
    },
]

# ─── 도구 실행 ────────────────────────────────────────────────────────────────

def _resolve(path_str: str) -> Path:
    """팔란티르 루트 기준으로 경로를 절대화."""
    p = Path(path_str)
    return p if p.is_absolute() else PALANTIR_DIR / p


def execute_tool(name: str, inputs: dict, *,
                 batch: bool = False, skip_cleanup: bool = False) -> str:
    # 배치 모드: 도구 출력 크기를 줄여 컨텍스트 누적 속도 억제
    READ_LIMIT = 12_000 if batch else 32_000
    GREP_LIMIT =  6_000 if batch else 16_000

    try:
        if name == "read_file":
            p = _resolve(inputs["path"])
            if not p.exists():
                return f"[ERROR] 파일 없음: {inputs['path']}"
            lines = p.read_text(errors="replace").splitlines(keepends=True)
            offset = max(0, (inputs.get("offset") or 1) - 1)
            limit  = inputs.get("limit")
            lines  = lines[offset : offset + limit] if limit else lines[offset:]
            content = "".join(lines)[:READ_LIMIT]
            if batch and len("".join(lines)) > READ_LIMIT:
                content += f"\n...[배치 모드: {READ_LIMIT}자 이후 생략. offset 파라미터로 이어 읽기 가능]"
            return content

        elif name == "write_file":
            p = _resolve(inputs["path"])
            # 안전 검사: state/ 하위에만 허용
            try:
                p.resolve().relative_to((PALANTIR_DIR / "state").resolve())
            except ValueError:
                return f"[ERROR] write_file은 state/ 하위에만 허용됩니다: {inputs['path']}"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(inputs["content"], encoding="utf-8")
            return f"저장 완료: {inputs['path']} ({len(inputs['content'])} bytes)"

        elif name == "grep":
            pattern = inputs["pattern"]
            path    = str(_resolve(inputs["path"]))
            flags   = inputs.get("flags") or "-n"
            cmd     = f"rg {flags} {json.dumps(pattern)} {json.dumps(path)}"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            out = (r.stdout + r.stderr).strip()
            if not out:
                return "(검색 결과 없음)"
            if len(out) > GREP_LIMIT:
                out = out[:GREP_LIMIT] + f"\n...[배치 모드: {GREP_LIMIT}자 이후 생략. -l 플래그로 파일 목록만 조회 가능]"
            return out

        elif name == "glob":
            pattern  = inputs["pattern"]
            full_pat = str(PALANTIR_DIR / pattern) if not Path(pattern).is_absolute() else pattern
            matches  = sorted(glob_module.glob(full_pat, recursive=True))[:300]
            rel = [str(Path(m).relative_to(PALANTIR_DIR)) for m in matches]
            return "\n".join(rel) if rel else "(없음)"

        elif name == "run_cleanup":
            prefix = inputs["prefix"]
            repo   = inputs["repo"]

            if skip_cleanup:
                return "skip_cleanup 옵션으로 testbed 보존."

            print(f"\n  [정리] cleanup_testbed.py {repo} --force")
            r2 = subprocess.run(
                ["python3", "tools/cleanup_testbed.py", repo, "--force"],
                capture_output=True, text=True, cwd=str(PALANTIR_DIR),
            )
            cleanup_out = (r2.stdout + r2.stderr).strip()
            print(f"  {cleanup_out[:500]}")
            return f"testbed 정리 완료.\n{cleanup_out[:200]}"

        return f"[ERROR] 알 수 없는 도구: {name}"

    except Exception as exc:
        return f"[ERROR] {name} 실행 중 예외: {exc}"


# ─── 레포 유형 탐지 ──────────────────────────────────────────────────────────

def detect_repo_type(src: str) -> str:
    """
    빠른 파일 존재 여부로 레포 유형 판별.
    반환값: "backend" | "frontend" | "php" | "unknown"
    """
    src_path = PALANTIR_DIR / src
    # Java/Kotlin 파일 존재 → backend (glob 방식으로 안정적 탐지)
    for ext in ("*.java", "*.kt"):
        matches = list(src_path.rglob(ext))
        if matches:
            return "backend"
    # PHP 파일 존재
    if list(src_path.rglob("*.php")):
        return "php"
    # package.json 존재 → frontend
    if (src_path / "package.json").exists():
        return "frontend"
    return "unknown"


# ─── Auto-Scan (Python 스크립트 직접 실행) ───────────────────────────────────

def run_auto_scan(skill: str, src: str, prefix: str) -> bool:
    config = SKILL_CONFIG[skill]
    repo   = Path(src).name

    _sep()
    print(f"[Phase 1] Auto-Scan — {skill.upper()}")
    _sep()

    # 레포 유형 감지 — frontend/PHP는 백엔드 스캐너 skip
    repo_type = detect_repo_type(src)
    print(f"\n  [repo_type] {repo_type}")
    if repo_type == "frontend" and skill in ("injection", "xss", "file", "data"):
        print(f"  [SKIP] 프론트엔드 레포 — {skill} 백엔드 Auto-Scan 해당없음")
        print(f"  → LLM-Check Phase에서 FE 전용 진단 절차 적용 예정")
        # 빈 결과 파일 생성 (LLM-Check 게이트 통과용)
        out_path = PALANTIR_DIR / prefix / config["main_output"]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            '{"task_id":"' + skill + '","status":"skipped",'
            '"reason":"frontend_repo","findings":[],"endpoint_diagnoses":[],'
            '"global_findings":{},"summary":{"total":0}}',
            encoding="utf-8",
        )
        return True
    if repo_type == "php":
        print(f"  [SKIP] PHP 레포 — 자동 스캔 미지원 (unsupported_lang_targets.md 참조)")
        out_path = PALANTIR_DIR / prefix / config["main_output"]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            '{"task_id":"' + skill + '","status":"skipped",'
            '"reason":"php_unsupported","findings":[],"endpoint_diagnoses":[],'
            '"global_findings":{},"summary":{"total":0}}',
            encoding="utf-8",
        )
        return True

    for i, cmd_tmpl in enumerate(config["auto_scan"]):
        cmd = [
            part.format(src=src, prefix=prefix, repo=repo)
            for part in cmd_tmpl
        ]
        script = Path(cmd[1]).name
        print(f"\n  [{i+1}/{len(config['auto_scan'])}] {script}")
        print(f"  $ {' '.join(cmd)}\n")

        r = subprocess.run(cmd, capture_output=True, text=True, cwd=str(PALANTIR_DIR))
        if r.stdout.strip():
            # 긴 출력은 앞/뒤 300자만 표시
            out = r.stdout.strip()
            if len(out) > 600:
                print(f"  {out[:300]}\n  ...(생략)...\n  {out[-300:]}")
            else:
                print(f"  {out}")
        if r.returncode != 0:
            print(f"  [WARN] returncode={r.returncode}: {r.stderr.strip()[:300]}")
            # fallback: 계속 진행

    out_path = PALANTIR_DIR / prefix / config["main_output"]
    if out_path.exists():
        size = out_path.stat().st_size
        print(f"\n  ✓ {prefix}/{config['main_output']} ({size:,} bytes)")
        _generate_llm_input(prefix, skill)   # P0: LLM용 경량 입력 파일 생성
        return True
    else:
        print(f"\n  [WARN] 메인 출력 파일 없음: {out_path}")
        return False


# ─── P0: LLM-Check용 경량 입력 파일 생성 ────────────────────────────────────
# 양호/해당없음 항목을 제거해 컨텍스트 크기를 줄임.
# 원본 main_output은 유지 — 이 파일은 LLM 입력 전용.

def _generate_llm_input(prefix: str, skill: str) -> None:
    """LLM-Check용 경량 입력 파일 생성 (양호/해당없음 제거, data는 카테고리 샘플링)."""
    from collections import defaultdict

    config   = SKILL_CONFIG[skill]
    src_path = PALANTIR_DIR / prefix / config["main_output"]
    if not src_path.exists():
        return
    try:
        data = json.loads(src_path.read_text(encoding="utf-8"))
    except Exception:
        return

    filtered      = dict(data)
    skipped_total = 0

    if skill == "injection":
        SAFE = {"양호", "해당없음(DB접근없음)", "해당없음"}
        eps   = data.get("endpoint_diagnoses", [])
        kept  = [e for e in eps if e.get("result") not in SAFE]
        skipped_total = len(eps) - len(kept)
        # db_operations 압축: is_vulnerable=False 항목 → 1줄 문자열로 대체
        for ep in kept:
            ops = ep.get("db_operations")
            if ops:
                ep["db_operations"] = [
                    f"{o.get('method','?')}:{o.get('access_type','?')}"
                    if not o.get("is_vulnerable", False)
                    else o
                    for o in ops
                ]
        filtered["endpoint_diagnoses"] = kept

    elif skill == "xss":
        SAFE = {"양호"}
        eps   = data.get("endpoint_diagnoses", [])
        kept  = [e for e in eps if e.get("result") not in SAFE]
        skipped_total = len(eps) - len(kept)
        filtered["endpoint_diagnoses"] = kept

    elif skill == "file":
        SAFE = {"safe", "Safe", "양호"}
        for key in ("upload_diagnoses", "download_diagnoses", "rfi_diagnoses"):
            arr  = data.get(key, [])
            kept = [e for e in arr if e.get("result") not in SAFE]
            skipped_total += len(arr) - len(kept)
            filtered[key] = kept

    elif skill == "data":
        # 스캐너가 이미 취약/정보만 출력하므로 결과 필터 불필요.
        # 동일 카테고리 내 반복 패턴을 샘플링해 크기 절감.
        MAX_SAMPLES = 5
        findings = data.get("findings", [])
        by_cat: dict[str, list] = defaultdict(list)
        for f in findings:
            by_cat[f.get("category", "OTHER")].append(f)
        result_findings: list = []
        for cat, items in sorted(by_cat.items()):
            if len(items) <= MAX_SAMPLES:
                result_findings.extend(items)
            else:
                samples = [dict(e) for e in items[:MAX_SAMPLES]]
                samples[0]["_group_meta"] = {
                    "total_count": len(items),
                    "showing":     MAX_SAMPLES,
                    "note": (
                        f"{cat} {len(items)}건 중 {MAX_SAMPLES}건 샘플. "
                        f"나머지 {len(items) - MAX_SAMPLES}건은 동일 패턴"
                    ),
                }
                result_findings.extend(samples)
                skipped_total += len(items) - MAX_SAMPLES
        filtered["findings"] = result_findings

    elif skill == "sca":
        KEEP = {"CRITICAL", "HIGH"}
        findings = data.get("findings", [])
        kept     = [f for f in findings if f.get("severity", "").upper() in KEEP]
        medium   = sum(1 for f in findings if f.get("severity", "").upper() == "MEDIUM")
        low_info = sum(1 for f in findings if f.get("severity", "").upper() in ("LOW", "INFO", "INFORMATIONAL"))
        filtered["findings"] = kept
        skipped_total = medium + low_info
        if skipped_total:
            filtered["_skipped_by_severity"] = {"MEDIUM": medium, "LOW+Info": low_info}

    filtered["_llm_input_meta"] = {
        "generated_by":    "run_skill.py _generate_llm_input",
        "skipped_count":   skipped_total,
        "source":          config["main_output"],
        "note": (
            f"LLM-Check 경량 입력. 양호/해당없음/중복 {skipped_total}건 제외. "
            f"전체 결과는 {config['main_output']} 참조"
        ),
    }

    out_name = f"{skill}_llm_input.json"
    out_path = PALANTIR_DIR / prefix / out_name
    out_path.write_text(json.dumps(filtered, ensure_ascii=False, indent=2), encoding="utf-8")

    orig_kb = src_path.stat().st_size / 1024
    new_kb  = out_path.stat().st_size / 1024
    pct     = (1 - new_kb / orig_kb) * 100 if orig_kb > 0 else 0
    print(f"  ✓ {out_name} ({new_kb:.0f}KB, -{pct:.0f}% vs {orig_kb:.0f}KB 원본)")


# ─── claude-cli 전용 task prompt 생성 ────────────────────────────────────────
# claude -p는 native 도구명(Read/Write/Grep/Glob)을 사용하므로 별도 프롬프트 필요

_SKILL_TAG = {"injection": "INJ", "xss": "XSS", "file": "FILE", "data": "DATA", "sca": "SCA"}
_SKILL_SUMMARY_KEY = {"injection": "injection", "xss": "xss", "file": "file", "data": "data", "sca": "sca"}

_STEP2_DETAIL = {
    "injection": (
        "LLM-Check Phase 1: '취약' 판정 건 → Controller→Service→Repository 흐름 교차검증, FP 재분류\n"
        "        LLM-Check Phase 2: needs_review=true / 정보 건 → 코드 직접 확인 후 취약 여부 판정\n"
        "        ※ 소스 확인 필요 시 Read 또는 Grep으로 해당 파일만 핀포인트 조회"
    ),
    "xss": (
        "LLM-Check Phase 1: '취약' 판정 건 → Controller→View 렌더링 흐름 교차검증\n"
        "        LLM-Check Phase 2: '정보/수동검토' 건 → taint 추적 후 취약 여부 판정\n"
        "        ※ 소스 확인 필요 시 Read 또는 Grep으로 해당 파일만 핀포인트 조회"
    ),
    "file": (
        "LLM-Check Phase 1: '취약' 판정 건 → 업로드 경로/확장자 검증 로직 교차검증\n"
        "        LLM-Check Phase 2: needs_review 건 → IDOR/우회기법/LFI 심층 확인\n"
        "        ※ 소스 확인 필요 시 Read 또는 Grep으로 해당 파일만 핀포인트 조회"
    ),
    "data": (
        "LLM-Check Phase 1: '취약' 판정 건 교차검증\n"
        "           CORS: allowedOrigins 동적 반영 여부 / Secrets: 실제 비밀값 vs 플레이스홀더\n"
        "           JWT: alg 검증 / Crypto: 알고리즘 강도 / PII: 로그 레벨별 민감도\n"
        "        LLM-Check Phase 2: '정보/수동검토' 건 심층 확인\n"
        "        ※ 소스 확인 필요 시 Read 또는 Grep으로 해당 파일만 핀포인트 조회"
    ),
    "sca": (
        "HIGH/CRITICAL CVE 전수 검토:\n"
        "           [1] 소스코드 실사용 여부 (Grep으로 artifact명 검색)\n"
        "           [2] 취약 조건 부합 여부 (CVE 트리거 조건 코드 확인)\n"
        "           [3] 관련성 판정: 적용/제한적/조건미충족/확인불가\n"
        "           [4] 한국어 취약점 설명 (이 프로젝트 영향 범위 포함)"
    ),
}


def build_claude_cli_task_prompt(skill: str, src: str, prefix: str) -> str:
    """claude -p용 task prompt — native Claude Code 도구명(Read/Write/Grep/Glob) 사용."""
    repo = Path(src).name
    config = SKILL_CONFIG[skill]
    tag = _SKILL_TAG[skill]
    main_output   = f"{prefix}/{config['main_output']}"
    llm_input     = f"{prefix}/{skill}_llm_input.json"
    summary_file  = f"{prefix}/{skill}_llm_summary.json"
    findings_out  = f"{prefix}/findings_{tag}.json"
    summary_out   = f"{prefix}/summary_{_SKILL_SUMMARY_KEY[skill]}.md"

    # P1: summary-first — 요약본이 있으면 먼저 읽어 전체 규모 파악 후 llm_input 접근
    llm_input_exists  = (PALANTIR_DIR / llm_input).exists()
    summary_exists    = (PALANTIR_DIR / summary_file).exists()

    if llm_input_exists:
        if summary_exists:
            step1 = (
                f"Step 1-a. Read('{summary_file}') — 통계 요약 확인 (규모/분포 파악)\n"
                f"Step 1-b. Read('{llm_input}') — LLM 검토 대상 항목 (양호/해당없음 제외된 경량 파일)\n"
                f"          [주의] '{main_output}' 전체 읽기 금지 — llm_input 파일만 사용\n"
            )
        else:
            step1 = (
                f"Step 1. Read('{llm_input}') — LLM 검토 대상 항목 (양호/해당없음 제외된 경량 파일)\n"
                f"        [주의] '{main_output}' 전체 읽기 금지 — llm_input 파일만 사용\n"
            )
    else:
        # llm_input 생성 실패 시 원본으로 fallback
        step1 = f"Step 1. Read('{main_output}') — 전체 읽기\n"

    return (
        f"Auto-Scan이 완료되었습니다. 소스코드: {src}  결과경로: {prefix}/\n"
        f"메인 스캔 결과: {main_output}\n\n"
        f"시스템 프롬프트의 [LLM-Check 절차서]를 기준으로 반드시 아래 단계를 순서대로 완료하세요.\n\n"
        f"{step1}"
        f"Step 2. {_STEP2_DETAIL[skill]}\n"
        f"Step 3. Write '{findings_out}' (최종 finding 목록 JSON)\n"
        f"        Write '{summary_out}' (통계 + 테이블 Markdown)\n"
        f"        ※ Upload/Cleanup은 부모 프로세스가 처리하므로 Write 완료 후 바로 종료하세요.\n"
        f"\nprefix={prefix}, repo={repo}"
    )


# ── Pre-fetching: llm_input.json에 코드 스니펫 주입 ─────────────────────────

def _extract_method_snippet(source_dir: Path, rel_file: str, method_name: str,
                             context_lines: int = 28) -> str | None:
    """소스 파일에서 method_name 메서드 본문 스니펫 추출 (최대 context_lines 줄)."""
    abs_path = source_dir / rel_file
    if not abs_path.exists():
        return None
    try:
        lines = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None

    method_line = -1
    # 접근제어자 / Kotlin fun 패턴 우선 매칭
    for i, line in enumerate(lines):
        if (method_name + "(") in line:
            s = line.strip()
            if any(kw in s for kw in ("public ", "private ", "protected ", "fun ", "override ")):
                method_line = i
                break
    # fallback: 단순 메서드명
    if method_line < 0:
        for i, line in enumerate(lines):
            if (method_name + "(") in line:
                method_line = i
                break

    if method_line < 0:
        return None

    start = max(0, method_line - 3)   # annotation 줄 포함
    end   = min(len(lines), method_line + context_lines)
    return "\n".join(f"{start+j+1:4d}│ {l}" for j, l in enumerate(lines[start:end]))


def _enrich_llm_input_with_snippets(prefix: str, src: str) -> None:
    """
    Phase 1 완료 후 *_llm_input.json 의 endpoint_diagnoses 각 항목에 컨트롤러 코드
    스니펫을 주입한다.  LLM이 Read 툴을 호출하지 않아도 코드를 즉시 판정할 수 있어
    턴(Turn) 수·캐시 누적을 대폭 줄인다.
    """
    prefix_dir = PALANTIR_DIR / prefix
    llm_input_files = sorted(prefix_dir.glob("*_llm_input.json"))
    if not llm_input_files:
        return

    for llm_input_path in llm_input_files:
        try:
            data = json.loads(llm_input_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        # source_dir: 절대/상대 모두 처리
        raw_src = data.get("scan_metadata", {}).get("source_dir", "")
        source_dir = Path(raw_src)
        if not source_dir.is_absolute():
            source_dir = PALANTIR_DIR / raw_src
        if not source_dir.exists():
            source_dir = PALANTIR_DIR / src

        endpoint_diagnoses = data.get("endpoint_diagnoses", [])
        if not endpoint_diagnoses:
            continue

        enriched = 0
        for entry in endpoint_diagnoses:
            if "code_snippets" in entry:
                continue  # 이미 처리됨

            process_file = entry.get("process_file", "")
            handler      = entry.get("handler", "")
            method_name  = (entry.get("method_name")
                            or (handler.split(".")[-1].rstrip("()") if "." in handler else handler.rstrip("()")))

            if not process_file or not method_name:
                continue

            snippets: dict[str, str] = {}

            # 1) Controller 스니펫
            ctrl = _extract_method_snippet(source_dir, process_file, method_name)
            if ctrl:
                snippets["controller"] = ctrl

            # 2) Service 스니펫 (injection: service_calls 필드)
            for svc_call in entry.get("service_calls", [])[:2]:
                svc_class  = svc_call.split(".")[0]
                svc_method = svc_call.split(".")[-1].rstrip("()") if "." in svc_call else ""
                if not svc_method:
                    continue
                matches = (list(source_dir.rglob(f"{svc_class}.java")) +
                           list(source_dir.rglob(f"{svc_class}.kt")))
                if matches:
                    snip = _extract_method_snippet(
                        source_dir,
                        str(matches[0].relative_to(source_dir)),
                        svc_method,
                    )
                    if snip:
                        snippets[f"service_{svc_class}"] = snip

            if snippets:
                entry["code_snippets"] = snippets
                enriched += 1

        already = sum(1 for e in endpoint_diagnoses if "code_snippets" in e)
        if enriched > 0:
            llm_input_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print(f"  [Pre-fetch] {llm_input_path.name}: {enriched}/{len(endpoint_diagnoses)}건 스니펫 주입")
        elif already > 0:
            print(f"  [Pre-fetch] {llm_input_path.name}: {already}건 이미 주입됨 — 스킵")
        elif not endpoint_diagnoses:
            print(f"  [Pre-fetch] {llm_input_path.name}: 진단 대상 없음")
        else:
            print(f"  [Pre-fetch] {llm_input_path.name}: 스니펫 추출 실패 (testbed 경로 확인 필요)")


def _make_llm_prompt(skill: str, src: str, prefix: str) -> str:
    """non-claude-cli 경로(anthropic/openai/gemini 등)용 user 메시지 생성.

    SKILL_CONFIG[skill]["llm_prompt"] 템플릿의 {step1} 플레이스홀더를
    런타임에 llm_input.json / llm_summary.json 존재 여부를 확인해 채운다.
    P0(경량 파일 유도) + P1(summary-first) 적용.
    """
    config = SKILL_CONFIG[skill]
    repo   = Path(src).name

    main_output  = f"{prefix}/{config['main_output']}"
    llm_input    = f"{prefix}/{skill}_llm_input.json"
    summary_file = f"{prefix}/{skill}_llm_summary.json"

    llm_input_exists = (PALANTIR_DIR / llm_input).exists()
    summary_exists   = (PALANTIR_DIR / summary_file).exists()

    if llm_input_exists:
        if summary_exists:
            step1 = (
                f"Step 1-a. read_file('{summary_file}') — 통계 요약 확인 (규모/분포 파악)\n"
                f"Step 1-b. read_file('{llm_input}') — LLM 검토 대상 항목 (양호/해당없음 제외된 경량 파일)\n"
                f"          [주의] '{main_output}' 전체 읽기 금지 — llm_input 파일만 사용\n"
            )
        else:
            step1 = (
                f"Step 1. read_file('{llm_input}') — LLM 검토 대상 항목 (양호/해당없음 제외된 경량 파일)\n"
                f"        [주의] '{main_output}' 전체 읽기 금지 — llm_input 파일만 사용\n"
            )
    else:
        step1 = f"Step 1. read_file('{main_output}') — 전체 읽기\n"

    return config["llm_prompt"].format(src=src, prefix=prefix, repo=repo, step1=step1)


def _build_claude_cli_system_prompt(skill: str, batch: bool = False) -> str:
    """claude -p용 system prompt — native 도구명 사용, run_cleanup 미포함."""
    config = SKILL_CONFIG[skill]
    module = config["module"]

    skill_md_path = PALANTIR_DIR / module / "SKILL.md"
    skill_md = skill_md_path.read_text(encoding="utf-8") if skill_md_path.exists() else ""

    primary_ref_content = ""
    primary_ref_path = config.get("primary_ref", "")
    if primary_ref_path:
        p = PALANTIR_DIR / primary_ref_path
        if p.exists():
            primary_ref_content = (
                f"\n=== LLM-Check 절차서 — {p.name} ===\n"
                + p.read_text(encoding="utf-8")
            )

    refs_hint = ""
    if config.get("refs"):
        refs_hint = "\n[보조 참조 문서 — 필요 시 Read로 조회]\n" + "\n".join(
            f"  - {r}" for r in config["refs"]
        )

    batch_section = ""
    if batch:
        batch_section = """
[BATCH MODE — 토큰 절약 가드레일 (CRITICAL, 반드시 준수)]
1. 스크립트 오류 금지 대응: 오류 발생 시 원본 Python 코드를 절대 열어보거나 수정하지 말 것.
   즉시 실패 사유 한 줄을 Write로 기록하고 종료.
2. 소스 직접 탐색 최소화:
   - [허용] 진단 참조 문서(.md 파일, ref 목록 내 경로): Read로 자유롭게 읽을 것.
   - [제한] testbed/ 하위 소스파일(.java/.kt/.py 등): JSON의 code_snippet/evidence로
     판정 불가한 경우에만 Read. 동일 소스파일 2회 이상 Read 금지.
     Grep은 핀포인트 패턴 확인 용도로만 사용 (탐색적 Grep 루프 금지).
3. 재시도 금지: 동일 도구 호출이 실패하면 즉시 다음 단계로 진행. 재시도는 1회만 허용.
   판정 불확실한 경우 '정보'로 처리하고 계속 진행.
"""

    return f"""당신은 소프트웨어 보안 진단 전문가입니다.
아래 SKILL 정의와 절차서를 기반으로 진단을 자율 완주하세요.
{batch_section}
HARD RULES:
- "계속할까요?", "do you want to proceed?" 등 확인 질문 절대 금지
- Auto-Scan은 이미 완료된 상태 — 스캔 스크립트를 다시 실행하지 마세요
- findings JSON 작성 완료 후 즉시 종료하세요 (Upload/Cleanup은 부모 프로세스가 처리)
- Write는 state/ 하위 경로에만 사용하세요
{refs_hint}

=== SKILL 정의 ({module}/SKILL.md) ===
{skill_md}
{primary_ref_content}"""


# ─── LLM-Check (claude -p CLI) ────────────────────────────────────────────────

def run_llm_check_claude_cli(skill: str, src: str, prefix: str,
                              model: str | None, max_turns: int,
                              skip_upload: bool, batch: bool, skip_cleanup: bool,
                              max_budget_usd: float = 3.0) -> None:
    """
    claude -p CLI를 LLM 엔진으로 사용.
    Claude Pro 구독 토큰 사용 (API 키 불필요).
    allowedTools=Read,Write,Grep,Glob → Bash/Edit 차단으로 스크립트 자기수정 루프 구조적 방지.
    max_budget_usd: 1회 실행당 토큰 비용 상한 (기본 $3.0 — skill 진단 이상 소비 방지).
    Upload/Cleanup은 claude -p 종료 후 parent Python이 직접 처리.
    """
    repo = Path(src).name

    _sep()
    print(f"[Phase 2] LLM-Check — provider: claude-cli  model: {model or 'sonnet'}")
    print(f"  허용 도구: Read, Write, Grep, Glob  (Bash/Edit 차단 — 자기수정 루프 방지)")
    print(f"  토큰 예산: ${max_budget_usd:.2f} / skill (초과 시 자동 중단)")
    _sep()

    system_prompt = _build_claude_cli_system_prompt(skill, batch=batch)
    task_prompt   = build_claude_cli_task_prompt(skill, src, prefix)

    cmd = [
        "claude", "-p", task_prompt,
        "--allowedTools", "Read,Write,Grep,Glob",
        "--system-prompt", system_prompt,
        "--output-format", "json",
        "--dangerously-skip-permissions",
        "--max-budget-usd", str(max_budget_usd),
        "--add-dir", str(PALANTIR_DIR / src),
        "--add-dir", str(PALANTIR_DIR / "state"),
        "--add-dir", str(PALANTIR_DIR / "shared" / "references"),
        "--add-dir", str(PALANTIR_DIR / SKILL_CONFIG[skill]["module"] / "references"),
    ]
    if model:
        cmd += ["--model", model]

    print(f"\n  [claude CLI] 실행 중... (최대 1시간 대기, 예산 ${max_budget_usd:.2f})")
    print(f"  $ claude -p \"<task_prompt>\" --allowedTools Read,Write,Grep,Glob --max-budget-usd {max_budget_usd} ...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(PALANTIR_DIR),
            timeout=3600,
        )
    except subprocess.TimeoutExpired:
        print(f"\n  [ERROR] claude -p 타임아웃 (1시간 초과)")
        return
    except FileNotFoundError:
        print(f"\n  [ERROR] claude CLI 없음. PATH에 'claude'가 있어야 합니다.")
        return

    # JSON 응답 파싱 (--output-format json)
    cost_info = ""
    try:
        output = json.loads(result.stdout)
        final_text = output.get("result", "")
        cost_usd   = output.get("total_cost_usd")
        if cost_usd is not None:
            cost_info = f"  비용: ${cost_usd:.4f} USD"
        if final_text:
            print(f"\n{final_text[:600]}" + ("..." if len(final_text) > 600 else ""))
    except (json.JSONDecodeError, ValueError):
        final_text = result.stdout
        if final_text:
            print(f"\n{final_text[:600]}")

    if result.returncode != 0:
        combined = result.stdout + result.stderr
        if "you've hit your limit" in combined.lower():
            import re as _re
            from datetime import datetime as _dt
            m = _re.search(r'resets\s+[\d:apm]+\s*\([^)]+\)', combined, _re.IGNORECASE)
            reset_info = m.group(0) if m else ""
            print(f"\n  [RATE LIMIT] Claude Pro 사용 한도 초과 — {reset_info}")
            marker = {
                "reason": "rate_limit_exceeded",
                "reset_info": reset_info,
                "failed_at": _dt.now().isoformat(),
                "skill": skill,
            }
            (PALANTIR_DIR / prefix / "llm_check_failed.json").write_text(
                json.dumps(marker, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print(f"  → 마커 저장: llm_check_failed.json")
        else:
            stderr_preview = result.stderr.strip()[:400]
            print(f"\n  [WARN] claude CLI exit={result.returncode}")
            if stderr_preview:
                print(f"  stderr: {stderr_preview}")

    print(f"\n  ✓ claude -p 완료.{cost_info}")

    # findings 파일 확인
    tag = _SKILL_TAG[skill]
    findings_path = PALANTIR_DIR / prefix / f"findings_{tag}.json"
    if not findings_path.exists():
        print(f"\n  [WARN] findings 파일 없음: {findings_path}")
        print("  LLM이 Write 도구를 사용하지 않았을 수 있습니다.")
        return
    print(f"  ✓ {findings_path.name} ({findings_path.stat().st_size:,} bytes)")

    # Cleanup (parent가 직접 처리 — LLM 없이)
    if not skip_cleanup:
        print(f"\n  [정리] cleanup_testbed.py {repo} --force")
        r2 = subprocess.run(
            ["python3", "tools/cleanup_testbed.py", repo, "--force"],
            capture_output=True, text=True, cwd=str(PALANTIR_DIR),
        )
        print(f"  {(r2.stdout + r2.stderr).strip()[:300]}")


# ─── Anthropic 도구 스키마 변환 ───────────────────────────────────────────────

def _to_anthropic_tools(openai_schemas: list[dict]) -> list[dict]:
    """OpenAI tool schema → Anthropic tool schema 변환."""
    result = []
    for t in openai_schemas:
        fn = t["function"]
        result.append({
            "name":        fn["name"],
            "description": fn["description"],
            "input_schema": fn["parameters"],   # parameters → input_schema
        })
    return result


# ─── LLM-Check (Anthropic 네이티브 SDK) ──────────────────────────────────────

def run_llm_check_anthropic(skill: str, src: str, prefix: str,
                             model: str, api_key: str,
                             max_turns: int, skip_upload: bool,
                             batch: bool, skip_cleanup: bool) -> None:
    try:
        import anthropic as anthropic_sdk
    except ImportError:
        print("\n[ERROR] anthropic 패키지 없음. pip install anthropic --break-system-packages")
        sys.exit(1)

    config = SKILL_CONFIG[skill]
    repo   = Path(src).name

    _sep()
    print(f"[Phase 2] LLM-Check — provider: anthropic  model: {model}")
    _sep()

    client = anthropic_sdk.Anthropic(api_key=api_key)

    system_prompt = build_system_prompt(skill, batch=batch)
    MAX_CTX_CHARS = 400_000 if batch else 900_000

    # 프롬프트 캐싱: system prompt를 ephemeral 캐시로 — 반복 전송 비용 대폭 절감
    system_with_cache = [
        {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}
    ]

    anthropic_tools = _to_anthropic_tools(
        TOOL_SCHEMAS if not skip_upload
        else [t for t in TOOL_SCHEMAS if t["function"]["name"] != "run_cleanup"]
    )

    user_msg = _make_llm_prompt(skill, src, prefix)
    if skip_upload:
        user_msg += "\n\n(이번 실행에서는 Cleanup은 건너뜁니다.)"

    messages: list[dict] = [{"role": "user", "content": user_msg}]

    turn = 0
    while turn < max_turns:
        turn += 1
        print(f"\n[LLM turn {turn}/{max_turns}]", end=" ", flush=True)

        try:
            response = client.messages.create(
                model=model,
                max_tokens=8192,
                system=system_with_cache,
                messages=messages,
                tools=anthropic_tools,
            )
        except anthropic_sdk.RateLimitError as e:
            print(f"\n  [WARN] Rate Limit. 60초 대기 후 재시도...")
            time.sleep(60)
            continue
        except anthropic_sdk.APIStatusError as e:
            print(f"\n  [ERROR] API 오류 ({e.status_code}): {e.message}")
            sys.exit(1)
        except Exception as e:
            print(f"\n  [ERROR] 예외: {e}")
            sys.exit(1)

        stop_reason = response.stop_reason

        # 텍스트 출력 수집
        text_parts = [b.text for b in response.content if b.type == "text"]
        if text_parts:
            preview = " ".join(text_parts)[:500]
            print(f"\n{preview}" + ("..." if sum(len(t) for t in text_parts) > 500 else ""))

        # 컨텍스트 크기 추정 (입력 토큰 기준)
        ctx_chars = response.usage.input_tokens * 4  # 토큰 → 문자 근사
        if ctx_chars > MAX_CTX_CHARS:
            print(f"\n  [WARN] 컨텍스트 {ctx_chars:,}자(≈{response.usage.input_tokens:,}tok) > 한도 — 조기 종료")
            break

        if stop_reason == "end_turn":
            print(f"\n\n  ✓ LLM-Check 완료  (입력 {response.usage.input_tokens:,}tok / 출력 {response.usage.output_tokens:,}tok)")
            break

        if stop_reason == "tool_use":
            tool_blocks = [b for b in response.content if b.type == "tool_use"]

            # assistant 메시지에 전체 content 추가
            messages.append({"role": "assistant", "content": response.content})

            # 도구 실행 후 결과를 단일 user 메시지(tool_result 블록들)로 묶기
            tool_results = []
            for tb in tool_blocks:
                arg_preview = ", ".join(f"{k}={str(v)[:60]}" for k, v in dict(tb.input).items())
                print(f"  [Tool] {tb.name}({arg_preview})")
                result = execute_tool(tb.name, dict(tb.input), batch=batch, skip_cleanup=skip_cleanup)
                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": tb.id,
                    "content":     str(result)[:32_000],
                })

            messages.append({"role": "user", "content": tool_results})
        else:
            print(f"\n  [WARN] 예상치 못한 stop_reason: {stop_reason}")
            break

    if turn >= max_turns:
        print(f"\n  [WARN] 최대 턴({max_turns}) 도달 — LLM-Check 중단")


# 배치 모드 가드레일 — 토큰 폭증 방지 3원칙
_BATCH_GUARDRAILS = """
[BATCH MODE — 토큰 절약 가드레일 (CRITICAL, 반드시 준수)]
1. 스크립트 오류 금지 대응: 스크립트(scan_* 등) 실행 오류가 발생하면
   원본 Python 코드를 절대 열어보거나 수정하지 말 것.
   즉시 실패 사유 한 줄을 write_file로 기록하고 run_cleanup을 호출하여 종료.
2. 소스 직접 탐색 최소화:
   - [허용] 진단 참조 문서(.md 파일, ref 목록 내 경로): read_file로 자유롭게 읽을 것.
   - [제한] testbed/ 하위 소스파일(.java/.kt/.py 등): JSON의 code_snippet/evidence로
     판정 불가한 경우에만 read_file. 동일 소스파일 2회 이상 read_file 금지.
     grep은 핀포인트 패턴 확인 용도로만 사용 (탐색적 grep 루프 금지).
3. 재시도 금지: 동일 도구 호출이 실패하면 즉시 다음 단계로 진행. 재시도는 1회만 허용.
   판정 불확실한 경우 '정보'로 처리하고 계속 진행.
"""


# ─── 시스템 프롬프트 빌드 ─────────────────────────────────────────────────────

# P3: LLM-check 실행 시 system prompt에서 제거할 SKILL.md 섹션 헤더 목록.
# 이 섹션들은 스크립트 실행법/Clone/Upload 안내로 run_skill.py가 이미 처리하므로
# LLM에 불필요하며 system prompt 토큰을 20~40% 절약한다.
_SKILL_MD_STRIP_HEADERS = {
    "### Step 1: Load references",
    "### ⚠️ 사전 필수",          # Clone 안내
    "### Step 2: Execute tasks",
    "### Step 3: Output validation",
    "### Step 4-1: LLM-Check 완료 확인",
    "### Step 5: Upload",
    "## Resources",
}


def _strip_skill_md(content: str) -> str:
    """SKILL.md에서 LLM-check 시 불필요한 섹션을 제거한다 (P3).

    제거 대상: 스크립트 실행법, Clone 안내, Upload/Cleanup, Resources 목록.
    보존 대상: Overview, 실행원칙(HARD RULE), Step 4 Summary 포맷.

    중첩 헤더 처리: 제거 대상 섹션의 하위 헤더(깊이 ≥ 제거 헤더)도 함께 제거.
    동일/상위 레벨 헤더가 나오면 skip 해제.
    """
    def _md_header_level(line: str) -> int:
        """마크다운 헤더 레벨 반환. '## foo' → 2, 코드블록 내 bash 주석 등 비헤더 → 0.
        마크다운 헤더는 반드시 '# ' (# + 공백) 패턴이어야 한다."""
        stripped = line.lstrip()
        if not stripped.startswith("#"):
            return 0
        level = len(stripped) - len(stripped.lstrip("#"))
        # '#' 뒤에 공백이 없으면 bash 주석/코드이지 마크다운 헤더가 아님
        rest = stripped[level:]
        if not rest.startswith(" "):
            return 0
        return level

    lines = content.split("\n")
    result: list[str] = []
    skip_from_level: int = 0  # 0 = not skipping
    in_code_block = False

    for line in lines:
        # 코드블록 토글 (``` 로 시작하는 줄)
        if line.strip().startswith("```"):
            in_code_block = not in_code_block

        level = 0 if in_code_block else _md_header_level(line)

        if level > 0:
            if skip_from_level and level > skip_from_level:
                # 현재 skip 중인 섹션의 하위 헤더 → 계속 skip
                pass
            else:
                # 동일/상위 레벨 헤더 → skip 해제 후 판단
                skip_from_level = 0
                is_strip = any(line.strip().startswith(h) for h in _SKILL_MD_STRIP_HEADERS)
                if is_strip:
                    skip_from_level = level

        if not skip_from_level:
            result.append(line)

    return "\n".join(result)


def build_system_prompt(skill: str, batch: bool = False) -> str:
    config = SKILL_CONFIG[skill]
    module = config["module"]

    skill_md_path = PALANTIR_DIR / module / "SKILL.md"
    raw_skill_md = skill_md_path.read_text(encoding="utf-8") if skill_md_path.exists() else ""
    skill_md = _strip_skill_md(raw_skill_md)  # P3: 불필요 섹션 제거

    # primary_ref: LLM-Check 핵심 절차서를 system prompt에 직접 포함
    # → LLM이 read_file 없이도 절차를 받음 (refs never-used 이슈 해소)
    primary_ref_content = ""
    primary_ref_path = config.get("primary_ref", "")
    if primary_ref_path:
        p = PALANTIR_DIR / primary_ref_path
        if p.exists():
            primary_ref_content = (
                f"\n=== LLM-Check 절차서 — {p.name} ===\n"
                + p.read_text(encoding="utf-8")
            )

    # 보조 refs 목록 안내 (on-demand read_file 유도)
    refs_hint = ""
    if config.get("refs"):
        refs_hint = "\n[보조 참조 문서 — 필요 시 read_file로 조회]\n" + "\n".join(
            f"  - {r}" for r in config["refs"]
        )

    batch_section = _BATCH_GUARDRAILS if batch else ""

    return f"""당신은 소프트웨어 보안 진단 전문가입니다.
아래 SKILL 정의와 절차서를 기반으로 진단을 자율 완주하세요.
{batch_section}
HARD RULES:
- "계속할까요?", "do you want to proceed?" 등 확인 질문 절대 금지
- Auto-Scan은 이미 완료된 상태 — 스캔 스크립트를 다시 실행하지 마세요
- LLM-Check 완료 후 반드시 run_cleanup 도구를 호출하세요
- write_file은 state/ 하위 경로에만 허용됩니다
{refs_hint}

=== SKILL 정의 ({module}/SKILL.md) ===
{skill_md}
{primary_ref_content}"""


# ─── LLM-Check (OpenAI agentic loop) ─────────────────────────────────────────

def run_llm_check(skill: str, src: str, prefix: str,
                  provider: str, model: str, api_key: str | None, base_url: str | None,
                  max_turns: int, skip_upload: bool,
                  batch: bool = False, skip_cleanup: bool = False) -> None:
    try:
        from openai import OpenAI, RateLimitError, APIStatusError
    except ImportError:
        print("\n[ERROR] openai 패키지 없음. 다음 명령으로 설치하세요:")
        print("  pip install openai")
        sys.exit(1)

    config = SKILL_CONFIG[skill]
    repo   = Path(src).name

    _sep()
    print(f"[Phase 2] LLM-Check — provider: {provider}  model: {model}")
    _sep()

    client_kwargs: dict = {"api_key": api_key or "no-key"}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)
    
    # [주의] Groq 등 컨텍스트 한도가 낮은 모델은 여기서 생성된 system_prompt 용량 때문에 413 에러가 날 수 있음.
    system_prompt = build_system_prompt(skill, batch=batch)
    # 배치 모드 컨텍스트 한도 (chars): 초과 시 조기 종료
    MAX_CTX_CHARS = 400_000 if batch else 900_000

    # cleanup 스킵 시 run_cleanup 도구 제거
    tools = TOOL_SCHEMAS if not skip_upload else [
        t for t in TOOL_SCHEMAS if t["function"]["name"] != "run_cleanup"
    ]

    user_msg = _make_llm_prompt(skill, src, prefix)
    if skip_upload:
        user_msg += "\n\n(이번 실행에서는 Cleanup은 건너뜁니다.)"

    messages: list[dict] = [{"role": "user", "content": user_msg}]

    turn = 0
    while turn < max_turns:
        turn += 1
        print(f"\n[LLM turn {turn}/{max_turns}]", end=" ", flush=True)

        # API 호출 및 재시도 로직 (Rate Limit 방어)
        max_retries = 5
        response = None
        
        for attempt in range(max_retries):
            try:
                # [안전장치 1] Gemini 무료 티어 RPM(분당 15회) 방어: 1회 요청 시 최소 4.2초 강제 지연
                if provider == "gemini":
                    time.sleep(4.2)
                    
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system_prompt}] + messages,
                    tools=tools,
                    tool_choice="auto",
                    max_tokens=8192,
                    temperature=0.1,
                )
                break  # 성공 시 재시도 루프 탈출
                
            except RateLimitError as e:
                # [안전장치 2] 429 에러 발생 시 지수 백오프(Exponential Backoff) 대기 후 재시도
                wait_time = 15 * (2 ** attempt)  # 15초, 30초, 60초...
                print(f"\n  [WARN] Rate Limit 초과 (429). {wait_time}초 대기 후 자동 재시도... ({attempt+1}/{max_retries})")
                time.sleep(wait_time)
                
            except APIStatusError as e:
                # [안전장치 3] 413 에러(토큰 초과) 발생 시 즉시 중단 및 원인 안내
                if e.status_code == 413:
                    print(f"\n  [ERROR] 토큰 한도 초과 (413).")
                    print(f"  원인: 레퍼런스 문서(SKILL.md 등)가 {model} 모델의 컨텍스트 한도를 초과했습니다.")
                    print(f"  대처: --provider gemini 등 컨텍스트 창이 큰 모델을 사용하세요.")
                    sys.exit(1)
                else:
                    print(f"\n  [ERROR] API 오류 발생: {e}")
                    sys.exit(1)
            except Exception as e:
                print(f"\n  [ERROR] 알 수 없는 네트워크/API 오류: {e}")
                sys.exit(1)
                
        if not response:
            print(f"\n  [ERROR] 최대 재시도 횟수({max_retries}회) 초과. LLM-Check를 중단합니다.")
            sys.exit(1)

        msg           = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        # 응답 메시지를 messages에 추가
        messages.append(msg.model_dump(exclude_unset=True))

        if msg.content:
            # 긴 텍스트는 앞 500자만 표시
            preview = msg.content.strip()[:500]
            suffix  = "..." if len(msg.content.strip()) > 500 else ""
            print(f"\n{preview}{suffix}")

        # 컨텍스트 누적 크기 추정 — 배치 모드 조기 종료 가드
        ctx_chars = sum(
            len(m.get("content") or "")
            + sum(len(str(tc)) for tc in (m.get("tool_calls") or []))
            for m in messages
        )
        if ctx_chars > MAX_CTX_CHARS:
            print(f"\n  [WARN] 컨텍스트 누적 {ctx_chars:,}자 > 한도 {MAX_CTX_CHARS:,}자")
            print("  배치 모드 조기 종료 — 현재까지의 결과를 저장하세요.")
            break

        if finish_reason == "stop":
            print("\n\n  ✓ LLM-Check 완료")
            break

        if finish_reason == "tool_calls" and msg.tool_calls:
            tool_results = []
            for tc in msg.tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                # 도구 호출 로그
                arg_preview = ", ".join(
                    f"{k}={str(v)[:80]}" for k, v in args.items()
                )
                print(f"  [Tool] {name}({arg_preview})")

                result = execute_tool(name, args, batch=batch, skip_cleanup=skip_cleanup)

                tool_results.append({
                    "role":         "tool",
                    "tool_call_id": tc.id,
                    "content":      str(result)[:32_000],
                })

            messages.extend(tool_results)
        else:
            print(f"\n  [WARN] 예상치 못한 finish_reason: {finish_reason}")
            break

    if turn >= max_turns:
        print(f"\n  [WARN] 최대 턴({max_turns}) 도달 — LLM-Check 중단")


# ─── 유틸 ─────────────────────────────────────────────────────────────────────

def _sep():
    print(f"\n{'─' * 60}")


def _provider_key_url(provider: str) -> str:
    urls = {
        "openai":   "https://platform.openai.com/api-keys",
        "gemini":   "https://aistudio.google.com/app/apikey",
        "groq":     "https://console.groq.com/keys",
        "deepseek": "https://platform.deepseek.com/api_keys",
        "ollama":   "(로컬 서버 — 키 불필요)",
    }
    return urls.get(provider, "")


def _banner(skill: str, src: str, prefix: str, provider: str, model: str):
    pconf = PROVIDERS[provider]
    _sep()
    print(f"  palantir / run_skill.py")
    print(f"  Skill    : {skill}")
    print(f"  Source   : {src}")
    print(f"  Prefix   : {prefix}")
    print(f"  Provider : {provider}  ({pconf['notes']})")
    print(f"  Model    : {model}")
    _sep()


# ─── 메인 ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="sec-scan skill 실행 (기본 provider: claude-cli)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("skill",  choices=list(SKILL_CONFIG.keys()), help="실행할 스킬")
    parser.add_argument("src",    help="소스코드 경로 (예: testbed/gws)")
    parser.add_argument("prefix", help="결과 저장 경로 (예: state/injection/gws/20260415_0915)")
    parser.add_argument("--provider",    default="claude-cli",
                        choices=list(PROVIDERS.keys()),
                        help="LLM provider (기본: claude-cli)")
    parser.add_argument("--model",       default=None,
                        help="모델명 (생략 시 provider 기본 모델 사용)")
    parser.add_argument("--api-key",     default=None,
                        help="API 키 (생략 시 provider 환경변수 자동 탐지)")
    parser.add_argument("--skip-scan",    action="store_true", help="Auto-Scan 건너뜀")
    parser.add_argument("--skip-llm",     action="store_true", help="LLM-Check 건너뜀")
    parser.add_argument("--skip-upload",  action="store_true", help="(레거시 — --skip-cleanup 사용 권장) Cleanup 건너뜀")
    parser.add_argument("--skip-cleanup", action="store_true",
                        help="testbed 삭제 생략 (배치 모드에서 멀티 skill 재사용 시 사용)")
    parser.add_argument("--batch",        action="store_true", default=True,
                        help="배치 모드: 토큰 절약 가드레일 활성화 (기본 ON). --no-batch로 해제")
    parser.add_argument("--no-batch",     action="store_false", dest="batch",
                        help="배치 모드 해제 (탐색적 grep/재시도 허용, 정밀 진단 시 사용)")
    parser.add_argument("--max-turns",      type=int,   default=None,
                        help="LLM 최대 턴 수 (기본: 배치 30, 일반 60)")
    parser.add_argument("--max-budget-usd", type=float, default=3.0,
                        help="claude-cli 1회 실행당 최대 비용 달러 (기본: $3.0)")
    args = parser.parse_args()

    # Provider 설정 해석
    pconf    = PROVIDERS[args.provider]
    base_url = pconf["base_url"]
    model    = args.model or pconf["default_model"]
    max_turns = args.max_turns if args.max_turns is not None else (30 if args.batch else 60)

    # API 키 확인 (claude-cli/ollama는 키 불필요)
    env_key = pconf["env_key"]
    api_key = args.api_key or (os.environ.get(env_key) if env_key else None)
    no_key_providers = {"ollama", "claude-cli"}
    if not api_key and args.provider not in no_key_providers and not args.skip_llm:
        print(f"[ERROR] {args.provider} API 키가 없습니다.")
        print(f"  방법 1: export {env_key}=<your-key>")
        print(f"  방법 2: --api-key <your-key> 옵션 사용")
        print(f"  키 발급: {_provider_key_url(args.provider)}")
        sys.exit(1)

    # 소스 경로 확인
    src_full = PALANTIR_DIR / args.src
    if not src_full.exists():
        print(f"[ERROR] 소스코드 경로 없음: {src_full}")
        sys.exit(1)

    # 결과 디렉터리 생성
    prefix_full = PALANTIR_DIR / args.prefix
    prefix_full.mkdir(parents=True, exist_ok=True)

    _banner(args.skill, args.src, args.prefix, args.provider, model)
    t0 = time.time()

    # ── Phase 1: Auto-Scan ──────────────────────────────────────────────────
    if not args.skip_scan:
        run_auto_scan(args.skill, args.src, args.prefix)
    else:
        print("\n[Phase 1] Auto-Scan — 스킵")

    # ── main_output 존재 확인 (LLM-Check 진입 게이트) ───────────────────────
    main_output_path = PALANTIR_DIR / args.prefix / SKILL_CONFIG[args.skill]["main_output"]
    if not args.skip_llm and not args.skip_scan and not main_output_path.exists():
        print(f"\n[ERROR] Auto-Scan 출력 없음: {main_output_path}")
        print("  LLM-Check를 건너뜁니다. Auto-Scan 오류를 먼저 해결하세요.")
        args.skip_llm = True

    # ── Phase 1.5: Pre-fetching — llm_input.json에 코드 스니펫 주입 ─────────
    if not args.skip_llm:
        _enrich_llm_input_with_snippets(args.prefix, args.src)

    # ── Phase 2: LLM-Check ──────────────────────────────────────────────────
    if not args.skip_llm:
        native = pconf.get("native")
        if native == "claude-cli":
            run_llm_check_claude_cli(
                args.skill, args.src, args.prefix,
                model if model != pconf["default_model"] or args.model else None,
                max_turns, args.skip_upload,
                batch=args.batch, skip_cleanup=args.skip_cleanup,
                max_budget_usd=args.max_budget_usd,
            )
        elif native is True:
            run_llm_check_anthropic(
                args.skill, args.src, args.prefix,
                model, api_key, max_turns, args.skip_upload,
                batch=args.batch, skip_cleanup=args.skip_cleanup,
            )
        else:
            run_llm_check(
                args.skill, args.src, args.prefix,
                args.provider, model, api_key, base_url,
                max_turns, args.skip_upload,
                batch=args.batch, skip_cleanup=args.skip_cleanup,
            )
    else:
        print("\n[Phase 2] LLM-Check — 스킵")

    # ── LLM-Check 실패 마커 확인 → bash에 exit=1 신호 ───────────────────────
    if not args.skip_llm and (prefix_full / "llm_check_failed.json").exists():
        elapsed = time.time() - t0
        _sep()
        print(f"  [실패] LLM-Check 미완료  소요시간: {elapsed:.0f}초")
        print(f"  결과: {args.prefix}/")
        _sep()
        sys.exit(1)

    # ── 완료 ────────────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    _sep()
    print(f"  완료  소요시간: {elapsed:.0f}초")
    print(f"  결과: {args.prefix}/")
    _sep()


if __name__ == "__main__":
    main()
