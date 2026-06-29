#!/usr/bin/env python3
"""
scan_sca_gradle_tree.py — Gradle Transitive Dependency SCA (OSV.dev 연동)

기존 scan_sca.py 의 한계 (물리적 JAR 파일 스캔만 가능) 를 극복한 대체 스크립트.
./gradlew dependencies 로 전이적 의존성 트리를 직접 추출하고,
결과를 OSV.dev Batch Query API 로 취약점 조회한다.

핵심 개선사항
  1. 전이적 의존성 (Transitive Dependency) 100% 포함
     — build.gradle 텍스트 파싱 방식은 직접 의존성만 식별하므로 기각.
     — gradlew 실행 → resolved dependency tree 추출.
  2. -> resolved version 정확 처리
     — "jackson-databind:2.13.3 -> 2.13.5" 에서 2.13.5 를 사용.
  3. UUID 격리 작업 디렉토리 — 병렬 실행 Race Condition 완전 방지
     — 각 실행마다 /tmp/sca_<uuid>/ 를 독립적으로 사용.
  4. OSV.dev Batch Query (chunked) — rate-limit 없이 대량 조회 가능.

사용법
    # 단일 모듈 프로젝트
    python3 scan_sca_gradle_tree.py testbed/gws/oki-be \\
        --project gws-oki-be \\
        --output state/t36_gws_oki_be_sca.json

    # 멀티모듈 — 특정 서브프로젝트 타겟
    python3 scan_sca_gradle_tree.py testbed/ob/ob-backend@master@bb1b2f4 \\
        --subproject :cms_resource \\
        --project ob-backend-cms \\
        --output state/t40_ob_backend_cms_sca.json

    # 멀티모듈 — 모든 서브프로젝트 합산 (대형 프로젝트 전체 커버리지)
    python3 scan_sca_gradle_tree.py testbed/ob/ob-backend@master@bb1b2f4 \\
        --all-subprojects \\
        --project ob-backend \\
        --output state/t40_ob_backend_sca.json

    # JDK 홈 직접 지정 (WSL2 에서 Windows JDK 경유 시)
    python3 scan_sca_gradle_tree.py testbed/ob/ob-backend@master@bb1b2f4 \\
        --java-home "/mnt/c/Program Files/Java/jdk-17" \\
        --project ob-backend \\
        --output state/t40_ob_backend_sca.json

실행 순서
    1. JDK 탐색 (--java-home > JAVA_HOME > 시스템 PATH > WSL2 Windows 경로)
    2. UUID 격리 작업 디렉토리 생성 (/tmp/sca_<uuid>/)
    3. gradlew 권한 설정 + ./gradlew [:<subproject>:]dependencies 실행
    4. 의존성 트리 파싱 → (groupId, artifactId, resolvedVersion) Set
    5. OSV.dev Batch Query (500 개 단위 청크)
    6. CVSS v3 Base Score 계산 + CISA KEV 교차 확인
    7. 결과를 공통 스키마로 출력 (publish_confluence.py 호환)
"""

import argparse
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────
# 상수
# ─────────────────────────────────────────────────────────────────

_OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"
_CISA_KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# OSV.dev 단일 배치 권장 상한. 초과 시 자동 청크 분할.
_OSV_BATCH_SIZE = 500

# CVSS Base Score 이상만 findings 로 기록 (정보성은 별도)
_DEFAULT_CVSS_THRESHOLD = 7.0

# gradlew 기본 실행 구성 (Transitive 포함하는 runtimeClasspath 사용)
_DEFAULT_CONFIGURATION = "runtimeClasspath"

# Gradle 의존성 트리 라인 파싱 정규식
#
# 대상 라인 예시:
#   +--- org.springframework:spring-web:5.3.21
#   \--- com.fasterxml.jackson.core:jackson-databind:2.13.3 -> 2.13.5
#   |    +--- org.springframework:spring-core:5.3.21 -> 5.3.27 (*)
#   +--- (c) com.example:constraint-lib:1.0    ← constraint 전용: groupId만 있고 버전 없음
#
# 캡처 그룹:
#   1 = groupId
#   2 = artifactId
#   3 = requested version (-> 앞)
#   4 = resolved version (-> 뒤, 없으면 None — 이 경우 그룹3 사용)
#
# 제외 패턴:
#   (*) — 이미 상위에서 출력된 중복 노드 (의존성 자체는 동일하므로 Set 중복제거로 처리)
#   (n) — 미해석 노드
#   (c) — constraint 전용 (버전 선언 없음)
_DEP_LINE_RE = re.compile(
    r"^[\s|]*[+\\]\-\-\-\s+"          # 트리 프리픽스:  |    +---  또는  \---
    r"(?:project\s+)?"                 # project :foo 형태의 내부 프로젝트 참조 — 스킵
    r"(?:\(c\)\s+)?"                   # (c) constraint 마커
    r"([A-Za-z0-9._\-]+)"             # groupId
    r":([A-Za-z0-9._\-]+)"            # artifactId
    r":([^\s\->()]+)"                  # requested version (공백·→·괄호 이전까지)
    r"(?:\s+->\s+([^\s()+]+))?"        # -> resolved version (선택적)
    r"(?:\s+\([^)]*\))?"              # (*), (c), (n) 등 후행 마커 — 스킵
    r"\s*$"
)

# 멀티모듈 프로젝트에서 서브프로젝트 경로 파싱 (gradlew projects 출력)
# 예: "+--- Project ':business:ocb-member'"  or  "\--- Project ':cms_resource'"
_SUBPROJECT_RE = re.compile(r"[+\\]\-\-\-\s+Project\s+'([^']+)'")


# ─────────────────────────────────────────────────────────────────
# 환경 변수 / .env 로더
# ─────────────────────────────────────────────────────────────────

def _load_env(env_path: Path = Path(".env")) -> dict:
    """`.env` 파일에서 KEY=VALUE 형식으로 환경 변수를 로드한다."""
    env = {}
    if not env_path.exists():
        return env
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


_ENV: dict = _load_env(Path(__file__).parent.parent.parent / ".env")


# ─────────────────────────────────────────────────────────────────
# CVSS v3 Base Score 계산기
# ─────────────────────────────────────────────────────────────────

def _cvss3_base_score(vector: str) -> float:
    """CVSS v3.x 벡터 문자열에서 Base Score 를 계산한다.

    CVSS v3.1 공식: https://www.first.org/cvss/v3.1/specification-document
    벡터 예시: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8

    Returns:
        0.0~10.0 (float). 파싱 실패 시 0.0 반환.
    """
    try:
        # "CVSS:3.1/..." 또는 "CVSS:3.0/..." 접두사 제거
        raw = vector.split("/", 1)[-1] if "CVSS:" in vector else vector
        parts: dict[str, str] = {}
        for seg in raw.split("/"):
            if ":" in seg:
                k, v = seg.split(":", 1)
                parts[k] = v

        # ── Impact Sub Score (ISS) ──────────────────────────────
        # CIA Impact 가중치 테이블
        cia_weight = {"N": 0.00, "L": 0.22, "H": 0.56}
        c_val = cia_weight.get(parts.get("C", "N"), 0.0)
        i_val = cia_weight.get(parts.get("I", "N"), 0.0)
        a_val = cia_weight.get(parts.get("A", "N"), 0.0)

        iss = 1.0 - (1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val)

        scope = parts.get("S", "U")
        if scope == "U":
            impact = 6.42 * iss
        else:  # Scope Changed
            # 공식: 7.52×[ISS−0.029] − 3.25×[ISS−0.02]^15
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        if impact <= 0.0:
            return 0.0

        # ── Exploitability Sub Score ────────────────────────────
        av_weight  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_weight  = {"L": 0.77, "H": 0.44}
        # PR 가중치는 Scope 값에 따라 달라진다 (Unchanged vs Changed)
        pr_weight_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_weight_c = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_weight  = {"N": 0.85, "R": 0.62}

        pr_map = pr_weight_c if scope == "C" else pr_weight_u
        exploitability = (
            8.22
            * av_weight.get(parts.get("AV", "N"), 0.85)
            * ac_weight.get(parts.get("AC", "L"), 0.77)
            * pr_map.get(parts.get("PR", "N"),    0.85)
            * ui_weight.get(parts.get("UI", "N"), 0.85)
        )

        # ── Base Score ──────────────────────────────────────────
        if scope == "U":
            raw_score = min(impact + exploitability, 10.0)
        else:
            raw_score = min(1.08 * (impact + exploitability), 10.0)

        # CVSS 규격: 소수 첫째 자리에서 올림 (0.1 단위)
        return math.ceil(raw_score * 10) / 10.0

    except Exception:
        return 0.0


def _severity_label(score: float) -> str:
    """CVSS 점수 → 심각도 레이블."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Unknown"


def _version_key(v: str) -> tuple:
    """버전 문자열을 비교 가능한 튜플로 변환한다.

    예) "10.1.34" → ((0,10),(0,1),(0,34))
        "2.0.0-M3" → ((0,2),(0,0),(0,0),(1,"m3"))
    숫자 파트가 알파 파트보다 앞에 오도록 (0, int) vs (1, str) 구분.
    """
    parts = re.split(r"[.\-]", v)
    result = []
    for p in parts:
        try:
            result.append((0, int(p)))
        except ValueError:
            result.append((1, p.lower()))
    return tuple(result)


def _extract_fixed_version(osv_vuln: dict, package_name: str) -> str:
    """OSV vuln 객체의 affected 배열에서 해당 패키지의 최신 fixed 버전을 반환한다.

    OSV affected 구조:
      affected[].package.name == "group:artifact" (Maven) 또는 패키지명 (npm)
      affected[].ranges[type=ECOSYSTEM].events: [{"introduced": "0"}, {"fixed": "1.2.3"}, ...]

    여러 버전 브랜치에 대한 fixed 이벤트가 있을 수 있으며 (e.g. 9.0.x, 10.1.x 각각),
    모든 fixed 버전 중 최댓값을 반환한다 — 가장 최신 패치 버전 권고.

    Returns:
        fixed version 문자열. 데이터 없으면 "".
    """
    artifact_suffix = package_name.split(":")[-1].lower()
    fixed_versions: list[str] = []

    for affected_item in osv_vuln.get("affected", []):
        pkg = affected_item.get("package", {})
        osv_name = pkg.get("name", "").lower()

        # 패키지 매칭: 전체명 일치 또는 artifactId(콜론 이후) 일치
        if not osv_name:
            continue
        if osv_name != package_name.lower() and osv_name.split(":")[-1] != artifact_suffix:
            continue

        for rng in affected_item.get("ranges", []):
            # ECOSYSTEM (Maven 등) 및 SEMVER (npm 등) 모두 처리
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in rng.get("events", []):
                fv = event.get("fixed", "")
                if fv:
                    fixed_versions.append(fv)

    if not fixed_versions:
        return ""
    try:
        return max(fixed_versions, key=_version_key)
    except Exception:
        return fixed_versions[-1]


# ─────────────────────────────────────────────────────────────────
# HTTP 유틸리티
# ─────────────────────────────────────────────────────────────────

def _http_get_json(url: str, timeout: int = 15) -> Optional[dict | list]:
    """GET 요청 → JSON 파싱. 실패 시 None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "scan_sca_gradle_tree/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _http_post_json(url: str, body: dict, timeout: int = 30) -> Optional[dict]:
    """POST JSON 요청 → JSON 파싱. 실패 시 None."""
    try:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "scan_sca_gradle_tree/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"  ⚠️  HTTP POST 실패 ({url}): {e}", file=sys.stderr)
        return None


# ─────────────────────────────────────────────────────────────────
# JDK 탐색 + 자동 설치
# ─────────────────────────────────────────────────────────────────

# Linux 네이티브 JDK 17 다운로드 후보 (접근 가능 CDN 순, sudo 불필요)
# setup_linux_jdk.sh 와 동일 CDN 순서: Corretto(AWS) > OpenJDK.net(Akamai) > Zulu > Temurin
_JDK17_CANDIDATES = [
    ("Amazon Corretto 17",
     "https://corretto.aws/downloads/latest/amazon-corretto-17-x64-linux-jdk.tar.gz"),
    ("OpenJDK 17 (download.java.net)",
     "https://download.java.net/java/GA/jdk17/0d483333a00540d886896bac774ff48b/35/GPL/openjdk-17_linux-x64_bin.tar.gz"),
    ("Zulu JDK 17",
     "https://cdn.azul.com/zulu/bin/zulu17.56.15-ca-jdk17.0.14-linux_x64.tar.gz"),
    ("Eclipse Temurin 17",
     "https://github.com/adoptium/temurin17-binaries/releases/download/"
     "jdk-17.0.11%2B9/OpenJDK17U-jdk_x64_linux_hotspot_17.0.11_9.tar.gz"),
]
# 로컬 설치 기본 경로 (sudo 불필요)
_LOCAL_JDK_DIR = Path.home() / ".local" / "share" / "jdk"


def _find_java(java_home_override: Optional[str] = None) -> Optional[Path]:
    """java 실행 파일 경로 탐색 (설치 없이 기존 JDK 만 탐색).

    우선순위:
      1. --java-home 인수
      2. JAVA_HOME 환경변수 / .env
      3. 로컬 자동설치 경로 (~/.local/share/jdk/)
      4. WSL2 Windows 측 JDK (/mnt/c/Program Files/Java/*)
      5. 시스템 PATH (which java)
    """
    candidates: list[Path] = []

    if java_home_override:
        candidates.append(Path(java_home_override) / "bin" / "java")

    java_home_env = os.environ.get("JAVA_HOME") or _ENV.get("JAVA_HOME")
    if java_home_env:
        candidates.append(Path(java_home_env) / "bin" / "java")

    # 이전 자동설치로 내려받은 로컬 JDK 탐색
    if _LOCAL_JDK_DIR.exists():
        for child in sorted(_LOCAL_JDK_DIR.iterdir(), reverse=True):
            candidates.append(child / "bin" / "java")

    # WSL2: IntelliJ IDEA 가 ~/.jdks/ 에 내려받은 JDK (Corretto, MS OpenJDK 등)
    # Windows 사용자 홈의 .jdks 디렉토리 탐색 (버전 내림차순 — 최신 우선)
    for win_user in ["/mnt/c/Users/skplanet", "/mnt/c/Users/GEUN", "/mnt/c/Users"]:
        jdks_dir = Path(win_user) / ".jdks"
        if jdks_dir.exists():
            for child in sorted(jdks_dir.iterdir(), reverse=True):
                candidates.append(child / "bin" / "java")
                candidates.append(child / "bin" / "java.exe")

    # WSL2: Windows 측 JDK 표준 설치 경로
    for win_root in [
        "/mnt/c/Program Files/Java",
        "/mnt/c/Program Files/Microsoft",
        "/mnt/c/Program Files/Eclipse Adoptium",
    ]:
        win_jdk = Path(win_root)
        if win_jdk.exists():
            for child in sorted(win_jdk.iterdir(), reverse=True):
                candidates.append(child / "bin" / "java")

    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate

    # PATH 마지막 시도
    try:
        result = subprocess.run(["which", "java"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return Path(result.stdout.strip())
    except Exception:
        pass

    return None


def _install_jdk_apt() -> Optional[Path]:
    """apt-get 으로 OpenJDK 17 설치 (sudo 필요).

    Returns:
        설치 성공 시 java 경로, 실패 시 None.
    """
    print("  [apt] sudo apt-get install -y openjdk-17-jdk 시도...")
    try:
        subprocess.run(
            ["sudo", "apt-get", "install", "-y", "--no-install-recommends", "openjdk-17-jdk"],
            check=True, timeout=300,
        )
        # 설치 후 경로 재탐색
        result = subprocess.run(
            ["which", "java"], capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            java = Path(result.stdout.strip())
            print(f"  ✅ apt 설치 완료: {java}")
            return java
    except subprocess.CalledProcessError as e:
        print(f"  ⚠️  apt 설치 실패 (rc={e.returncode}) — 다음 방법 시도", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("  ⚠️  apt 타임아웃", file=sys.stderr)
    except FileNotFoundError:
        print("  ⚠️  sudo/apt-get 없음", file=sys.stderr)
    return None


def _install_jdk_download() -> Optional[Path]:
    """Linux 네이티브 JDK 17 을 다운로드하여 ~/.local/share/jdk/jdk-17/ 에 설치.

    sudo 권한 불필요. CDN 우선순위: Corretto(AWS) > OpenJDK.net > Zulu > Temurin.
    setup_linux_jdk.sh 와 동일 로직.

    Returns:
        설치 성공 시 java 경로, 실패 시 None.
    """
    dest_dir = _LOCAL_JDK_DIR / "jdk-17"
    dest_dir.mkdir(parents=True, exist_ok=True)
    tarball   = _LOCAL_JDK_DIR / "jdk17.tar.gz"

    # ── CDN 순서대로 다운로드 시도 ───────────────────────────────
    downloaded = False
    for cdn_name, url in _JDK17_CANDIDATES:
        print(f"  [download] {cdn_name} 접근 확인 중...")
        try:
            # HEAD 요청으로 접근 가능 여부 먼저 확인 (타임아웃 8초)
            req_head = urllib.request.Request(url, method="HEAD",
                           headers={"User-Agent": "scan_sca_gradle_tree/1.0"})
            with urllib.request.urlopen(req_head, timeout=8):
                pass
        except Exception:
            print(f"  ⚠️  {cdn_name} 접근 불가 — 다음 CDN 시도", file=sys.stderr)
            continue

        print(f"  ✅ {cdn_name} 접근 가능. 다운로드 시작 (약 180~200MB)...")
        print(f"  URL: {url}")
        try:
            def _progress(count: int, block: int, total: int) -> None:
                if total > 0:
                    pct = min(count * block / total * 100, 100)
                    print(f"\r    {pct:.0f}%  ({count * block // 1_048_576}MB / {total // 1_048_576}MB)   ",
                          end="", flush=True)
            urllib.request.urlretrieve(url, str(tarball), reporthook=_progress)
            print()
            if tarball.exists() and tarball.stat().st_size > 1_000_000:
                downloaded = True
                break
        except Exception as e:
            print(f"\n  ⚠️  {cdn_name} 다운로드 실패: {e} — 다음 CDN 시도", file=sys.stderr)
            tarball.unlink(missing_ok=True)

    if not downloaded:
        print("  ❌ 모든 CDN 다운로드 실패.", file=sys.stderr)
        print("     수동 설치: bash tools/scripts/setup_linux_jdk.sh", file=sys.stderr)
        return None

    # ── 압축 해제 ─────────────────────────────────────────────────
    print(f"  압축 해제 중 → {dest_dir}")
    try:
        with tarfile.open(tarball, "r:gz") as tf:
            # strip-components=1 효과: 최상위 디렉토리(jdk-17.0.x) 제거
            members = tf.getmembers()
            prefix  = members[0].name.split("/")[0] if members else ""
            for member in members:
                member.name = member.name.replace(f"{prefix}/", "", 1) if prefix else member.name
                if member.name:
                    tf.extract(member, path=dest_dir)
        tarball.unlink(missing_ok=True)
    except Exception as e:
        print(f"  ❌ 압축 해제 실패: {e}", file=sys.stderr)
        return None

    # ── 설치 검증 ────────────────────────────────────────────────
    java_bin = dest_dir / "bin" / "java"
    if not java_bin.exists():
        print(f"  ❌ java 바이너리 없음: {java_bin}", file=sys.stderr)
        return None

    java_home = dest_dir
    os.environ["JAVA_HOME"] = str(java_home)
    os.environ["PATH"]      = f"{java_home / 'bin'}:{os.environ.get('PATH', '')}"

    print(f"  ✅ JDK 설치 완료: {java_bin}")
    print(f"  ℹ️  JAVA_HOME={java_home}  (현재 프로세스)")
    print(f"     영구 적용: bash tools/scripts/setup_linux_jdk.sh")

    # ~/.local/.installed_jdk17 마커 저장
    (_LOCAL_JDK_DIR / ".installed_jdk17").write_text(str(java_bin))
    return java_bin


def _ensure_java(
    java_home_override: Optional[str] = None,
    auto_install: bool = False,
) -> Optional[Path]:
    """JDK 를 탐색하고, 없으면 자동 설치를 시도한다.

    설치 전략 (auto_install=True 시):
      1. apt-get install openjdk-17-jdk  (sudo, 빠름 ~30초)
      2. Eclipse Temurin 17 직접 다운로드  (sudo 불필요, ~180MB, 약 1분)

    Note:
      `./gradlew dependencies` 는 소스 컴파일을 하지 않는다.
      Gradle 자체를 실행하기 위한 JRE/JDK 만 필요하므로
      JDK 17 LTS 설치로 충분하다.

    Returns:
        java 실행 파일 Path, 또는 설치 실패 시 None.
    """
    # ── 1차: 기존 JDK 탐색 ───────────────────────────────────────
    java = _find_java(java_home_override)
    if java:
        return java

    print("\n  ⚠️  JDK 를 찾을 수 없습니다.")

    if not auto_install:
        _print_jdk_install_guide()
        return None

    print("  → --auto-install-jdk 플래그 감지. JDK 자동 설치를 시작합니다.")
    print("  ℹ️  gradlew dependencies 는 소스 컴파일 없이 의존성 트리만 해석합니다.")
    print("     (JDK 실행 환경만 필요 — 전체 빌드 불필요)\n")

    # ── 2차: apt-get 시도 ─────────────────────────────────────────
    java = _install_jdk_apt()
    if java:
        return java

    # ── 3차: 직접 다운로드 (sudo 불필요 fallback) ─────────────────
    print("  → apt 실패. Eclipse Temurin 17 직접 다운로드 시도...")
    java = _install_jdk_download()
    if java:
        return java

    print("\n  ❌ 모든 JDK 설치 방법 실패.", file=sys.stderr)
    _print_jdk_install_guide()
    return None


def _print_jdk_install_guide() -> None:
    """JDK 설치 안내 메시지 출력."""
    print("\n  JDK 설치 방법:", file=sys.stderr)
    print("  ┌─ WSL2 Ubuntu/Debian (권장):", file=sys.stderr)
    print("  │   sudo apt-get install -y openjdk-17-jdk", file=sys.stderr)
    print("  ├─ sudo 없이 자동 설치:", file=sys.stderr)
    print("  │   python3 scan_sca_gradle_tree.py ... --auto-install-jdk", file=sys.stderr)
    print("  ├─ Windows JDK 를 WSL2 에서 사용:", file=sys.stderr)
    print("  │   --java-home '/mnt/c/Program Files/Java/jdk-17'", file=sys.stderr)
    print("  └─ SDKMAN (sudo 불필요):", file=sys.stderr)
    print("      curl -s https://get.sdkman.io | bash", file=sys.stderr)
    print("      source ~/.sdkman/bin/sdkman-init.sh && sdk install java 17-open", file=sys.stderr)


def _find_gradlew(project_dir: Path) -> Optional[Path]:
    """gradlew (Linux) 또는 gradlew.bat (Windows) 경로 탐색."""
    for name in ("gradlew", "gradlew.bat"):
        candidate = project_dir / name
        if candidate.exists():
            return candidate
    return None


# ─────────────────────────────────────────────────────────────────
# Gradle 환경 자동 보정 (WSL2 / Windows clone 대응)
# ─────────────────────────────────────────────────────────────────

def _block_end(text: str, open_pos: int) -> int:
    """open_pos 위치의 '{' 에서 시작하는 블록의 닫는 '}' 인덱스를 반환."""
    depth = 0
    for i in range(open_pos, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def _fix_gradlew_crlf(project_dir: Path) -> None:
    """gradlew 의 CRLF line endings 를 LF 로 변환한다 (Windows clone 대응)."""
    gradlew = project_dir / "gradlew"
    if not gradlew.exists():
        return
    raw = gradlew.read_bytes()
    if b"\r" in raw:
        fixed = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        gradlew.write_bytes(fixed)
        print("  [prep] gradlew: CRLF → LF 변환 완료")


def _fix_settings_gradle(settings_file: Path) -> None:
    """settings.gradle(.kts) 의 Nexus-only pluginManagement 와 refreshVersions 를 보정한다.

    - pluginManagement.repositories 가 Nexus URL 만 포함 시 → gradlePluginPortal + mavenCentral 로 교체
    - de.fayard.refreshVersions 플러그인 블록 → 주석 처리 (외부망 미접속 환경 대응)
    """
    try:
        text = settings_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    original = text
    nexus_re = re.compile(r"https?://[^\s\"']*nexus[^\s\"']*", re.IGNORECASE)

    # ── pluginManagement 블록 내 repositories 수정 ─────────────────
    pm_idx = text.find("pluginManagement")
    if pm_idx != -1:
        brace_idx = text.find("{", pm_idx)
        if brace_idx != -1:
            pm_end = _block_end(text, brace_idx)
            pm_block = text[brace_idx : pm_end + 1]

            if nexus_re.search(pm_block):
                repo_idx = pm_block.find("repositories")
                if repo_idx != -1:
                    repo_brace = pm_block.find("{", repo_idx)
                    if repo_brace != -1:
                        repo_end = _block_end(pm_block, repo_brace)
                        new_repos = "{\n        gradlePluginPortal()\n        mavenCentral()\n    }"
                        pm_block = pm_block[:repo_brace] + new_repos + pm_block[repo_end + 1:]
                        text = text[:brace_idx] + pm_block + text[pm_end + 1:]
                        print(f"  [prep] {settings_file.name}: pluginManagement.repositories → gradlePluginPortal + mavenCentral")

    # ── refreshVersions 플러그인 블록 주석 처리 ─────────────────────
    # 이미 모든 라인이 주석 처리된 경우는 매칭 제외
    rv_re = re.compile(
        r"^(?!\s*//)(\s*plugins\s*\{[^}]*de\.fayard\.refreshVersions[^}]*\})",
        re.MULTILINE | re.DOTALL,
    )

    def _comment_out(m: re.Match) -> str:
        return "\n".join("// " + line for line in m.group(0).splitlines())

    new_text, n = rv_re.subn(_comment_out, text)
    if n > 0:
        text = new_text
        print(f"  [prep] {settings_file.name}: refreshVersions 블록 주석 처리")

    if text != original:
        settings_file.write_text(text, encoding="utf-8")


def _fix_build_gradle_repos(build_file: Path) -> None:
    """build.gradle(.kts) 의 Nexus-only repositories 블록을 mavenCentral + mavenLocal 로 교체한다."""
    try:
        text = build_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    original = text
    nexus_re = re.compile(r"https?://[^\s\"']*nexus[^\s\"']*", re.IGNORECASE)

    # top-level repositories {} 블록만 대상 (pluginManagement 하위 제외)
    search_start = 0
    modified = False
    while True:
        repo_match = re.search(r"\brepos(?:itories)?\s*\{", text[search_start:])
        if not repo_match:
            break
        abs_repo_start = search_start + repo_match.start()
        brace_open = search_start + repo_match.end() - 1
        brace_close = _block_end(text, brace_open)
        repo_block = text[brace_open : brace_close + 1]

        # pluginManagement 하위인지 확인 (단순: 앞에 pluginManagement 가 200자 이내에 있으면 건너뜀)
        prefix = text[max(0, abs_repo_start - 200) : abs_repo_start]
        if "pluginManagement" in prefix and prefix.rfind("pluginManagement") > prefix.rfind("}"):
            search_start = brace_close + 1
            continue

        if nexus_re.search(repo_block):
            new_block = "{\n    mavenCentral()\n    mavenLocal()\n}"
            text = text[:brace_open] + new_block + text[brace_close + 1:]
            print(f"  [prep] {build_file.name}: repositories Nexus → mavenCentral + mavenLocal")
            modified = True
            # 블록 길이가 바뀌었으므로 처음부터 재탐색
            search_start = 0
        else:
            search_start = brace_close + 1

    if modified:
        build_file.write_text(text, encoding="utf-8")


def _needs_refreshversions(project_dir: Path) -> bool:
    """versions.properties 가 존재하고 build.gradle.kts 에 버전 없는 플러그인이 있으면 True."""
    if not (project_dir / "versions.properties").exists():
        return False
    build = project_dir / "build.gradle.kts"
    if not build.exists():
        build = project_dir / "build.gradle"
    if not build.exists():
        return False
    text = build.read_text(encoding="utf-8", errors="replace")
    # plugins 블록 안에 버전 없이 id("...") 만 있는 줄 탐지
    plugins_match = re.search(r"plugins\s*\{", text)
    if not plugins_match:
        return False
    brace_open = plugins_match.end() - 1
    brace_close = _block_end(text, brace_open)
    plugins_block = text[brace_open : brace_close + 1]
    # id("...") 가 있고 version 이 없는 줄이 하나라도 있으면 True
    for line in plugins_block.splitlines():
        stripped = line.strip()
        if re.search(r'\bid\s*\(', stripped) and "version" not in stripped and not stripped.startswith("//"):
            return True
    return False


def _enable_refreshversions(settings_file: Path) -> None:
    """settings.gradle(.kts) 에서 refreshVersions 플러그인 블록을 활성화한다.

    - 이미 활성화된 경우: 아무것도 하지 않음
    - 주석처리된 경우: 주석 해제
    - 없는 경우: plugins { id("de.fayard.refreshVersions") version "0.40.2" } 블록 추가
    """
    try:
        text = settings_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    # 이미 활성화된 경우 (주석 아닌 줄에 refreshVersions 선언 존재)
    already_active = any(
        "de.fayard.refreshVersions" in line and not line.strip().startswith("//")
        for line in text.splitlines()
    )
    if already_active:
        return

    # 파일 끝에 개행이 없으면 추가 (마지막 줄이 regex에서 누락되는 것 방지)
    if not text.endswith("\n"):
        text = text + "\n"

    original = text

    # 주석처리된 블록 해제: de.fayard.refreshVersions 가 포함된 연속 주석 블록 찾아 주석 제거
    rv_commented_re = re.compile(
        r"((?:^[ \t]*//[^\n]*\n)*[ \t]*//[^\n]*de\.fayard\.refreshVersions[^\n]*\n(?:[ \t]*//[^\n]*\n)*)",
        re.MULTILINE,
    )
    m = rv_commented_re.search(text)
    if m:
        uncommented = re.sub(r"^[ \t]*// ?", "", m.group(0), flags=re.MULTILINE)
        text = text[:m.start()] + uncommented + text[m.end():]
    else:
        # 블록 자체가 없음 → 파일 끝에 추가
        text = text.rstrip() + '\n\nplugins {\n    id("de.fayard.refreshVersions") version "0.40.2"\n}\n'

    if text != original:
        settings_file.write_text(text, encoding="utf-8")
        print(f"  [prep] {settings_file.name}: refreshVersions 플러그인 활성화")


def _detect_installed_java_version() -> Optional[int]:
    """현재 환경의 Java major 버전을 반환한다. 감지 실패 시 None."""
    try:
        result = subprocess.run(
            ["java", "-version"], capture_output=True, text=True, timeout=10,
        )
        # java -version 출력은 stderr 로 나옴
        output = result.stderr or result.stdout
        m = re.search(r'"(\d+)(?:\.(\d+))?', output)
        if m:
            major = int(m.group(1))
            if major == 1 and m.group(2):  # Java 8: "1.8.x" 형식
                major = int(m.group(2))
            return major
    except Exception:
        pass
    return None


def _fix_java_toolchain(build_file: Path, installed_version: int) -> None:
    """build.gradle(.kts) 의 JavaLanguageVersion.of(N) 을 설치된 버전으로 낮춘다."""
    try:
        text = build_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return

    pattern = re.compile(r"JavaLanguageVersion\.of\((\d+)\)")

    def _clamp_version(m: re.Match) -> str:
        declared = int(m.group(1))
        if declared > installed_version:
            return f"JavaLanguageVersion.of({installed_version})"
        return m.group(0)

    new_text, n = pattern.subn(_clamp_version, text)
    if n > 0 and new_text != text:
        build_file.write_text(new_text, encoding="utf-8")
        print(f"  [prep] {build_file.name}: Java toolchain → {installed_version} (설치 버전 기준 자동 조정)")


def _prepare_gradle_env(project_dir: Path) -> None:
    """gradlew 실행 전 WSL2/Windows-clone 환경 호환성 자동 보정.

    1. gradlew CRLF → LF 변환
    2. settings.gradle(.kts): Nexus-only pluginManagement → gradlePluginPortal + mavenCentral
    3. settings.gradle(.kts): refreshVersions 블록 — 필요 시 활성화, 불필요 시 주석처리
    4. build.gradle(.kts): Nexus-only repositories → mavenCentral + mavenLocal
    5. build.gradle(.kts): Java toolchain 버전 → 설치된 JDK 버전으로 자동 다운그레이드
    """
    print("  [prep] Gradle 환경 호환성 보정 중...")
    _fix_gradlew_crlf(project_dir)

    needs_rv = _needs_refreshversions(project_dir)

    for sf in (
        list(project_dir.rglob("settings.gradle.kts"))
        + list(project_dir.rglob("settings.gradle"))
    ):
        _fix_settings_gradle(sf)
        if needs_rv:
            _enable_refreshversions(sf)

    build_files = (
        list(project_dir.rglob("build.gradle.kts"))
        + list(project_dir.rglob("build.gradle"))
    )
    for bf in build_files:
        _fix_build_gradle_repos(bf)

    installed_java = _detect_installed_java_version()
    if installed_java:
        print(f"  [prep] 설치된 Java 버전: {installed_java}")
        for bf in build_files:
            _fix_java_toolchain(bf, installed_java)
    else:
        print("  [prep] Java 버전 감지 실패 — toolchain 버전 조정 생략", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────
# Gradle 실행 헬퍼
# ─────────────────────────────────────────────────────────────────

def _run_gradle(
    project_dir: Path,
    gradlew: Path,
    args: list[str],
    java_home: Optional[Path],
    job_id: str,
    timeout: int = 600,
) -> Optional[str]:
    """gradlew 를 실행하고 stdout 을 반환한다.

    [Race Condition 방지]
    Gradle 데몬 및 프로젝트 캐시가 동시 실행 시 충돌하지 않도록
    --project-cache-dir 를 UUID 격리 경로(/tmp/sca_<uuid>/gradle_cache)로 지정한다.
    """
    # UUID 기반 격리 Gradle 캐시 디렉토리
    # 여러 scan_sca_gradle_tree.py 가 동시에 실행될 때 ~/.gradle 공유 캐시 충돌 방지
    isolated_cache = Path(f"/tmp/sca_{job_id}") / "gradle_cache"
    isolated_cache.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    if java_home:
        # JAVA_HOME 을 명시적으로 설정 (gradlew 내부 java 탐색에 사용됨)
        env["JAVA_HOME"] = str(java_home.parent.parent)

    # gradlew 실행 권한 보장 (WSL2 checkout 시 +x 가 빠지는 경우 대비)
    try:
        os.chmod(gradlew, 0o755)
    except Exception:
        pass

    cmd = [str(gradlew)] + args + [
        "--project-cache-dir", str(isolated_cache),
        "--no-daemon",     # 데몬 공유에 의한 상태 오염 방지
        "--console", "plain",
        "--quiet",
    ]

    # SCA_GRADLE_INIT_SCRIPT 환경변수가 설정된 경우 init script 추가
    # (사내망 Nexus 접근 불가 환경에서 Maven Central 오버라이드 등에 사용)
    init_script = os.environ.get("SCA_GRADLE_INIT_SCRIPT", "")
    if init_script and Path(init_script).exists():
        cmd += ["--init-script", init_script]

    print(f"  실행: {' '.join(cmd[:3])} ... (job={job_id[:8]})")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        if proc.returncode != 0:
            print(f"  ⚠️  gradlew 비정상 종료 (rc={proc.returncode})", file=sys.stderr)
            if proc.stderr:
                # 첫 5줄만 출력 (너무 긴 에러 메시지 억제)
                for line in proc.stderr.strip().splitlines()[:5]:
                    print(f"     {line}", file=sys.stderr)
            # rc != 0 이어도 stdout 에 의존성 정보가 있을 수 있음 (일부 빌드 실패 시)
        return proc.stdout
    except subprocess.TimeoutExpired:
        print(f"  ❌ gradlew 타임아웃 ({timeout}초)", file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"  ❌ gradlew 실행 파일을 찾을 수 없음: {gradlew}", file=sys.stderr)
        return None


def _list_subprojects(
    project_dir: Path,
    gradlew: Path,
    java_home: Optional[Path],
    job_id: str,
) -> list[str]:
    """멀티모듈 프로젝트의 서브프로젝트 목록을 반환한다.

    `./gradlew projects` 출력 파싱 결과:
        [':business:ocb-member', ':cms_resource', ':event_resource', ...]
    """
    output = _run_gradle(project_dir, gradlew, ["projects"], java_home, job_id, timeout=120)
    if not output:
        return []

    subprojects = []
    for line in output.splitlines():
        m = _SUBPROJECT_RE.search(line)
        if m:
            path = m.group(1)
            # 루트 프로젝트 (':') 는 제외
            if path and path != ":":
                subprojects.append(path)

    return subprojects


# ─────────────────────────────────────────────────────────────────
# 의존성 트리 파싱
# ─────────────────────────────────────────────────────────────────

def _parse_dependency_tree(output: str) -> set[tuple[str, str, str]]:
    """gradlew dependencies 출력에서 (groupId, artifactId, resolvedVersion) Set 을 추출한다.

    처리 규칙:
      - "+--- groupId:artifactId:version" → (groupId, artifactId, version)
      - r"\--- ...:version -> resolvedVersion" → (groupId, artifactId, resolvedVersion) 사용
        (앞의 requested version 은 버림; BOM/constraints 에 의해 override 된 최종 버전 우선)
      - "(*)" 는 이미 다른 노드에서 출력된 중복이므로 Set 으로 자동 제거됨
      - "project :subproject" 형태의 내부 프로젝트 참조는 regex 에서 제외

    Returns:
        중복 제거된 (groupId, artifactId, resolvedVersion) 튜플 Set.
    """
    deps: set[tuple[str, str, str]] = set()

    for line in output.splitlines():
        m = _DEP_LINE_RE.match(line)
        if not m:
            continue

        group_id    = m.group(1)
        artifact_id = m.group(2)
        # [핵심] -> resolved version 이 있으면 우선 사용, 없으면 requested version 사용
        resolved_version = m.group(4) if m.group(4) else m.group(3)

        # 빈 버전 또는 "unspecified" 제외
        if not resolved_version or resolved_version.lower() in ("unspecified", ""):
            continue

        deps.add((group_id, artifact_id, resolved_version))

    return deps


# ─────────────────────────────────────────────────────────────────
# OSV.dev Batch Query + 상세 조회
# ─────────────────────────────────────────────────────────────────

def _fetch_vuln_details(vuln_id: str) -> Optional[dict]:
    """OSV /vulns/{id} 엔드포인트로 취약점 전체 정보 (CVSS 포함) 를 조회한다.

    배경: querybatch 응답은 {id, modified} 스텁만 반환하므로,
    CVSS 점수·aliases·summary 를 얻으려면 개별 조회가 필요하다.
    """
    return _http_get_json(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=15)


def _query_osv_batch(
    deps: list[tuple[str, str, str]],
    batch_size: int = _OSV_BATCH_SIZE,
) -> list[dict]:
    """의존성 목록을 OSV.dev Batch Query API 로 조회한다.

    2단계 처리:
      Step A — querybatch: 취약 패키지 + vuln ID 목록 식별 (대량 배치)
      Step B — /vulns/{id}: 각 취약점의 CVSS·aliases·summary 상세 조회

    OSV Batch API 포맷:
      POST https://api.osv.dev/v1/querybatch
      {"queries": [{"package": {"name": "groupId:artifactId", "ecosystem": "Maven"}, "version": "x.y.z"}]}

    querybatch 응답은 {id, modified} 스텁만 포함하므로, CVSS 점수를 얻으려면
    Step B 에서 /vulns/{id} 를 개별 요청해야 한다.

    Returns:
        각 의존성별 OSV 취약점 결과 list.
        각 항목: {"dep": (gid, aid, ver), "vulns": [...full_osv_vuln...]}
    """
    results: list[dict] = []
    total = len(deps)

    # ── Step A: batch query — 취약 vuln ID 식별 ───────────────────
    # batch_size 단위로 청크 분할 (API 요청 크기 초과 방지)
    raw_hits: list[dict] = []  # {"dep": ..., "vuln_ids": [...]}
    for chunk_start in range(0, total, batch_size):
        chunk = deps[chunk_start: chunk_start + batch_size]
        chunk_end = min(chunk_start + batch_size, total)
        print(f"  [A] 취약 ID 식별 [{chunk_start + 1}~{chunk_end}/{total}]...")

        queries = [
            {
                "package": {
                    "name": f"{gid}:{aid}",
                    "ecosystem": "Maven",
                },
                "version": ver,
            }
            for gid, aid, ver in chunk
        ]

        response = _http_post_json(_OSV_BATCH_URL, {"queries": queries}, timeout=60)
        if not response:
            print(f"  ⚠️  청크 [{chunk_start}~{chunk_end}] OSV 응답 없음 — 스킵", file=sys.stderr)
            continue

        # 응답 순서는 queries 와 동일 보장
        for idx, result in enumerate(response.get("results", [])):
            vuln_stubs = result.get("vulns", [])
            if vuln_stubs:
                raw_hits.append({
                    "dep": chunk[idx],
                    "vuln_ids": [v["id"] for v in vuln_stubs],
                })

    if not raw_hits:
        return []

    # ── Step B: /vulns/{id} 개별 조회 — CVSS·aliases·summary 획득 ─
    # 중복 vuln ID 를 먼저 dedupe 하여 요청 수 최소화
    all_ids: set[str] = {vid for hit in raw_hits for vid in hit["vuln_ids"]}
    print(f"  [B] CVSS 상세 조회 (고유 vuln {len(all_ids)}건)...")

    vuln_cache: dict[str, dict] = {}
    for i, vid in enumerate(sorted(all_ids), 1):
        detail = _fetch_vuln_details(vid)
        if detail:
            vuln_cache[vid] = detail
        # 진행률 출력 (50건 단위)
        if i % 50 == 0:
            print(f"    {i}/{len(all_ids)} 완료...")

    # ── 결과 조립 ──────────────────────────────────────────────────
    for hit in raw_hits:
        full_vulns = [vuln_cache[vid] for vid in hit["vuln_ids"] if vid in vuln_cache]
        if full_vulns:
            results.append({"dep": hit["dep"], "vulns": full_vulns})

    return results


# ─────────────────────────────────────────────────────────────────
# npm(package-lock.json) 지원
# ─────────────────────────────────────────────────────────────────

def _detect_npm_lock(project_dir: Path) -> Optional[Path]:
    """프로젝트 루트에서 package-lock.json 경로를 반환한다(없으면 None)."""
    lock = project_dir / "package-lock.json"
    return lock if lock.exists() else None


def _parse_package_lock(lock_path: Path) -> set[tuple[str, str]]:
    """package-lock.json에서 (package_name, version) 집합을 추출한다.

    지원 포맷:
      - npm v7+ (lockfileVersion 2/3): 최상위 "packages" 객체 활용 (name/version 포함)
      - npm v6 (lockfileVersion 1): 최상위 "dependencies" 재귀 순회
    """
    try:
        data = json.loads(lock_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return set()

    deps: set[tuple[str, str]] = set()
    lock_ver = data.get("lockfileVersion")

    # npm v7+ : packages dict
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_path, info in packages.items():
            if not isinstance(info, dict):
                continue
            name = info.get("name")
            ver = info.get("version")
            if isinstance(ver, str) and ver:
                # npm v7+에서는 대부분 name 필드가 없고 key가
                # "node_modules/<pkg>" 또는 "node_modules/@scope/<pkg>" 형태다.
                if not isinstance(name, str) or not name:
                    if isinstance(pkg_path, str) and pkg_path.startswith("node_modules/"):
                        # "node_modules/" 다음 경로를 패키지명으로 복원
                        # 예: node_modules/lodash
                        # 예: node_modules/@types/node
                        rest = pkg_path[len("node_modules/"):]
                        if rest.startswith("@"):
                            parts = rest.split("/", 2)
                            if len(parts) >= 2:
                                name = parts[0] + "/" + parts[1]
                        else:
                            name = rest.split("/", 1)[0]
                if isinstance(name, str) and name:
                    deps.add((name, ver))
        # packages 기반이 있으면 여기서 종료 (정확도가 더 높음)
        if deps:
            return deps

    # npm v6 : dependencies dict 재귀
    def walk(dep_obj: dict) -> None:
        for name, info in (dep_obj or {}).items():
            if not isinstance(info, dict):
                continue
            ver = info.get("version")
            if isinstance(name, str) and isinstance(ver, str):
                deps.add((name, ver))
            nested = info.get("dependencies")
            if isinstance(nested, dict):
                walk(nested)

    if isinstance(data.get("dependencies"), dict):
        walk(data["dependencies"])

    return deps


def _query_osv_batch_npm(
    deps: list[tuple[str, str]],
    batch_size: int = _OSV_BATCH_SIZE,
) -> list[dict]:
    """npm 의존성 목록을 OSV.dev Batch Query API 로 조회한다.

    Returns:
        각 의존성별 OSV 취약점 결과 list.
        각 항목: {"dep": (name, ver), "vulns": [...full_osv_vuln...]}
    """
    results: list[dict] = []
    total = len(deps)

    raw_hits: list[dict] = []  # {"dep": ..., "vuln_ids": [...]}
    for chunk_start in range(0, total, batch_size):
        chunk = deps[chunk_start: chunk_start + batch_size]
        chunk_end = min(chunk_start + batch_size, total)
        print(f"  [A] 취약 ID 식별(npm) [{chunk_start + 1}~{chunk_end}/{total}]...")

        queries = [
            {"package": {"name": name, "ecosystem": "npm"}, "version": ver}
            for name, ver in chunk
        ]

        response = _http_post_json(_OSV_BATCH_URL, {"queries": queries}, timeout=60)
        if not response:
            print(f"  ⚠️  청크 [{chunk_start}~{chunk_end}] OSV 응답 없음 — 스킵", file=sys.stderr)
            continue

        for idx, result in enumerate(response.get("results", [])):
            vuln_stubs = result.get("vulns", [])
            if vuln_stubs:
                raw_hits.append({
                    "dep": chunk[idx],
                    "vuln_ids": [v["id"] for v in vuln_stubs],
                })

    if not raw_hits:
        return []

    all_ids: set[str] = {vid for hit in raw_hits for vid in hit["vuln_ids"]}
    print(f"  [B] CVSS 상세 조회 (고유 vuln {len(all_ids)}건)...")

    vuln_cache: dict[str, dict] = {}
    for i, vid in enumerate(sorted(all_ids), 1):
        detail = _fetch_vuln_details(vid)
        if detail:
            vuln_cache[vid] = detail
        if i % 50 == 0:
            print(f"    {i}/{len(all_ids)} 완료...")

    for hit in raw_hits:
        full_vulns = [vuln_cache[vid] for vid in hit["vuln_ids"] if vid in vuln_cache]
        if full_vulns:
            results.append({"dep": hit["dep"], "vulns": full_vulns})

    return results


def _build_findings_npm(
    osv_results: list[dict],
    kev_set: set[str],
    cvss_threshold: float,
) -> tuple[list[dict], dict]:
    """npm OSV 조회 결과 → findings 리스트 + summary 딕셔너리 구성."""
    findings: list[dict] = []
    summary = {"취약": 0, "정보": 0, "실제사용": 0, "간접사용": 0, "미확인": 0}

    for item in osv_results:
        name, ver = item["dep"]
        package_name = name

        for osv_vuln in item["vulns"]:
            info = _extract_vuln_info(osv_vuln, package_name)
            score = info["cvss_score"]
            cve = info["cve_id"]
            in_kev = cve in kev_set if cve else False

            if score >= cvss_threshold or in_kev:
                summary["취약"] += 1
                if in_kev:
                    summary["실제사용"] += 1
                findings.append({
                    "type":          info["severity"],
                    "package":       package_name,
                    "version":       ver,
                    "cve":           cve or info["osv_id"],
                    "cvss":          score,
                    "severity":      info["severity"],
                    "summary":       info["summary"],
                    "cvss_vector":   info["cvss_vector"],
                    "in_kev":        in_kev,
                    "osv_id":        info["osv_id"],
                    "status":        "취약",
                    "fixed_version": info["fixed_version"],
                })
            else:
                summary["정보"] += 1

    findings.sort(key=lambda f: f["cvss"], reverse=True)
    return findings, summary

# ─────────────────────────────────────────────────────────────────
# OSV 취약점 → CVE 정보 추출
# ─────────────────────────────────────────────────────────────────

def _extract_vuln_info(osv_vuln: dict, package_name: str = "") -> dict:
    """OSV 취약점 객체에서 CVE ID, CVSS 점수, 설명, fixed 버전을 추출한다.

    OSV severity 필드 구조:
      {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}]}
    CVSS 벡터 문자열을 직접 파싱하여 Base Score 를 계산한다.

    package_name 이 주어지면 affected 배열에서 fixed 버전도 추출한다.
    """
    osv_id = osv_vuln.get("id", "")
    summary = osv_vuln.get("summary", "")
    details = osv_vuln.get("details", "")

    # CVE ID 추출 (aliases 또는 id 직접)
    cve_id = ""
    for alias in osv_vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = alias
            break
    if not cve_id and osv_id.startswith("CVE-"):
        cve_id = osv_id

    # CVSS v3 벡터 탐색 → Base Score 계산
    cvss_score = 0.0
    cvss_vector = ""
    for sev in osv_vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            cvss_vector = sev.get("score", "")
            if cvss_vector:
                cvss_score = _cvss3_base_score(cvss_vector)
                break

    # CVSS 벡터가 없는 경우 database_specific 에서 fallback
    if cvss_score == 0.0:
        db_specific = osv_vuln.get("database_specific", {})
        # NVD, GitHub Advisory 등 다양한 키 시도
        for key in ("cvss_v3", "cvss", "cvss_score"):
            raw = db_specific.get(key)
            if isinstance(raw, (int, float)):
                cvss_score = float(raw)
                break
            if isinstance(raw, str) and raw.startswith("CVSS:"):
                cvss_score = _cvss3_base_score(raw)
                break

    # 마지막 fallback: database_specific.severity 텍스트 레이블 → 보수적 점수 매핑
    # CVSS v2만 있거나 벡터 파싱 불가한 경우 오탐 방지용 최솟값 부여
    if cvss_score == 0.0:
        label = (osv_vuln.get("database_specific", {}).get("severity") or "").upper()
        label_score_map = {"CRITICAL": 9.0, "HIGH": 7.0, "MODERATE": 5.0, "MEDIUM": 5.0, "LOW": 2.0}
        cvss_score = label_score_map.get(label, 0.0)

    fixed_version = _extract_fixed_version(osv_vuln, package_name) if package_name else ""

    return {
        "osv_id":        osv_id,
        "cve_id":        cve_id,
        "summary":       summary or details[:120],
        "cvss_score":    cvss_score,
        "cvss_vector":   cvss_vector,
        "severity":      _severity_label(cvss_score),
        "fixed_version": fixed_version,
    }


# ─────────────────────────────────────────────────────────────────
# CISA KEV (Known Exploited Vulnerabilities)
# ─────────────────────────────────────────────────────────────────

def _load_cisa_kev() -> set[str]:
    """CISA KEV 피드를 로드하고 CVE ID Set 을 반환한다. 실패 시 빈 Set."""
    print("  CISA KEV 피드 로드 중...")
    data = _http_get_json(_CISA_KEV_URL, timeout=20)
    if not data:
        print("  ⚠️  CISA KEV 로드 실패 — 스킵", file=sys.stderr)
        return set()
    kev_set = {v.get("cveID", "") for v in data.get("vulnerabilities", [])}
    print(f"  → KEV {len(kev_set)}건 로드 완료")
    return kev_set


# ─────────────────────────────────────────────────────────────────
# 분석 파이프라인
# ─────────────────────────────────────────────────────────────────

def _build_findings(
    osv_results: list[dict],
    kev_set: set[str],
    cvss_threshold: float,
) -> tuple[list[dict], dict]:
    """OSV 조회 결과 → findings 리스트 + summary 딕셔너리 구성.

    Returns:
        (findings, summary)
        findings: 각 (패키지, CVE) 조합 — CVSS threshold 이상만 포함
        summary: {'취약': N, '정보': N, ...}
    """
    findings: list[dict] = []
    summary = {"취약": 0, "정보": 0, "실제사용": 0, "간접사용": 0, "미확인": 0}

    for item in osv_results:
        gid, aid, ver = item["dep"]
        package_name = f"{gid}:{aid}"

        for osv_vuln in item["vulns"]:
            info = _extract_vuln_info(osv_vuln, package_name)
            score = info["cvss_score"]
            cve = info["cve_id"]
            in_kev = cve in kev_set if cve else False

            if score >= cvss_threshold or in_kev:
                # CVSS threshold 이상 또는 KEV 등재 → 취약 확정
                summary["취약"] += 1
                if in_kev:
                    summary["실제사용"] += 1
                finding = {
                    "type":          info["severity"],
                    "package":       package_name,
                    "version":       ver,
                    "cve":           cve or info["osv_id"],
                    "cvss":          score,
                    "severity":      info["severity"],
                    "summary":       info["summary"],
                    "cvss_vector":   info["cvss_vector"],
                    "in_kev":        in_kev,
                    "osv_id":        info["osv_id"],
                    "status":        "취약",
                    "fixed_version": info["fixed_version"],
                }
                findings.append(finding)
            else:
                # threshold 미만 → 정보성 기록
                summary["정보"] += 1

    # 심각도 내림차순 정렬
    findings.sort(key=lambda f: f["cvss"], reverse=True)
    return findings, summary


def _build_grouped(findings: list[dict]) -> list[dict]:
    """findings 를 패키지 단위로 그룹핑한다 (보고서 가독성용).

    각 패키지 항목에 recommended_version 필드를 추가한다.
    recommended_version: 해당 패키지의 모든 CVE fixed_version 중 최댓값.
    이 버전으로 업그레이드하면 식별된 CVE가 모두 패치된다.
    """
    pkg_map: dict[str, dict] = {}
    for f in findings:
        key = f"{f['package']}:{f['version']}"
        if key not in pkg_map:
            pkg_map[key] = {
                "package":             f["package"],
                "version":             f["version"],
                "max_cvss":            f["cvss"],
                "severity":            f["severity"],
                "cves":                [],
                "in_kev":              False,
                "recommended_version": "",
            }
        pkg_map[key]["cves"].append({
            "cve":           f["cve"],
            "cvss":          f["cvss"],
            "summary":       f["summary"],
            "in_kev":        f["in_kev"],
            "fixed_version": f.get("fixed_version", ""),
        })
        if f["in_kev"]:
            pkg_map[key]["in_kev"] = True
        if f["cvss"] > pkg_map[key]["max_cvss"]:
            pkg_map[key]["max_cvss"] = f["cvss"]
            pkg_map[key]["severity"] = f["severity"]

    # 패키지별 recommended_version: 모든 CVE fixed_version 중 최댓값
    for g in pkg_map.values():
        fixed_vers = [c["fixed_version"] for c in g["cves"] if c.get("fixed_version")]
        if fixed_vers:
            try:
                g["recommended_version"] = max(fixed_vers, key=_version_key)
            except Exception:
                g["recommended_version"] = fixed_vers[-1]

    return sorted(pkg_map.values(), key=lambda g: g["max_cvss"], reverse=True)


# ─────────────────────────────────────────────────────────────────
# auto_findings 생성 (표준 finding 스키마)
# ─────────────────────────────────────────────────────────────────

_SCA_FALLBACK_RECOMMENDATION = (
    "취약한 버전의 라이브러리를 보안 패치가 적용된 최신 버전으로 업그레이드하세요. "
    "업그레이드가 불가한 경우 해당 라이브러리의 취약 기능 사용을 제한하거나 "
    "WAF 룰로 완화 조치를 적용하세요."
)


def _build_recommendation(pkg: str, fixed_version: str, in_kev: bool) -> str:
    """라이브러리명과 fixed_version으로 구체적인 조치권고 문자열을 생성한다."""
    artifact = pkg.split(":")[-1] if ":" in pkg else pkg
    kev_note = " CISA KEV 등재 CVE이므로 즉시 조치가 필요합니다." if in_kev else ""
    if fixed_version:
        return (
            f"{artifact} {fixed_version} 이상으로 업그레이드하세요.{kev_note} "
            "업그레이드가 불가한 경우 해당 라이브러리의 취약 기능 사용을 제한하거나 "
            "WAF 룰로 완화 조치를 적용하세요."
        )
    return _SCA_FALLBACK_RECOMMENDATION + (" CISA KEV 등재 CVE이므로 즉시 조치가 필요합니다." if in_kev else "")


def _sca_finding_to_auto_finding(f: dict, seq: int) -> dict:
    """SCA finding item → 표준 finding object."""
    cve_id      = f.get("cve") or f.get("osv_id") or ""
    pkg         = f.get("package", "")
    ver         = f.get("version", "")
    cvss        = f.get("cvss", 0.0)
    fixed_ver   = f.get("fixed_version", "")
    in_kev      = f.get("in_kev", False)

    return {
        "finding_id":       f"SCA-AUTO-{seq:03d}",
        "title":            f"취약 오픈소스 라이브러리 — {pkg} {ver} ({cve_id})",
        "severity":         f.get("severity", "High"),
        "category":         "SCA/CVE",
        "cwe_id":           "CWE-1395",
        "result":           "취약",
        "diagnosis_method": "auto-scan",
        "source":           "auto-scan",
        "fn_detected":      False,
        "scope": {
            "type":       "dependency",
            "endpoint":   None,
            "file":       None,
            "line":       None,
            "module":     None,
            "package":    pkg,
            "version":    ver,
        },
        "description": (
            f"{cve_id} — {f.get('summary', '')} "
            f"(CVSS {cvss:.1f}"
            + (" / CISA KEV 등재" if in_kev else "")
            + ")"
        ),
        "recommendation": _build_recommendation(pkg, fixed_ver, in_kev),
        "code_snippet":   "",
        "evidence":       [{
            "cve":           cve_id,
            "cvss":          cvss,
            "cvss_vector":   f.get("cvss_vector", ""),
            "osv_id":        f.get("osv_id", ""),
            "in_kev":        in_kev,
            "fixed_version": fixed_ver,
        }],
        "needs_review":   False,
    }


def _build_sca_auto_findings(findings: list[dict]) -> list[dict]:
    """SCA findings 리스트 → auto_findings[]."""
    return [_sca_finding_to_auto_finding(f, i + 1) for i, f in enumerate(findings)]


# ─────────────────────────────────────────────────────────────────
# 출력 스키마 빌더 (publish_confluence.py 호환)
# ─────────────────────────────────────────────────────────────────

def _build_output(
    source_dir: str,
    project_name: str,
    job_id: str,
    total_deps: int,
    deps_with_vuln: int,
    total_cve: int,
    kev_count: int,
    cvss_threshold: float,
    findings: list[dict],
    summary: dict,
) -> dict:
    """기존 scan_sca.py 출력 스키마와 호환되는 결과 딕셔너리를 생성한다."""
    auto_findings = _build_sca_auto_findings(findings)
    return {
        "task_id":     "sca",
        "source_tool": "SCA-GradleTree",
        "metadata": {
            "source_dir":               source_dir,
            "scan_method":              "gradle_dependency_tree",
            "project_name":             project_name,
            "job_id":                   job_id,
            "scanned_at":               datetime.now().isoformat(),
            "cvss_threshold":           cvss_threshold,
            "total_dependencies":       total_deps,
            "total_dependencies_with_vuln": deps_with_vuln,
            "total_cve":                total_cve,
            "high_critical_cve":        sum(1 for f in findings if f["cvss"] >= cvss_threshold),
            "kev_count":                kev_count,
        },
        "summary": {
            **summary,
            "auto_findings_count": len(auto_findings),
            "evidence_trail_count": 0,  # SCA는 threshold 미만 CVE를 findings에서 제외하므로 trail 없음
        },
        "findings":      findings,
        "grouped":       _build_grouped(findings),
        "auto_findings": auto_findings,
        "evidence_trail": [],
    }


# ─────────────────────────────────────────────────────────────────
# LLM 요약본 생성
# ─────────────────────────────────────────────────────────────────

def _write_llm_summary(output_data: dict, out_path: "Path") -> None:
    """Phase 2 완료 후 LLM용 초경량 요약본을 _llm_summary.json으로 저장."""
    import json as _json
    meta = output_data.get("scan_metadata", {})
    summary = output_data.get("summary", {})
    findings = output_data.get("findings", [])

    # 심각도별 샘플 최대 2건 추출 (CVSS 내림차순 정렬된 상태)
    samples: dict = {}
    for f in findings:
        sev = f.get("severity", "Unknown")
        if sev not in samples:
            samples[sev] = []
        if len(samples[sev]) < 2:
            samples[sev].append({
                "package": f.get("package", ""),
                "version": f.get("version", ""),
                "cve": f.get("cve", ""),
                "cvss": f.get("cvss", 0),
                "in_kev": f.get("in_kev", False),
                "brief": (f.get("summary") or "")[:120],
            })

    llm_summary = {
        "scan_type": "sca",
        "generated_at": meta.get("scanned_at", ""),
        "full_result_path": str(out_path.resolve()),
        "statistics": {
            "total_dependencies": meta.get("total_dependencies", 0),
            "total_dependencies_with_vuln": meta.get("total_dependencies_with_vuln", 0),
            "total_cve": meta.get("total_cve", 0),
            "high_critical_cve": meta.get("high_critical_cve", 0),
            "kev_count": meta.get("kev_count", 0),
            "by_severity": summary,
        },
        "samples_by_severity": samples,
    }

    summary_path = out_path.with_name(out_path.stem + "_llm_summary.json")
    summary_path.write_text(_json.dumps(llm_summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"LLM 요약본 저장: {summary_path}")


# ─────────────────────────────────────────────────────────────────
# P0: gradle-wrapper.jar 자동 복구
# ─────────────────────────────────────────────────────────────────

def _recover_gradle_wrapper_jar(project_dir: Path) -> bool:
    """gradle-wrapper.jar 누락 시 복구한다.

    복구 우선순위:
    1. `gradle wrapper` 명령 (시스템 gradle 있을 때)
    2. GitHub raw에서 wrapper JAR 직접 다운로드
    """
    import urllib.request

    wrapper_jar = project_dir / "gradle" / "wrapper" / "gradle-wrapper.jar"
    if wrapper_jar.exists():
        return True

    props_file = project_dir / "gradle" / "wrapper" / "gradle-wrapper.properties"
    gradle_version: Optional[str] = None
    if props_file.exists():
        for line in props_file.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.search(r"distributionUrl=.*gradle-([0-9]+\.[0-9]+(?:\.[0-9]+)?)-", line)
            if m:
                gradle_version = m.group(1)
                break

    if not gradle_version:
        print("  ⚠️  [P0] gradle-wrapper.properties에서 버전 확인 불가 — wrapper 복구 스킵", file=sys.stderr)
        return False

    print(f"  [P0] gradle-wrapper.jar 누락 감지 (gradle {gradle_version}) — 복구 시도")

    # 방법 1: 시스템 gradle 명령
    try:
        result = subprocess.run(
            ["gradle", "wrapper", f"--gradle-version={gradle_version}"],
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if wrapper_jar.exists():
            print(f"  [P0] gradle-wrapper.jar 복구 완료 (gradle wrapper 명령)")
            return True
    except FileNotFoundError:
        pass  # gradle 바이너리 없음 → 방법 2로
    except subprocess.TimeoutExpired:
        print("  ⚠️  [P0] gradle wrapper 명령 타임아웃", file=sys.stderr)

    # 방법 2: GitHub raw에서 직접 다운로드
    jar_url = (
        f"https://raw.githubusercontent.com/gradle/gradle"
        f"/v{gradle_version}/gradle/wrapper/gradle-wrapper.jar"
    )
    print(f"  [P0] GitHub에서 직접 다운로드: {jar_url}")
    try:
        wrapper_jar.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(jar_url, timeout=60) as resp:
            wrapper_jar.write_bytes(resp.read())
        if wrapper_jar.exists() and wrapper_jar.stat().st_size > 1024:
            print(f"  [P0] gradle-wrapper.jar 다운로드 완료 ({wrapper_jar.stat().st_size // 1024} KB)")
            return True
        wrapper_jar.unlink(missing_ok=True)
        print("  ⚠️  [P0] 다운로드 파일 크기 비정상 — 복구 실패", file=sys.stderr)
        return False
    except Exception as e:
        print(f"  ⚠️  [P0] wrapper JAR 다운로드 실패: {e}", file=sys.stderr)
        return False


# ─────────────────────────────────────────────────────────────────
# P3: Ant/JAR 스캔 지원 (WEB-INF/lib, lib 폴더 내 JAR 직접 분석)
# ─────────────────────────────────────────────────────────────────

def _detect_ant(project_dir: Path) -> Optional[Path]:
    """build.xml 이 존재하고 pom.xml / gradlew 가 없으면 Ant 프로젝트로 판단."""
    build_xml = project_dir / "build.xml"
    if not build_xml.exists():
        return None
    if (project_dir / "pom.xml").exists():
        return None
    if (project_dir / "gradlew").exists() or (project_dir / "gradlew.bat").exists():
        return None
    return build_xml


def _jar_maven_coords(jar_path: Path) -> Optional[tuple[str, str, str]]:
    """JAR 내 META-INF/maven/*/pom.properties 에서 Maven coordinates 추출."""
    try:
        with zipfile.ZipFile(jar_path, "r") as z:
            for name in z.namelist():
                if name.startswith("META-INF/maven/") and name.endswith("pom.properties"):
                    props: dict[str, str] = {}
                    for line in z.read(name).decode("utf-8", errors="ignore").splitlines():
                        if "=" in line and not line.startswith("#"):
                            k, _, v = line.partition("=")
                            props[k.strip()] = v.strip()
                    g = props.get("groupId", "").strip()
                    a = props.get("artifactId", "").strip()
                    v = props.get("version", "").strip()
                    if g and a and v:
                        return (g, a, v)
    except Exception:
        pass
    return None


def _scan_jar_libs(project_dir: Path) -> set[tuple[str, str, str]]:
    """WEB-INF/lib, lib 폴더 내 JAR 파일에서 Maven coordinates 추출."""
    search_dirs = [
        project_dir / "WebContent" / "WEB-INF" / "lib",
        project_dir / "WEB-INF" / "lib",
        project_dir / "lib",
        project_dir / "libs",
    ]
    coords: set[tuple[str, str, str]] = set()
    skipped: list[str] = []

    for lib_dir in search_dirs:
        if not lib_dir.is_dir():
            continue
        for jar in sorted(lib_dir.glob("*.jar")):
            result = _jar_maven_coords(jar)
            if result:
                coords.add(result)
            else:
                skipped.append(jar.name)

    if skipped:
        print(f"  [prep] Maven metadata 없음 (커스텀 JAR, OSV 조회 생략): {len(skipped)}건")
        for name in skipped[:10]:
            print(f"    - {name}")
        if len(skipped) > 10:
            print(f"    ... 외 {len(skipped) - 10}건")

    return coords


# ─────────────────────────────────────────────────────────────────
# P2: Maven 지원 (mvnw / pom.xml 직접 파싱 fallback)
# ─────────────────────────────────────────────────────────────────

def _has_gradle_build(project_dir: Path) -> bool:
    """build.gradle / build.gradle.kts / gradlew 중 하나라도 존재하면 True."""
    return any(
        (project_dir / name).exists()
        for name in ("build.gradle", "build.gradle.kts", "gradlew", "gradlew.bat")
    )


def _detect_maven(project_dir: Path) -> Optional[Path]:
    """pom.xml + mvnw/mvnw.cmd 존재 시 mvnw 경로 반환.
    build.gradle 이 함께 존재하는 경우 Gradle 우선 — None 반환."""
    if not (project_dir / "pom.xml").exists():
        return None
    if _has_gradle_build(project_dir):
        return None  # Gradle 프로젝트가 배포용 pom.xml 을 함께 보유하는 경우
    for name in ("mvnw", "mvnw.cmd"):
        candidate = project_dir / name
        if candidate.exists():
            return candidate
    return None


def _detect_pom_only(project_dir: Path) -> bool:
    """mvnw 없이 pom.xml만 존재하는 경우 True.
    build.gradle 이 함께 존재하면 Gradle 프로젝트로 간주 — False 반환."""
    if _has_gradle_build(project_dir):
        return False
    return (project_dir / "pom.xml").exists() and _detect_maven(project_dir) is None


def _fix_mvnw_crlf(mvnw: Path) -> None:
    """mvnw CRLF → LF 변환 (Windows clone 대응)."""
    try:
        raw = mvnw.read_bytes()
        if b"\r" in raw:
            mvnw.write_bytes(raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n"))
            print("  [prep] mvnw: CRLF → LF 변환 완료")
    except Exception:
        pass


_KNOWN_PRIVATE_GROUP_IDS = {
    "com.oracle",
    "com.oracle.ojdbc",
    "com.oracle.database",
    "com.oracle.database.nls",
    "com.ibm.db2",
    "com.microsoft.sqlserver",
}


def _fix_pom_xml_repos(project_dir: Path) -> None:
    """pom.xml 의 Nexus-only <repositories>/<pluginRepositories> 블록을 Maven Central 로 교체하고
    Maven Central 미등재 비공개 의존성(Oracle JDBC 등)을 provided scope 로 변경한다."""
    nexus_re = re.compile(r"nexus", re.IGNORECASE)

    for pom_file in project_dir.rglob("pom.xml"):
        try:
            text = pom_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        original = text

        # 1. <repositories> / <pluginRepositories> Nexus → Maven Central
        repos_block_re = re.compile(r"<repositories>.*?</repositories>", re.DOTALL)
        def _replace_repos(m: re.Match) -> str:
            if nexus_re.search(m.group(0)):
                return (
                    "<repositories>\n"
                    "        <repository>\n"
                    "            <id>central</id>\n"
                    "            <url>https://repo.maven.apache.org/maven2</url>\n"
                    "        </repository>\n"
                    "    </repositories>"
                )
            return m.group(0)
        text = repos_block_re.sub(_replace_repos, text)

        plugin_repos_re = re.compile(r"<pluginRepositories>.*?</pluginRepositories>", re.DOTALL)
        def _replace_plugin_repos(m: re.Match) -> str:
            if nexus_re.search(m.group(0)):
                return (
                    "<pluginRepositories>\n"
                    "        <pluginRepository>\n"
                    "            <id>central</id>\n"
                    "            <url>https://repo.maven.apache.org/maven2</url>\n"
                    "        </pluginRepository>\n"
                    "    </pluginRepositories>"
                )
            return m.group(0)
        text = plugin_repos_re.sub(_replace_plugin_repos, text)

        # 2. Maven Central 미등재 비공개 의존성 블록 제거 (provided scope도 Maven이 resolution 시도)
        #    com.oracle:ojdbc6 등 독점 드라이버는 OSV.dev에 등재 안 되므로 SCA 목적상 제거해도 무방
        dep_block_re = re.compile(r"\s*<dependency>.*?</dependency>", re.DOTALL)
        def _remove_private_dep(m: re.Match) -> str:
            block = m.group(0)
            # XML 주석 안의 블록은 건너뜀 (<!-- ... --> 안에 있으면 패턴 불일치하므로 안전)
            gid_m = re.search(r"<groupId>\s*([^<]+)\s*</groupId>", block)
            if not gid_m:
                return block
            gid = gid_m.group(1).strip()
            if gid not in _KNOWN_PRIVATE_GROUP_IDS:
                return block
            # 이미 system scope(local JAR 직접 참조)면 건드리지 않음
            scope_m = re.search(r"<scope>\s*([^<]+)\s*</scope>", block)
            if scope_m and scope_m.group(1).strip() == "system":
                return block
            aid_m = re.search(r"<artifactId>\s*([^<]+)\s*</artifactId>", block)
            aid = aid_m.group(1).strip() if aid_m else "?"
            print(f"  [prep] {pom_file.name}: {gid}:{aid} 제거 (Maven Central 미등재, SCA 대상 아님)")
            return ""
        text = dep_block_re.sub(_remove_private_dep, text)

        if text != original:
            pom_file.write_text(text, encoding="utf-8")
            if nexus_re.search(original):
                print(f"  [prep] {pom_file.name}: repositories Nexus → Maven Central")


# Maven dependency:tree 출력 파싱 정규식
# [INFO] +- groupId:artifactId:type:version:scope
# [INFO] |  \- groupId:artifactId:type:version:scope
_MAVEN_DEP_RE = re.compile(
    r"\[INFO\]\s+[+\\ |`-]+\s+"
    r"([A-Za-z0-9._\-]+)"   # groupId
    r":([A-Za-z0-9._\-]+)"  # artifactId
    r":[A-Za-z0-9._\-]+"    # type (jar, war, ...)
    r":([A-Za-z0-9._\-]+)"  # version
    r":[A-Za-z0-9._\-]+"    # scope
)


def _parse_maven_dep_tree(output: str) -> set[tuple[str, str, str]]:
    """Maven dependency:tree 출력 파싱 → (groupId, artifactId, version) Set."""
    deps: set[tuple[str, str, str]] = set()
    for line in output.splitlines():
        m = _MAVEN_DEP_RE.search(line)
        if m:
            deps.add((m.group(1), m.group(2), m.group(3)))
    return deps


def _run_maven_dep_tree(project_dir: Path, mvnw: Path, timeout: int = 300) -> Optional[str]:
    """./mvnw dependency:tree 실행 → stdout+stderr 반환. 실패 시 None."""
    _fix_mvnw_crlf(mvnw)
    _fix_pom_xml_repos(project_dir)
    try:
        os.chmod(mvnw, 0o755)
    except Exception:
        pass

    cmd = [str(mvnw), "dependency:tree", "-DoutputType=text", "--batch-mode", "--no-transfer-progress"]
    print(f"  실행: mvnw dependency:tree ...")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(project_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        combined = proc.stdout + proc.stderr
        if proc.returncode != 0:
            print(f"  ⚠️  mvnw 비정상 종료 (rc={proc.returncode})", file=sys.stderr)
            for line in proc.stderr.strip().splitlines()[:5]:
                print(f"     {line}", file=sys.stderr)
        return combined if combined.strip() else None
    except subprocess.TimeoutExpired:
        print(f"  ❌ mvnw 타임아웃 ({timeout}초)", file=sys.stderr)
        return None
    except FileNotFoundError as e:
        print(f"  ❌ mvnw 실행 불가: {e}", file=sys.stderr)
        return None


def _parse_pom_xml_deps(project_dir: Path) -> set[tuple[str, str, str]]:
    """pom.xml 직접 파싱 — 명시적 버전이 있는 의존성만 추출 (mvnw 실패 시 fallback)."""
    import xml.etree.ElementTree as ET
    pom = project_dir / "pom.xml"
    if not pom.exists():
        return set()
    try:
        root = ET.parse(str(pom)).getroot()
    except Exception as e:
        print(f"  ⚠️  pom.xml 파싱 실패: {e}", file=sys.stderr)
        return set()

    ns_prefix = ""
    if root.tag.startswith("{"):
        ns_prefix = root.tag.split("}")[0] + "}"

    def t(name: str) -> str:
        return f"{ns_prefix}{name}"

    # <properties> 에서 버전 변수 추출
    props: dict[str, str] = {}
    props_el = root.find(t("properties"))
    if props_el is not None:
        for child in props_el:
            tag = child.tag.replace(ns_prefix, "")
            if child.text and not child.text.startswith("${"):
                props[f"${{{tag}}}"] = child.text.strip()

    # dependencyManagement 버전 맵
    version_map: dict[tuple[str, str], str] = {}
    dm = root.find(f".//{t('dependencyManagement')}/{t('dependencies')}")
    if dm is not None:
        for dep in dm.findall(t("dependency")):
            gid = (dep.findtext(t("groupId")) or "").strip()
            aid = (dep.findtext(t("artifactId")) or "").strip()
            ver = (dep.findtext(t("version")) or "").strip()
            ver = props.get(ver, ver)
            if gid and aid and ver and not ver.startswith("${"):
                version_map[(gid, aid)] = ver

    deps: set[tuple[str, str, str]] = set()
    for dep in root.findall(f".//{t('dependencies')}/{t('dependency')}"):
        gid = (dep.findtext(t("groupId")) or "").strip()
        aid = (dep.findtext(t("artifactId")) or "").strip()
        ver = (dep.findtext(t("version")) or "").strip()
        scope = (dep.findtext(t("scope")) or "compile").strip().lower()
        if scope == "test":
            continue
        if not gid or not aid:
            continue
        ver = props.get(ver, ver)
        if not ver or ver.startswith("${"):
            ver = version_map.get((gid, aid), "")
        if not ver or ver.startswith("${"):
            continue  # 버전 불명 — 스킵
        deps.add((gid, aid, ver))
    return deps


# ─────────────────────────────────────────────────────────────────
# 메인 파이프라인
# ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gradle Transitive Dependency SCA (OSV.dev 연동)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("source_dir", type=Path, help="Gradle 프로젝트 루트 디렉토리")
    parser.add_argument("--project",       required=True, help="프로젝트 이름 (출력 메타데이터용)")
    parser.add_argument("--output",        required=True, type=Path, help="결과 JSON 출력 경로")
    parser.add_argument("--subproject",    default="",   help="특정 서브프로젝트 경로 (예: :cms_resource)")
    parser.add_argument("--all-subprojects", action="store_true",
                        help="모든 서브프로젝트를 탐색하여 합산 (대형 멀티모듈 프로젝트)")
    parser.add_argument("--configuration", default=_DEFAULT_CONFIGURATION,
                        help=f"Gradle 의존성 configuration (기본: {_DEFAULT_CONFIGURATION})")
    parser.add_argument("--cvss-threshold", type=float, default=_DEFAULT_CVSS_THRESHOLD,
                        help=f"CVSS 점수 필터 기준 (기본: {_DEFAULT_CVSS_THRESHOLD})")
    parser.add_argument("--java-home",       default=None,
                        help="JDK 홈 경로 (예: /mnt/c/Program Files/Java/jdk-17)")
    parser.add_argument("--auto-install-jdk", action="store_true",
                        help="JDK 미설치 시 자동 설치 (apt → Temurin 직접 다운로드 순으로 시도)")
    parser.add_argument("--gradle-timeout", type=int, default=600,
                        help="gradlew 실행 타임아웃 (초, 기본: 600)")
    parser.add_argument("--no-kev", action="store_true",
                        help="CISA KEV 조회 생략")
    args = parser.parse_args()

    # ── 사전 검증 ──────────────────────────────────────────────────
    source_dir: Path = args.source_dir.resolve()
    if not source_dir.is_dir():
        print(f"❌ 소스 디렉토리가 존재하지 않음: {source_dir}", file=sys.stderr)
        sys.exit(1)

    # npm 프로젝트(package-lock.json)면 gradlew 없이 npm SCA로 전환
    npm_lock = _detect_npm_lock(source_dir)
    if npm_lock:
        print(f"\n=== scan_sca_gradle_tree.py — npm SCA 분석 ===")
        print(f"소스: {source_dir}")
        print(f"lock: {npm_lock}")

        job_id = str(uuid.uuid4())
        print(f"JobID: {job_id[:8]}")

        print("\n[Step 1] package-lock.json 의존성 추출 중...")
        npm_deps = sorted(_parse_package_lock(npm_lock))
        if not npm_deps:
            print("  ❌ package-lock.json에서 파싱된 항목 없음.", file=sys.stderr)
            sys.exit(1)
        print(f"  → 전체 의존성: {len(npm_deps)}건")

        print("\n[Step 2] OSV.dev 취약점 조회 중...")
        osv_results = _query_osv_batch_npm(npm_deps, batch_size=_OSV_BATCH_SIZE)
        deps_with_vuln = len(osv_results)
        total_cve = sum(len(r["vulns"]) for r in osv_results)
        print(f"  → 취약 패키지: {deps_with_vuln}건, 총 CVE: {total_cve}건")

        kev_set: set[str] = set()
        if not args.no_kev:
            print("\n[Step 3] CISA KEV 조회 중...")
            kev_set = _load_cisa_kev()

        print(f"\n[Step 4] findings 생성 (CVSS ≥ {args.cvss_threshold})...")
        findings, summary = _build_findings_npm(osv_results, kev_set, args.cvss_threshold)
        kev_count = sum(1 for f in findings if f["in_kev"])

        print(f"\n[결과 요약]")
        print(f"  전체 의존성:    {len(npm_deps)}건")
        print(f"  취약 패키지:    {deps_with_vuln}건")
        print(f"  전체 CVE:       {total_cve}건")
        print(f"  High/Critical:  {summary['취약']}건 (CVSS ≥ {args.cvss_threshold})")
        print(f"  CISA KEV 등재:  {kev_count}건")

        # Gradle과 동일 스키마로 저장(단, scan_method만 npm으로 표시)
        output_data = _build_output(
            source_dir=str(source_dir),
            project_name=args.project,
            job_id=job_id,
            total_deps=len(npm_deps),
            deps_with_vuln=deps_with_vuln,
            total_cve=total_cve,
            kev_count=kev_count,
            cvss_threshold=args.cvss_threshold,
            findings=findings,
            summary=summary,
        )
        output_data["source_tool"] = "SCA-NPM-PackageLock"
        output_data.setdefault("metadata", {})
        output_data["metadata"]["scan_method"] = "npm_package_lock"

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(output_data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n결과 저장: {args.output}")
        _write_llm_summary(output_data, args.output)
        return

    # Maven 프로젝트(pom.xml) → Maven SCA로 전환
    mvnw = _detect_maven(source_dir)
    pom_only = _detect_pom_only(source_dir)
    if mvnw is not None or pom_only:
        print(f"\n=== scan_sca_gradle_tree.py — Maven SCA 분석 ===")
        print(f"소스: {source_dir}")
        if mvnw:
            print(f"mvnw: {mvnw}")
        else:
            print("mvnw: 없음 — pom.xml 직접 파싱으로 진행")

        job_id = str(uuid.uuid4())
        print(f"JobID: {job_id[:8]}")

        maven_deps: set[tuple[str, str, str]] = set()

        if mvnw is not None:
            print("\n[Step 1] Maven 의존성 트리 추출 중...")
            maven_output = _run_maven_dep_tree(source_dir, mvnw, timeout=args.gradle_timeout)
            if maven_output:
                maven_deps = _parse_maven_dep_tree(maven_output)
                print(f"  → mvnw 실행 완료, 의존성: {len(maven_deps)}건 (전이 포함)")
            if not maven_deps:
                print("  ⚠️  mvnw dep tree 파싱 결과 없음 → pom.xml 직접 파싱으로 fallback")

        if not maven_deps:
            print("\n[Step 1] pom.xml 직접 파싱 중...")
            maven_deps = _parse_pom_xml_deps(source_dir)
            print(f"  → pom.xml 직접 파싱: {len(maven_deps)}건 (직접 의존성, 명시 버전만)")

        if not maven_deps:
            print("  ❌ Maven 의존성 파싱 실패 — 명시적 버전이 있는 의존성이 없습니다.", file=sys.stderr)
            sys.exit(1)

        print("\n[Step 2] OSV.dev 취약점 조회 중...")
        maven_osv = _query_osv_batch(sorted(maven_deps), batch_size=_OSV_BATCH_SIZE)
        maven_vuln_count = len(maven_osv)
        maven_cve_count = sum(len(r["vulns"]) for r in maven_osv)
        print(f"  → 취약 패키지: {maven_vuln_count}건, 총 CVE: {maven_cve_count}건")

        kev_set_mv: set[str] = set()
        if not args.no_kev:
            print("\n[Step 3] CISA KEV 조회 중...")
            kev_set_mv = _load_cisa_kev()

        print(f"\n[Step 4] findings 생성 (CVSS ≥ {args.cvss_threshold})...")
        maven_findings, maven_summary = _build_findings(maven_osv, kev_set_mv, args.cvss_threshold)
        maven_kev_count = sum(1 for f in maven_findings if f["in_kev"])

        print(f"\n[결과 요약]")
        print(f"  전체 의존성:    {len(maven_deps)}건")
        print(f"  취약 패키지:    {maven_vuln_count}건")
        print(f"  전체 CVE:       {maven_cve_count}건")
        print(f"  High/Critical:  {maven_summary['취약']}건 (CVSS ≥ {args.cvss_threshold})")
        print(f"  CISA KEV 등재:  {maven_kev_count}건")

        maven_output_data = _build_output(
            source_dir=str(source_dir),
            project_name=args.project,
            job_id=job_id,
            total_deps=len(maven_deps),
            deps_with_vuln=maven_vuln_count,
            total_cve=maven_cve_count,
            kev_count=maven_kev_count,
            cvss_threshold=args.cvss_threshold,
            findings=maven_findings,
            summary=maven_summary,
        )
        scan_method = "maven_mvnw" if mvnw is not None else "maven_pom_xml"
        maven_output_data["source_tool"] = "SCA-Maven"
        maven_output_data.setdefault("metadata", {})
        maven_output_data["metadata"]["scan_method"] = scan_method

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(maven_output_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"\n결과 저장: {args.output}")
        _write_llm_summary(maven_output_data, args.output)
        return

    # P3: Ant 프로젝트 — WEB-INF/lib JAR 직접 스캔
    ant_build_xml = _detect_ant(source_dir)
    if ant_build_xml:
        print(f"\n=== scan_sca_gradle_tree.py — Ant/JAR SCA 분석 ===")
        print(f"소스: {source_dir}")
        print(f"build.xml: {ant_build_xml}")

        job_id = str(uuid.uuid4())
        print(f"JobID: {job_id[:8]}")

        print("\n[Step 1] JAR 라이브러리 Maven coordinates 추출 중...")
        ant_deps = _scan_jar_libs(source_dir)
        print(f"  → Maven metadata 확인된 의존성: {len(ant_deps)}건")

        if not ant_deps:
            print("  ❌ Maven metadata가 있는 JAR 없음 — SCA 불가", file=sys.stderr)
            sys.exit(1)

        print("\n[Step 2] OSV.dev 취약점 조회 중...")
        ant_osv = _query_osv_batch(sorted(ant_deps), batch_size=_OSV_BATCH_SIZE)
        ant_vuln_count = len(ant_osv)
        ant_cve_count = sum(len(r["vulns"]) for r in ant_osv)
        print(f"  → 취약 패키지: {ant_vuln_count}건, 총 CVE: {ant_cve_count}건")

        kev_set_ant: set[str] = set()
        if not args.no_kev:
            print("\n[Step 3] CISA KEV 조회 중...")
            kev_set_ant = _load_cisa_kev()

        print(f"\n[Step 4] findings 생성 (CVSS ≥ {args.cvss_threshold})...")
        ant_findings, ant_summary = _build_findings(ant_osv, kev_set_ant, args.cvss_threshold)
        ant_kev_count = sum(1 for f in ant_findings if f["in_kev"])

        print(f"\n[결과 요약]")
        print(f"  전체 의존성:    {len(ant_deps)}건")
        print(f"  취약 패키지:    {ant_vuln_count}건")
        print(f"  전체 CVE:       {ant_cve_count}건")
        print(f"  High/Critical:  {ant_summary['취약']}건 (CVSS ≥ {args.cvss_threshold})")
        print(f"  CISA KEV 등재:  {ant_kev_count}건")

        ant_output_data = _build_output(
            source_dir=str(source_dir),
            project_name=args.project,
            job_id=job_id,
            total_deps=len(ant_deps),
            deps_with_vuln=ant_vuln_count,
            total_cve=ant_cve_count,
            kev_count=ant_kev_count,
            cvss_threshold=args.cvss_threshold,
            findings=ant_findings,
            summary=ant_summary,
        )
        ant_output_data["source_tool"] = "SCA-Ant"
        ant_output_data.setdefault("metadata", {})
        ant_output_data["metadata"]["scan_method"] = "ant_jar_scan"

        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(ant_output_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"\n결과 저장: {args.output}")
        _write_llm_summary(ant_output_data, args.output)
        return

    # Gradle 프로젝트(기존 동작)
    gradlew = _find_gradlew(source_dir)
    if not gradlew:
        print(f"❌ gradlew 를 찾을 수 없음: {source_dir}", file=sys.stderr)
        print("   npm, Maven(pom.xml), Gradle(gradlew), Ant(build.xml) 어느 것도 감지되지 않았습니다.", file=sys.stderr)
        sys.exit(1)

    # P0: gradle-wrapper.jar 누락 시 자동 복구
    _recover_gradle_wrapper_jar(source_dir)

    _prepare_gradle_env(source_dir)

    java_path = _ensure_java(
        java_home_override=args.java_home,
        auto_install=args.auto_install_jdk,
    )
    if not java_path:
        sys.exit(1)

    print(f"\n=== scan_sca_gradle_tree.py — Gradle SCA 분석 ===")
    print(f"소스: {source_dir}")
    print(f"JDK:  {java_path}")

    # ── UUID 격리 Job ID 생성 ───────────────────────────────────────
    # 동일 서버에서 여러 레포지토리를 병렬 스캔할 때 Gradle 캐시 및
    # 임시 파일 경로가 충돌하지 않도록 UUID 기반 격리 경로를 사용한다.
    job_id = str(uuid.uuid4())
    print(f"JobID: {job_id[:8]} (격리 캐시: /tmp/sca_{job_id[:8]}...)")

    # ── Step 1: 의존성 트리 추출 ───────────────────────────────────
    print("\n[Step 1] Gradle 의존성 트리 추출 중...")

    all_deps: set[tuple[str, str, str]] = set()

    if args.all_subprojects:
        # 멀티모듈: 모든 서브프로젝트 탐색
        subprojects = _list_subprojects(source_dir, gradlew, java_path, job_id)
        if not subprojects:
            print("  ⚠️  서브프로젝트 목록 조회 실패 — 루트 프로젝트만 스캔")
            subprojects = [""]
        else:
            print(f"  → 서브프로젝트 {len(subprojects)}개 탐지됨")
            # 루트도 포함 (root-level 의존성 대비)
            subprojects = [""] + subprojects

        for sp in subprojects:
            task = f"{sp}:dependencies" if sp else "dependencies"
            gradle_args = [task, f"--configuration={args.configuration}"]
            output = _run_gradle(source_dir, gradlew, gradle_args, java_path, job_id, args.gradle_timeout)
            if output:
                parsed = _parse_dependency_tree(output)
                before = len(all_deps)
                all_deps.update(parsed)
                print(f"  {sp or '(root)'}: +{len(all_deps) - before}건 신규 (누적 {len(all_deps)}건)")
    else:
        # 단일 모듈 또는 지정 서브프로젝트
        sp = args.subproject.strip()
        task = f"{sp}:dependencies" if sp else "dependencies"
        gradle_args = [task, f"--configuration={args.configuration}"]
        output = _run_gradle(source_dir, gradlew, gradle_args, java_path, job_id, args.gradle_timeout)
        if output:
            all_deps = _parse_dependency_tree(output)

    if not all_deps:
        print("  ❌ 의존성 트리에서 파싱된 항목 없음.")
        print("     - gradlew 실행 로그 확인 (JDK 버전 호환성, Nexus 접근 가능 여부)")
        sys.exit(1)

    print(f"  → 전체 의존성: {len(all_deps)}건 (직접 + 전이적 포함)")

    # ── Step 2: OSV.dev Batch Query ────────────────────────────────
    print("\n[Step 2] OSV.dev 취약점 조회 중...")
    deps_list = sorted(all_deps)  # 정렬로 배치 순서 안정화
    osv_results = _query_osv_batch(deps_list, batch_size=_OSV_BATCH_SIZE)
    deps_with_vuln = len(osv_results)
    total_cve = sum(len(r["vulns"]) for r in osv_results)
    print(f"  → 취약 패키지: {deps_with_vuln}건, 총 CVE: {total_cve}건")

    # ── Step 3: CISA KEV 조회 ──────────────────────────────────────
    kev_set: set[str] = set()
    if not args.no_kev:
        print("\n[Step 3] CISA KEV 조회 중...")
        kev_set = _load_cisa_kev()

    # ── Step 4: findings 생성 ──────────────────────────────────────
    print(f"\n[Step 4] findings 생성 (CVSS ≥ {args.cvss_threshold})...")
    findings, summary = _build_findings(osv_results, kev_set, args.cvss_threshold)
    kev_count = sum(1 for f in findings if f["in_kev"])

    print(f"\n[결과 요약]")
    print(f"  전체 의존성:    {len(all_deps)}건")
    print(f"  취약 패키지:    {deps_with_vuln}건")
    print(f"  전체 CVE:       {total_cve}건")
    print(f"  High/Critical:  {summary['취약']}건 (CVSS ≥ {args.cvss_threshold})")
    print(f"  CISA KEV 등재:  {kev_count}건")

    # ── Step 5: 결과 저장 ──────────────────────────────────────────
    output_data = _build_output(
        source_dir=str(source_dir),
        project_name=args.project,
        job_id=job_id,
        total_deps=len(all_deps),
        deps_with_vuln=deps_with_vuln,
        total_cve=total_cve,
        kev_count=kev_count,
        cvss_threshold=args.cvss_threshold,
        findings=findings,
        summary=summary,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output_data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n결과 저장: {args.output}")
    _write_llm_summary(output_data, args.output)

    # ── 임시 격리 디렉토리 정리 ───────────────────────────────────
    import shutil
    isolated_dir = Path(f"/tmp/sca_{job_id}")
    if isolated_dir.exists():
        try:
            shutil.rmtree(isolated_dir)
        except Exception:
            pass


if __name__ == "__main__":
    main()
