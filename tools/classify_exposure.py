#!/usr/bin/env python3
"""
classify_exposure.py — OCB 서비스 대내/대외 노출 분류

소스코드 신호(testbed 있는 경우) + 레포명 컨벤션으로
exposure(external/internal/hybrid) 자동 분류 후 service_inventory.json 생성.

Usage:
    python3 tools/classify_exposure.py              # 전체 재분류
    python3 tools/classify_exposure.py --repo <name> # 특정 레포만
    python3 tools/classify_exposure.py --summary     # 통계만 출력
"""

import os
import re
import json
import argparse
from pathlib import Path
from datetime import date

BASE_DIR    = Path(__file__).parent.parent
TESTBED_DIR = BASE_DIR / "testbed"
INVENTORY   = BASE_DIR / "docs" / "service_inventory.json"

# ───────────────────────────── 소스코드 신호 체크 ──────────────────────────────

def _grep_files(repo: Path, patterns: list[str], exts: list[str]) -> list[str]:
    hits = []
    for ext in exts:
        for f in repo.rglob(f"*{ext}"):
            try:
                txt = f.read_text(errors="ignore")
                if any(re.search(p, txt, re.IGNORECASE) for p in patterns):
                    hits.append(str(f.relative_to(repo)))
            except Exception:
                pass
    return list(dict.fromkeys(hits))[:4]  # deduplicate, max 4

def sig_acl_ip(repo: Path) -> dict:
    """api.in.acl.allow-ips 존재 → 일부 엔드포인트 내부망 제한 (부분 신호)"""
    files = _grep_files(repo, [r"api\.in\.acl\.allow-ips"], [".properties"])
    return {"signal": "acl_ip_whitelist", "internal": bool(files), "files": files}

def sig_cors_public(repo: Path) -> dict:
    """CORS allowedOrigins 공개 도메인 or 와일드카드 → 대외 신호"""
    patterns = [r"allowedOrigins", r"allow-origins", r"corsOrigins", r"CorsConfiguration"]
    files = _grep_files(repo, patterns,
                        [".java", ".kt", ".yml", ".yaml", ".properties"])
    return {"signal": "cors_config", "external": bool(files), "files": files}

def sig_http_controllers(repo: Path) -> int:
    """HTTP @RestController / @Controller 수"""
    files = _grep_files(repo, [r"@RestController|@Controller\b|RouterFunction"],
                        [".java", ".kt"])
    return len(files)

def sig_grpc_only(repo: Path) -> bool:
    """proto 파일 있고 HTTP 컨트롤러 없음 → 내부 gRPC 전용"""
    has_proto = bool(list(repo.rglob("*.proto")))
    has_http  = bool(_grep_files(repo,
                    [r"@RestController|@Controller\b|RouterFunction"], [".java", ".kt"]))
    return has_proto and not has_http

def sig_kafka(repo: Path) -> bool:
    """Kafka Consumer → 내부 이벤트 처리"""
    return bool(_grep_files(repo,
                [r"@KafkaListener|KafkaConsumer|ConsumerRecord"], [".java", ".kt"]))

def sig_jwt_oauth(repo: Path) -> bool:
    """JWT/OAuth 설정 → 외부 사용자 인증 존재"""
    return bool(_grep_files(repo,
                [r"jwt\.secret|spring\.security\.oauth2|JwtDecoder|JwtEncoder|@EnableResourceServer"],
                [".java", ".kt", ".properties", ".yml"]))

# ─────────────────────────── 레포명 컨벤션 규칙 ───────────────────────────────

_INTERNAL_PAT = [
    r"-admin(?!-mcp$)", r"_admin", r"^admin[-_]",
    r"-batch$", r"_batch$", r"-batch-", r"_batch_",
    r"-scheduler$", r"_scheduler", r"-worker$", r"_worker",
    r"-kafka$", r"_kafka",
    r"-grpc$", r"_grpc", r"-mq-", r"_mq_",
    r"-synchronizer", r"-recon$", r"-transactor", r"-nonce-",
    r"-lambda$", r"_lambda$",
    r"prewarmer$", r"system.check$", r"fail.info$",
    r"trwas$", r"_enc$", r"-ssr$", r"airflow",
    r"livecm.common", r"livecm.admin",
    r"-inside$", r"-operation.support",
    r"bms_admin$", r"rwd_adm$", r"_adm$",
    r"socket.daemon", r"cms_resource", r"event_resource", r"yetax_resource",
    r"^tax_", r"displayadmin",
    r"-backend$", r"-common-",
    r"ogog-admin",
    r"ocbx.admin", r"uptn.admin", r"ocbws.nxmile",
    r"ocb.nft.admin", r"ocb.nft.batch", r"ocb.nft.fingerlabs", r"ocb.nft.lambda",
    r"ocbpass.admin", r"ocbpass.inside", r"ocbpass.operation",
    r"ocbpg.batch$", r"ocbpg.manage$",
    r"ocbpayui.admin", r"ocbpayui.batch", r"ocbpayui.frontend.admin",
    r"ocbpayui.nxmile", r"ocb.nxmile.grpc",
    r"okick.event.server", r"okick.reward.server",
    r"okick.event.batch", r"okick.reward.batch",
]

_EXTERNAL_PAT = [
    r"webview.(?!admin|batch|reward|nxmile)",
    r"fnc.webview",
    r"-frontend$", r"_frontend$", r"-frontend-web",
    r"-front$", r"_front$",
    r"-app$", r"_app$",
    r"community.api",
    r"deep.link$", r"deeplink$",
    r"soi.appweb",
    r"^external.api", r"-external$",
    r"cashbagmall", r"ob.promotion",
    r"unse.frontend", r"live.frontend",
    r"adlive.fe$",
    r"nft.frontend$", r"nft.homepage",
    r"ocbpg$",
    r"okick.front$", r"okick.reward.front",
    r"payui.front.api", r"payui.frontend.web",
    r"ocbpass.app$", r"ocbpass.verify$", r"ocbpass.external$",
    r"rwd_front$",
    r"ocbx.api$",
    r"joy.api$", r"joy.frontend",
    r"ocbws.web.api", r"ocbws.web.ui", r"ocbws.frontend$",
    r"ocb.service.frontend",
    r"ocb.event.front",
    r"unse.frontend", r"ob.promotion", r"cashbagmall",
    r"ocb.sugar$", r"ocb.iam$", r"ocb.gpb$", r"ocb.nrn$",
    r"ocb.epm$",
    r"ocb.wp.api$", r"ocb.wp.frontend$",
    r"ocb.deep.link$",
    r"main.api",
    r"ocb.soi.appweb",
    r"websocket.api",
    r"ocbpass.verify$", r"ocbpg$",
    r"ocb-webview-deeplink$",
]

_HYBRID_PAT = [
    r"thirdparty", r"-van$", r"-newpg$", r"-11st$",
    r"payui.merchant",
    r"ocb.epm$",
]

def classify_by_name(name: str) -> tuple[str, str]:
    n = name.lower()
    for p in _INTERNAL_PAT:
        if re.search(p, n):
            return "internal", f"이름 패턴: {p}"
    for p in _HYBRID_PAT:
        if re.search(p, n):
            return "hybrid", f"이름 패턴: {p}"
    for p in _EXTERNAL_PAT:
        if re.search(p, n):
            return "external", f"이름 패턴: {p}"
    return "unknown", "이름만으로 분류 불가"

# ──────────────────────────── 메인 분류 로직 ──────────────────────────────────

def classify_repo(repo_name: str) -> dict:
    repo_path = TESTBED_DIR / repo_name
    has_source = repo_path.exists() and repo_path.is_dir()

    entry: dict = {
        "repo": repo_name,
        "exposure": "unknown",
        "exposure_ko": "미확인",
        "confidence": "low",
        "basis": "name_only",
        "evidence": [],
        "needs_manual_review": False,
    }

    # ── 소스 신호 기반 분류 ──
    if has_source:
        entry["basis"] = "source_code"
        entry["confidence"] = "high"
        signals = {}

        acl    = sig_acl_ip(repo_path)
        cors   = sig_cors_public(repo_path)
        http_n = sig_http_controllers(repo_path)
        grpc   = sig_grpc_only(repo_path)
        kafka  = sig_kafka(repo_path)
        jwt    = sig_jwt_oauth(repo_path)

        signals["acl_ip"]   = acl
        signals["cors"]     = cors
        signals["grpc_only"] = grpc
        signals["kafka"]    = kafka
        signals["jwt_oauth"] = jwt
        signals["http_controller_files"] = http_n
        entry["signals"] = signals

        int_score = 0
        ext_score = 0

        # gRPC 전용(HTTP 없음) → 강한 내부망 신호
        if grpc:
            int_score += 4
            entry["evidence"].append("gRPC 전용 (HTTP 컨트롤러 없음) → 내부 RPC")

        # Kafka Consumer → 내부
        if kafka:
            int_score += 3
            entry["evidence"].append("Kafka Consumer → 내부 이벤트 처리")

        # ACL + HTTP 컨트롤러 수가 적으면 → 내부용 관리 API
        if acl["internal"]:
            if http_n <= 3:
                int_score += 3
                entry["evidence"].append(f"IP ACL + HTTP컨트롤러 {http_n}개 → 내부 관리 API")
            else:
                # ACL이 있어도 HTTP 컨트롤러 다수 → 일부 엔드포인트만 제한, 서비스 자체는 대외
                ext_score += 1
                entry["evidence"].append(f"IP ACL 있으나 HTTP컨트롤러 {http_n}개 → 관리 엔드포인트 일부 제한, 대외 서비스")

        # CORS 설정 → 외부 도메인 접근 허용
        if cors["external"]:
            ext_score += 3
            entry["evidence"].append("CORS 설정 존재 → 브라우저 크로스오리진 허용")

        # HTTP 컨트롤러 다수 (≥5) → 대외 API 유력
        if http_n >= 5:
            ext_score += 2
            entry["evidence"].append(f"HTTP 컨트롤러 파일 {http_n}개 → 대외 API 유력")
        elif http_n >= 1 and not grpc and not kafka:
            ext_score += 1

        # JWT/OAuth → 외부 사용자 인증
        if jwt:
            ext_score += 1
            entry["evidence"].append("JWT/OAuth 설정 → 외부 인증 처리")

        # 이름 보완
        name_exp, name_reason = classify_by_name(repo_name)
        if name_exp == "internal":
            int_score += 1
        elif name_exp == "external":
            ext_score += 1
        elif name_exp == "hybrid":
            int_score += 1; ext_score += 1
        entry["evidence"].append(f"레포명 추론: {name_reason}")

        # 최종 판정
        if int_score > ext_score:
            entry["exposure"] = "internal"
        elif ext_score > int_score:
            entry["exposure"] = "external"
        elif int_score == ext_score and int_score > 0:
            entry["exposure"] = "hybrid"
            entry["needs_manual_review"] = True
        else:
            entry["exposure"] = name_exp if name_exp != "unknown" else "unknown"
            entry["confidence"] = "medium"

    else:
        # 소스 없음 — 이름 기반
        name_exp, name_reason = classify_by_name(repo_name)
        entry["exposure"] = name_exp
        entry["evidence"].append(name_reason)
        if name_exp == "unknown":
            entry["needs_manual_review"] = True

    _set_ko(entry)
    return entry

def _set_ko(entry: dict):
    m = {"external": "대외", "internal": "대내", "hybrid": "대내외", "unknown": "미확인"}
    entry["exposure_ko"] = m.get(entry["exposure"], "미확인")


# ─────────────────────────────── 전체 레포 목록 ───────────────────────────────

ALL_REPOS: list[tuple[str, str]] = [
    # (group, repo_name)
    # P1-A
    ("P1-A", "ocb-webview-api"),
    ("P1-A", "ocb-webview-frontend"),
    ("P1-A", "ocb-webview-batch"),
    ("P1-A", "ocb-webview-reward-api"),
    ("P1-A", "ocb-webview-admin-api"),
    ("P1-A", "ocb-webview-nxmile-grpc"),
    ("P1-A", "ocb-webview-deeplink"),
    ("P1-A", "ocb-community-api"),
    ("P1-A", "ocb-community-ssr"),
    ("P1-A", "ocb-fnc-webview-api"),
    ("P1-A", "ocb-fnc-webview-frontend"),
    ("P1-A", "ocb-joy-api"),
    ("P1-A", "ocb-joy-frontend"),
    ("P1-A", "ocb-nxmile-mq-worker"),
    ("P1-A", "ocbws-web-api"),
    ("P1-A", "ocbws-nxmile-gateway"),
    ("P1-A", "ocbws-web-ui"),
    ("P1-A", "ocbws-frontend"),
    ("P1-A", "ocb-admin-frontend"),
    ("P1-A", "ocb-service-frontend"),
    ("P1-A", "ocb-ogeul-admin-frontend"),
    ("P1-A", "ocb-charge-publish"),
    ("P1-A", "ogog-admin-mcp-server"),
    ("P1-A", "ogog-admin-mcp"),
    # P1-B
    ("P1-B", "ocb-sugar"),
    ("P1-B", "ocb-iam"),
    ("P1-B", "ocb-epm"),
    ("P1-B", "ocb-wp-api"),
    ("P1-B", "ocb-wp-frontend"),
    ("P1-B", "soi-event-consumer"),
    ("P1-B", "sugar-admin-worker"),
    ("P1-B", "sugar-kafka"),
    ("P1-B", "ocb-soi-appweb"),
    ("P1-B", "ocb-bridge-scheduler"),
    ("P1-B", "ocb-deep-link"),
    ("P1-B", "ocb-nrn"),
    ("P1-B", "ocb-gpb"),
    ("P1-B", "bms_admin"),
    ("P1-B", "fail-info"),
    ("P1-B", "ocb_passbook_enc"),
    ("P1-B", "trwas"),
    ("P1-B", "ocb_airflow_test"),
    # P1-C
    ("P1-C", "rwd_front"),
    ("P1-C", "rwd_adm"),
    # P1-D
    ("P1-D", "main-api-kt"),
    ("P1-D", "main-api-on-lambda-kt"),
    ("P1-D", "admin-api-kt"),
    ("P1-D", "admin-api-py"),
    ("P1-D", "external-api"),
    ("P1-D", "thirdparty-api-kt"),
    ("P1-D", "websocket-api"),
    ("P1-D", "batch-api"),
    ("P1-D", "batch-script"),
    ("P1-D", "live-commerce-backend"),
    ("P1-D", "live-frontend"),
    ("P1-D", "live-frontend-nextjs"),
    ("P1-D", "live-frontend-vite"),
    ("P1-D", "livecm-admin-fe"),
    ("P1-D", "adlive-fe"),
    ("P1-D", "livecm-common-kt"),
    ("P1-D", "prewarmer"),
    ("P1-D", "system-check"),
    # P2-E
    ("P2-E", "ocb-event-server"),
    ("P2-E", "ocb-event-front"),
    ("P2-E", "ob-backend"),
    ("P2-E", "unse-backend"),
    ("P2-E", "unse-frontend"),
    ("P2-E", "cashbagmall"),
    ("P2-E", "business"),
    ("P2-E", "ob-promotion"),
    ("P2-E", "tax_business"),
    ("P2-E", "event_resource"),
    ("P2-E", "cms_resource"),
    ("P2-E", "yetax_resource"),
    # P2-F
    ("P2-F", "displayadmin_server"),
    ("P2-F", "displayadmin_ui"),
    ("P2-F", "osa"),
    # P2-G
    ("P2-G", "ocbx-api"),
    ("P2-G", "ocbx-admin-api"),
    ("P2-G", "ocbx-transactor"),
    ("P2-G", "ocbx-admin-transactor"),
    ("P2-G", "ocbx-synchronizer"),
    ("P2-G", "ocbx-recon"),
    ("P2-G", "ocbx-admin-fe"),
    ("P2-G", "uptn-admin-fe"),
    ("P2-G", "ocbx-nonce-observer"),
    # P2-H
    ("P2-H", "ocb-nft-backend"),
    ("P2-H", "ocb-nft-batch"),
    ("P2-H", "ocb-nft-frontend"),
    ("P2-H", "ocb-nft-admin-front"),
    ("P2-H", "ocb-nft-admin-front-nextjs"),
    ("P2-H", "ocb-nft-fingerlabs"),
    ("P2-H", "ocb-nft-homepage"),
    ("P2-H", "ocb-nft-lambda"),
    # P2-I
    ("P2-I", "ocbpass-app"),
    ("P2-I", "ocbpass-admin"),
    ("P2-I", "ocbpass-admin_web"),
    ("P2-I", "ocbpass-verify"),
    ("P2-I", "ocbpass-external"),
    ("P2-I", "ocbpass-van"),
    ("P2-I", "ocbpass-inside"),
    ("P2-I", "ocbpass-newpg"),
    ("P2-I", "ocbpass-11st"),
    ("P2-I", "ocbpass-operation-support"),
    ("P2-I", "ocbpass-batch"),
    ("P2-I", "ocbpg"),
    ("P2-I", "ocbpg-batch"),
    ("P2-I", "ocbpg-manage"),
    ("P2-I", "ocbpg-socket-daemon"),
    # P2-J
    ("P2-J", "ocbpayui-front-api"),
    ("P2-J", "ocbpayui-merchant-api"),
    ("P2-J", "ocbpayui-admin-api"),
    ("P2-J", "ocbpayui-batch"),
    ("P2-J", "ocbpayui-frontend-web"),
    ("P2-J", "ocbpayui-frontend-admin"),
    ("P2-J", "ocb-nxmile-grpc"),
    ("P2-J", "ocbpayui-nxmile-grpc"),
    # P2-K
    ("P2-K", "okick-event-server"),
    ("P2-K", "okick-reward-server"),
    ("P2-K", "okick-event-batch-server"),
    ("P2-K", "okick-reward-batch-server"),
    ("P2-K", "okick-front"),
    ("P2-K", "okick-reward-front"),
]

# ──────────────────────────────── CLI ─────────────────────────────────────────

def run_all(only_repo: str | None = None) -> dict:
    existing = {}
    if INVENTORY.exists():
        data = json.loads(INVENTORY.read_text())
        existing = {r["repo"]: r for r in data.get("services", [])}

    results = []
    for group, repo in ALL_REPOS:
        if only_repo and repo != only_repo:
            # preserve existing
            if repo in existing:
                results.append(existing[repo])
            continue
        entry = classify_repo(repo)
        entry["group"] = group
        # preserve manual overrides
        if repo in existing and existing[repo].get("manual_override"):
            entry["exposure"]    = existing[repo]["exposure"]
            entry["exposure_ko"] = existing[repo]["exposure_ko"]
            entry["manual_override"] = True
            entry["evidence"].insert(0, "수동 지정 (override)")
        results.append(entry)

    counts = {"external": 0, "internal": 0, "hybrid": 0, "unknown": 0}
    for r in results:
        counts[r["exposure"]] = counts.get(r["exposure"], 0) + 1

    inventory = {
        "generated_at": str(date.today()),
        "total": len(results),
        "summary": counts,
        "services": results,
    }
    INVENTORY.write_text(json.dumps(inventory, ensure_ascii=False, indent=2))
    return inventory


def print_summary(inventory: dict):
    s = inventory["summary"]
    print(f"\n{'='*60}")
    print(f"  OCB 서비스 노출 분류 결과  (총 {inventory['total']}개)")
    print(f"{'='*60}")
    print(f"  🌐 대외(external) : {s.get('external', 0):3d}개")
    print(f"  🔒 대내(internal) : {s.get('internal', 0):3d}개")
    print(f"  ↔️  대내외(hybrid) : {s.get('hybrid', 0):3d}개")
    print(f"  ❓ 미확인(unknown) : {s.get('unknown', 0):3d}개")
    print(f"{'='*60}")
    manual = [r for r in inventory["services"] if r.get("needs_manual_review")]
    if manual:
        print(f"\n  ⚠️  수동 검토 권고 ({len(manual)}개):")
        for r in manual:
            print(f"     - {r['group']} | {r['repo']}")
    print()


def print_table(inventory: dict):
    print(f"\n{'그룹':<8} {'레포':<42} {'분류':<8} {'신뢰도':<8} {'근거'}")
    print("-" * 110)
    icons = {"external": "🌐 대외", "internal": "🔒 대내", "hybrid": "↔️ 대내외", "unknown": "❓ 미확인"}
    for r in inventory["services"]:
        icon = icons.get(r["exposure"], "❓")
        conf = "✅ 소스" if r["basis"] == "source_code" else "⚠️  이름"
        ev   = r["evidence"][0][:50] if r["evidence"] else ""
        print(f"{r.get('group',''):<8} {r['repo']:<42} {icon:<14} {conf:<10} {ev}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo",    help="특정 레포만 재분류")
    parser.add_argument("--summary", action="store_true", help="통계만 출력")
    parser.add_argument("--table",   action="store_true", help="전체 테이블 출력")
    args = parser.parse_args()

    inv = run_all(only_repo=args.repo)
    print_summary(inv)
    if args.table or not args.summary:
        print_table(inv)
    print(f"\n  💾 저장 완료: {INVENTORY}")
