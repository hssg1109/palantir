#!/usr/bin/env python3
"""
Confluence 업로드용 JSON payload 파일 생성.
PowerShell이 직접 본문을 구성하면 인코딩 문제가 생기므로
Python으로 UTF-8 JSON을 만들어두고 PowerShell이 파일로 POST.
"""
import json
import sys
from pathlib import Path

PARENT_PAGE_ID = "746439687"
SPACE_KEY      = "SECDIG"
PAGE_TITLE     = "OCB 보안진단 — Fortify 이력 x palantir 진단계획 비교 (2026-04-20)"

BODY_HTML = """\
<h2>개요</h2>
<p>
  Confluence <em>_2025 / _2026</em> Fortify 진단이력과 palantir OCB 진단계획(ocb_scan_plan.md)을
  교차 비교하여 커버리지 Gap을 정리합니다.<br />
  상세 데이터는 첨부 Excel(<strong>ocb_audit_comparison_20260420_new.xlsx</strong>)을 참고하세요.
</p>

<h2>통계</h2>
<table><tbody>
<tr><th>항목</th><th>수치</th></tr>
<tr><td>Confluence OCB 진단이력 (레포 단위)</td><td><strong>72개</strong></td></tr>
<tr><td>Confluence OCB 진단이력 (build target 기준 전체 행)</td><td><strong>149건</strong></td></tr>
<tr><td>palantir 진단계획 레포</td><td><strong>130개</strong></td></tr>
<tr><td>커버리지 범위</td><td>2025-10, 2025-11, 2025-12, 2026-01, 2026-02, 2026-03, 2026-04</td></tr>
<tr><td>Gap A — Fortify 이력 有, palantir 계획 無</td><td><strong>35개 레포</strong></td></tr>
<tr><td>Gap B — palantir P1 계획 有, Fortify 이력 無</td><td><strong>48개 레포</strong></td></tr>
</tbody></table>

<h2>비교 기준</h2>
<ul>
<li>Fortify 진단 단위: <strong>build target</strong> (1 build target = 1 진단 건) — 멀티모듈 레포는 모듈별 복수 행</li>
<li>palantir 진단 단위: <strong>repo</strong> (소스코드 전체 1회 스캔) — AST/정규식 기반, 컴파일 불필요</li>
<li>Gap 분석 / 커버리지 비교: <strong>repo 단위</strong>로 통일</li>
</ul>

<h2>Gap A — Fortify 이력 有, palantir 계획 未등록 (35건)</h2>
<table><tbody>
<tr><th>레포</th><th>project</th><th>최근 진단월</th></tr>
<tr><td>front_resource</td><td>OB</td><td>2026-01</td></tr>
<tr><td>homeshopping</td><td>OTH</td><td>2026-03</td></tr>
<tr><td>locker-frontend-admin</td><td>OL</td><td>2026-03</td></tr>
<tr><td>locker-push</td><td>OL</td><td>2026-03</td></tr>
<tr><td>locker-server</td><td>OL</td><td>2026-03</td></tr>
<tr><td>locker-vision</td><td>OL</td><td>2026-03</td></tr>
<tr><td>locker-webview</td><td>OL</td><td>2026-03</td></tr>
<tr><td>locker-webview-front</td><td>OL</td><td>2026-03</td></tr>
<tr><td>ocb-appevt</td><td>OE</td><td>2026-04</td></tr>
<tr><td>ocb-cashbag-mall</td><td>OCB_BACK_END</td><td>2026-02</td></tr>
<tr><td>ocb-game-admin</td><td>OCB-GAME</td><td>2026-02</td></tr>
<tr><td>ocb-game-batch</td><td>OCB-GAME</td><td>2026-02</td></tr>
<tr><td>ocb-push</td><td>OCB_BACK_END</td><td>2026-04</td></tr>
<tr><td>ocb_fun_real</td><td>OCB-THP</td><td>2026-02</td></tr>
<tr><td>ocb_game_biz</td><td>OCB-THP</td><td>2026-02</td></tr>
<tr><td>ocb_game_biz_admin</td><td>OCB-THP</td><td>2026-02</td></tr>
<tr><td>ocb_game_biz_matgo</td><td>OCB-THP</td><td>2026-02</td></tr>
<tr><td>ocb_game_biz_matgo_php_dev</td><td>OCB-THP</td><td>2026-02</td></tr>
<tr><td>ocb_game_biz_matgo_php_real</td><td>OCB-THP</td><td>2026-02</td></tr>
<tr><td>oggletalk-admin-frontend</td><td>OCBWEBVIEW</td><td>2026-03</td></tr>
<tr><td>oggletalk-backend</td><td>OCBWEBVIEW</td><td>2026-03</td></tr>
<tr><td>oip_admin</td><td>OCBPASS</td><td>2026-04</td></tr>
<tr><td>oip_api</td><td>OCBPASS</td><td>2026-04</td></tr>
<tr><td>oip_batch</td><td>OCBPASS</td><td>2026-04</td></tr>
<tr><td>oip_front</td><td>OCBPASS</td><td>2026-04</td></tr>
<tr><td>oki-admin-fe</td><td>OCBWEBVIEW</td><td>2026-01</td></tr>
<tr><td>oki-be</td><td>OCBWEBVIEW</td><td>2026-01</td></tr>
<tr><td>oki-fe</td><td>OCBWEBVIEW</td><td>2026-01</td></tr>
<tr><td>oz-pay-socket</td><td>OCBPU</td><td>2026-04</td></tr>
<tr><td>talkplanet-frontend</td><td>OCBWEBVIEW</td><td>2026-03</td></tr>
<tr><td>trend-ad</td><td>OTH</td><td>2026-03</td></tr>
<tr><td>trend-cms</td><td>OTH</td><td>2026-03</td></tr>
<tr><td>trendissue</td><td>OTH</td><td>2026-03</td></tr>
<tr><td>web</td><td>OCBPU</td><td>2025-12</td></tr>
<tr><td>web-ie8</td><td>OCBPU</td><td>2025-12</td></tr>
</tbody></table>

<h2>Gap B — palantir P1 레포, Fortify 이력 없음 (48건)</h2>
<table><tbody>
<tr><th>레포 슬러그</th><th>project</th><th>INJ</th><th>XSS</th><th>FILE</th><th>DATA</th><th>SCA</th></tr>
<tr><td>adlive-fe</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>admin-api-kt</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>admin-api-py</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>batch-api</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>batch-script</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>bms_admin</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>external-api</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>fail-info</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>live-commerce-backend</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>live-frontend</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>live-frontend-nextjs</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>live-frontend-vite</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>livecm-admin-fe</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>livecm-common-kt</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>main-api-kt</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>main-api-on-lambda-kt</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-admin-frontend</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-bridge-scheduler</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-charge-publish</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-deep-link</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-epm</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-fnc-webview-api</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-gpb</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-iam</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-joy-api</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-joy-frontend</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-nrn</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-nxmile-mq-worker</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-service-frontend</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-soi-appweb</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-webview-deeplink</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-wp-api</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb-wp-frontend</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb_airflow_test</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocb_passbook_enc</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ocbws-web-ui</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ogog-admin-mcp</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>ogog-admin-mcp-server</td><td>OCBWEBVIEW</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>prewarmer</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>rwd_adm</td><td>OCBRWD</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>rwd_front</td><td>OCBRWD</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>soi-event-consumer</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>sugar-admin-worker</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>sugar-kafka</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>system-check</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>thirdparty-api-kt</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>trwas</td><td>OCBSUGAR</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
<tr><td>websocket-api</td><td>LIVECM</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td></tr>
</tbody></table>
"""

payload = {
    "type": "page",
    "title": PAGE_TITLE,
    "space": {"key": SPACE_KEY},
    "ancestors": [{"id": PARENT_PAGE_ID}],
    "body": {
        "storage": {
            "value": BODY_HTML,
            "representation": "storage"
        }
    }
}

out_path = Path(__file__).parent.parent / "docs" / "confluence_page_payload.json"
out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"[저장] {out_path}")
print(f"[제목] {PAGE_TITLE}")
print(f"[본문 길이] {len(BODY_HTML)} chars")
