# P1-A OCBWEBVIEW 24개 레포 일괄 Clone 스크립트
# 실행 환경: Windows PowerShell (WSL 불가 — No route to host)
# 실행 방법: cd C:\...\palantir ; .\tools\clone_p1a_ocbwebview.ps1
#
# 진단 분류:
#   [API]     → INJ + XSS + DATA + FILE + SCA
#   [WEB/FE]  → XSS + DATA + SCA  (injection/file은 자산식별 후 결정)
#   [Worker]  → 자산식별 후 스킬 결정

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repos = @(
    # ──────────── API / Backend ────────────
    @{ slug = "ocb-webview-api";          type = "API";    note = "메인 webview API" },
    @{ slug = "ocb-webview-batch";        type = "API";    note = "webview 배치" },
    @{ slug = "ocb-webview-reward-api";   type = "API";    note = "웹뷰 후적립 GW API" },
    @{ slug = "ocb-webview-admin-api";    type = "API";    note = "오글오글/래키바위보 어드민 API" },
    @{ slug = "ocb-webview-nxmile-grpc";  type = "API";    note = "넥스마일 gRPC 연동" },
    @{ slug = "ocb-webview-deeplink";     type = "API";    note = "브릿지(딥링크) 서버" },
    @{ slug = "ocb-community-api";        type = "API";    note = "커뮤니티 API [재진단]" },
    @{ slug = "ocb-fnc-webview-api";      type = "API";    note = "FNC webview API [재진단]" },
    @{ slug = "ocb-joy-api";              type = "API";    note = "Joy API [재진단]" },
    @{ slug = "ocbws-web-api";            type = "API";    note = "OCB 웹사이트 API [재진단]" },
    @{ slug = "ocbws-nxmile-gateway";     type = "API";    note = "넥스마일 전문 통신 서버" },
    @{ slug = "ogog-admin-mcp-server";    type = "API";    note = "오글오글 어드민 MCP 서버" },
    @{ slug = "ogog-admin-mcp";           type = "API";    note = "오글오글 어드민 MCP" },
    # ──────────── WEB / Frontend ───────────
    @{ slug = "ocb-webview-frontend";     type = "WEB";    note = "webview 프론트엔드" },
    @{ slug = "ocb-community-ssr";        type = "WEB";    note = "커뮤니티 SSR" },
    @{ slug = "ocb-fnc-webview-frontend"; type = "WEB";    note = "FNC webview 프론트" },
    @{ slug = "ocb-joy-frontend";         type = "WEB";    note = "Joy 프론트" },
    @{ slug = "ocbws-web-ui";             type = "WEB";    note = "웹사이트 UI" },
    @{ slug = "ocbws-frontend";           type = "WEB";    note = "웹서비스 프론트" },
    @{ slug = "ocb-admin-frontend";       type = "WEB";    note = "OCB 어드민 프론트" },
    @{ slug = "ocb-service-frontend";     type = "WEB";    note = "서비스 프론트" },
    @{ slug = "ocb-ogeul-admin-frontend"; type = "WEB";    note = "오글오글 어드민 프론트" },
    # ──────────── 자산식별 필요 ─────────────
    @{ slug = "ocb-nxmile-mq-worker";    type = "Worker"; note = "MQ Consumer (넥스마일)" },
    @{ slug = "ocb-charge-publish";       type = "Worker"; note = "휴대폰 충전 퍼블리싱" }
)

$project = "OCBWEBVIEW"
$total   = $repos.Count
$ok      = 0
$fail    = 0

Write-Host "=== P1-A OCBWEBVIEW Clone 시작 ($total 개) ===" -ForegroundColor Cyan
Write-Host ""

foreach ($r in $repos) {
    $slug = $r.slug
    $type = $r.type
    $note = $r.note

    Write-Host "[$type] $slug — $note" -ForegroundColor Yellow
    try {
        python tools/new_scan.py $slug --clone $project $slug
        Write-Host "  ✓ 완료" -ForegroundColor Green
        $ok++
    } catch {
        Write-Host "  ✗ 오류: $_" -ForegroundColor Red
        $fail++
    }
    Write-Host ""
}

Write-Host "=== Clone 완료 ===" -ForegroundColor Cyan
Write-Host "  성공: $ok / $total"
if ($fail -gt 0) {
    Write-Host "  실패: $fail" -ForegroundColor Red
    Write-Host "  실패한 레포는 수동으로 확인 후 재시도하세요."
}
Write-Host ""
Write-Host "다음 단계 (WSL에서 실행):"
Write-Host "  /sec-scan-injection  # state 경로 입력 후 진단 시작"
