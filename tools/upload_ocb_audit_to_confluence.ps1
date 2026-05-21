# upload_ocb_audit_to_confluence.ps1
#
# OCB 보안진단 비교 결과를 Confluence 하위 페이지로 업로드하고
# Excel 파일을 첨부합니다.
#
# 사용법:
#   .\tools\upload_ocb_audit_to_confluence.ps1
#   .\tools\upload_ocb_audit_to_confluence.ps1 -ParentPageId 746439687

param(
    [string]$ParentPageId = "746439687",
    [string]$ExcelFile    = "docs\ocb_audit_comparison_20260420_new.xlsx",
    [string]$EnvFile      = ".env"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ── .env 읽기 ─────────────────────────────────────────────────────────────────
$env_vars = @{}
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line -match "^([^=]+)=(.*)$") {
            $env_vars[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
}

$BASE_URL = if ($env_vars["CONFLUENCE_BASE_URL"]) { $env_vars["CONFLUENCE_BASE_URL"].TrimEnd("/") } else { "https://wiki.skplanet.com" }
$TOKEN    = $env_vars["CONFLUENCE_TOKEN"]

if (-not $TOKEN) {
    Write-Error "[ERROR] .env 에 CONFLUENCE_TOKEN 이 없습니다."
    exit 1
}

$HEADERS = @{
    "Authorization" = "Bearer $TOKEN"
    "Content-Type"  = "application/json"
    "Accept"        = "application/json"
}

# ── 부모 페이지 Space Key 조회 ────────────────────────────────────────────────
Write-Host "[1] 부모 페이지 Space Key 조회: $ParentPageId" -ForegroundColor Cyan
$parentResp = Invoke-RestMethod -Uri "$BASE_URL/rest/api/content/${ParentPageId}?expand=space" `
    -Headers $HEADERS -Method Get
$spaceKey = $parentResp.space.key
$parentTitle = $parentResp.title
Write-Host "    Space: $spaceKey  /  부모 제목: $parentTitle"

# ── 페이지 제목 ───────────────────────────────────────────────────────────────
$pageTitle = "OCB 보안진단 — Fortify 이력 x palantir 진단계획 비교 (2026-04-20)"

# ── Storage Format 본문 ───────────────────────────────────────────────────────
$body = @"
<h2>개요</h2>
<p>
  Confluence <em>_2025 / _2026</em> Fortify 진단이력과 palantir OCB 진단계획(ocb_scan_plan.md)을
  교차 비교하여 커버리지 Gap을 정리합니다.<br/>
  상세 데이터는 첨부 Excel(<strong>ocb_audit_comparison_20260420_new.xlsx</strong>)을 참고하세요.
</p>

<h2>통계</h2>
<table>
<tbody>
<tr><th>항목</th><th>수치</th></tr>
<tr><td>Confluence OCB 진단이력 (레포 단위)</td><td><strong>72개</strong></td></tr>
<tr><td>Confluence OCB 진단이력 (build target 기준 전체 행)</td><td><strong>149건</strong></td></tr>
<tr><td>palantir 진단계획 레포</td><td><strong>130개</strong></td></tr>
<tr><td>커버리지 범위</td><td>2025-10, 2025-11, 2025-12, 2026-01, 2026-02, 2026-03, 2026-04</td></tr>
<tr><td>Gap A — Fortify 이력 有, palantir 계획 無</td><td><strong>35개 레포</strong></td></tr>
<tr><td>Gap B — palantir P1 계획 有, Fortify 이력 無</td><td><strong>48개 레포</strong></td></tr>
</tbody>
</table>

<h2>비교 기준</h2>
<ul>
<li>Fortify 진단 단위: <strong>build target</strong> (1 build target = 1 진단 건) — 멀티모듈 레포는 모듈별 복수 행</li>
<li>palantir 진단 단위: <strong>repo</strong> (소스코드 전체 1회 스캔) — AST/정규식 기반으로 컴파일 불필요</li>
<li>Gap 분석 / 커버리지 비교: <strong>repo 단위</strong>로 통일</li>
</ul>

<h2>Gap A — Fortify 이력 有, palantir 계획 未등록 (35건)</h2>
<table>
<tbody>
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
</tbody>
</table>

<h2>Gap B — palantir P1 레포, Fortify 이력 없음 (48건)</h2>
<table>
<tbody>
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
</tbody>
</table>
"@

# ── Step 2: 페이지 생성 ────────────────────────────────────────────────────────
Write-Host "[2] 페이지 생성 중..." -ForegroundColor Cyan

$pagePayload = @{
    type      = "page"
    title     = $pageTitle
    space     = @{ key = $spaceKey }
    ancestors = @(@{ id = $ParentPageId })
    body      = @{
        storage = @{
            value          = $body
            representation = "storage"
        }
    }
} | ConvertTo-Json -Depth 10

$pagePayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($pagePayload)

try {
    $createResp = Invoke-RestMethod `
        -Uri "$BASE_URL/rest/api/content" `
        -Method Post `
        -Headers $HEADERS `
        -Body $pagePayloadBytes
    $newPageId  = $createResp.id
    $newPageUrl = "$BASE_URL/pages/viewpage.action?pageId=$newPageId"
    Write-Host "    생성 완료! pageId=$newPageId" -ForegroundColor Green
    Write-Host "    URL: $newPageUrl"
} catch {
    Write-Error "페이지 생성 실패: $_"
    exit 1
}

# ── Step 3: Excel 첨부 ────────────────────────────────────────────────────────
Write-Host "[3] Excel 파일 첨부: $ExcelFile" -ForegroundColor Cyan

if (-not (Test-Path $ExcelFile)) {
    Write-Warning "  [SKIP] Excel 파일 없음: $ExcelFile"
} else {
    $attachUrl = "$BASE_URL/rest/api/content/$newPageId/child/attachment"

    # multipart/form-data 수동 구성
    $boundary  = [System.Guid]::NewGuid().ToString("N")
    $fileBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $ExcelFile))
    $fileName  = [System.IO.Path]::GetFileName($ExcelFile)

    $bodyParts = [System.Collections.Generic.List[byte]]::new()

    $partHeader = "--$boundary`r`nContent-Disposition: form-data; name=`"file`"; filename=`"$fileName`"`r`nContent-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`r`n`r`n"
    $bodyParts.AddRange([System.Text.Encoding]::ASCII.GetBytes($partHeader))
    $bodyParts.AddRange($fileBytes)
    $bodyParts.AddRange([System.Text.Encoding]::ASCII.GetBytes("`r`n--$boundary--`r`n"))

    $attachHeaders = @{
        "Authorization" = "Bearer $TOKEN"
        "X-Atlassian-Token" = "no-check"
        "Content-Type"  = "multipart/form-data; boundary=$boundary"
    }

    try {
        $attachResp = Invoke-RestMethod `
            -Uri $attachUrl `
            -Method Post `
            -Headers $attachHeaders `
            -Body $bodyParts.ToArray()
        Write-Host "    첨부 완료: $fileName" -ForegroundColor Green
    } catch {
        Write-Warning "  첨부 실패 (페이지 생성은 완료): $_"
    }
}

Write-Host ""
Write-Host "완료!" -ForegroundColor Green
Write-Host "  페이지 URL: $newPageUrl"
