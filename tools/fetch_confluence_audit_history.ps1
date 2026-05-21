# fetch_confluence_audit_history.ps1
#
# Confluence wiki에서 _2025 / _2026 진단이력 페이지를 수집하여
# docs/confluence_audit_raw.json 으로 저장합니다.
#
# 사용법 (Windows PowerShell):
#   cd C:\path\to\palantir
#   .\tools\fetch_confluence_audit_history.ps1 -PageId 703068661
#
#   # 저장 경로 변경:
#   .\tools\fetch_confluence_audit_history.ps1 -PageId 703068661 -OutFile "docs\confluence_audit_raw.json"
#
# 환경변수 (.env):
#   CONFLUENCE_BASE_URL = https://wiki.skplanet.com
#   CONFLUENCE_TOKEN    = <Personal Access Token>

param(
    [string]$PageId  = "703068661",
    [string]$OutFile = "docs\confluence_audit_raw.json",
    [string]$EnvFile = ".env"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── .env 읽기 ──────────────────────────────────────────────────────────────────
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
    "Accept"        = "application/json"
}

# ── Helper: Confluence REST API GET ───────────────────────────────────────────
function Invoke-ConfluenceGet {
    param([string]$Url)
    try {
        $resp = Invoke-RestMethod -Uri $Url -Headers $HEADERS -Method Get
        return $resp
    } catch {
        Write-Warning "  [HTTP ERROR] $Url — $_"
        return $null
    }
}

# ── Step 1: 부모 페이지 정보 확인 ─────────────────────────────────────────────
Write-Host "[1] 부모 페이지 확인: pageId=$PageId" -ForegroundColor Cyan
$parentUrl = "$BASE_URL/rest/api/content/${PageId}?expand=title,ancestors"
$parent = Invoke-ConfluenceGet $parentUrl
if (-not $parent) { Write-Error "부모 페이지를 가져올 수 없습니다."; exit 1 }
Write-Host "    제목: $($parent.title)"

# ── Step 2: 하위 페이지 목록 수집 (페이지네이션 처리) ────────────────────────
Write-Host "[2] 하위 페이지 목록 수집 중..." -ForegroundColor Cyan
$allChildren = @()
$start = 0
$limit = 50
do {
    $childUrl = "$BASE_URL/rest/api/content/${PageId}/child/page?limit=$limit&start=$start&expand=title"
    $resp = Invoke-ConfluenceGet $childUrl
    if (-not $resp) { break }
    $allChildren += $resp.results
    $start += $resp.results.Count
    Write-Host "    누적 수집: $($allChildren.Count) / $($resp.size)"
} while ($resp.results.Count -eq $limit)

Write-Host "    전체 하위 페이지: $($allChildren.Count)개"

# ── Step 3: _2025 / _2026 포함 페이지 필터 ───────────────────────────────────
Write-Host "[3] 진단이력 페이지 필터 (_2025 / _2026)..." -ForegroundColor Cyan
$historyPages = $allChildren | Where-Object { $_.title -match "2025|2026" }
Write-Host "    매칭 페이지: $($historyPages.Count)개"
foreach ($p in $historyPages) {
    Write-Host "      → [$($p.id)] $($p.title)"
}

if ($historyPages.Count -eq 0) {
    Write-Warning "  _2025 / _2026 페이지를 찾지 못했습니다. 하위 페이지 제목을 확인하세요:"
    $allChildren | ForEach-Object { Write-Host "    [$($_.id)] $($_.title)" }
}

# ── Step 4: 각 이력 페이지의 본문(HTML view) 수집 ────────────────────────────
Write-Host "[4] 페이지 본문 수집 중..." -ForegroundColor Cyan
$pageContents = @()

foreach ($p in $historyPages) {
    Write-Host "    가져오는 중: [$($p.id)] $($p.title)" -ForegroundColor Gray

    # body.view = 렌더링된 HTML (테이블 파싱용)
    $contentUrl = "$BASE_URL/rest/api/content/$($p.id)?expand=body.view,body.storage"
    $content = Invoke-ConfluenceGet $contentUrl
    if (-not $content) { continue }

    # 하위 페이지도 재귀 수집 (1단계 깊이 추가)
    $subChildren = @()
    $subUrl = "$BASE_URL/rest/api/content/$($p.id)/child/page?limit=50&expand=title"
    $subResp = Invoke-ConfluenceGet $subUrl
    if ($subResp -and $subResp.results.Count -gt 0) {
        Write-Host "      하위 페이지 $($subResp.results.Count)개 발견" -ForegroundColor Gray
        foreach ($sub in $subResp.results) {
            Write-Host "        가져오는 중: [$($sub.id)] $($sub.title)" -ForegroundColor DarkGray
            $subContentUrl = "$BASE_URL/rest/api/content/$($sub.id)?expand=body.view,body.storage"
            $subContent = Invoke-ConfluenceGet $subContentUrl
            if ($subContent) {
                $subChildren += @{
                    id    = $sub.id
                    title = $sub.title
                    url   = "$BASE_URL/pages/viewpage.action?pageId=$($sub.id)"
                    body_view    = $subContent.body.view.value
                    body_storage = $subContent.body.storage.value
                }
            }
        }
    }

    $pageContents += @{
        id           = $p.id
        title        = $p.title
        url          = "$BASE_URL/pages/viewpage.action?pageId=$($p.id)"
        body_view    = $content.body.view.value
        body_storage = $content.body.storage.value
        sub_pages    = $subChildren
    }
}

# ── Step 5: JSON 저장 ──────────────────────────────────────────────────────────
Write-Host "[5] JSON 저장: $OutFile" -ForegroundColor Cyan
$output = @{
    fetched_at  = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    parent_id   = $PageId
    parent_title= $parent.title
    pages       = $pageContents
}

$jsonStr = $output | ConvertTo-Json -Depth 10
$jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonStr)
[System.IO.File]::WriteAllBytes($OutFile, $jsonBytes)

Write-Host ""
Write-Host "완료! → $OutFile ($($pageContents.Count)개 페이지)" -ForegroundColor Green
Write-Host "다음 단계: python3 tools/compare_ocb_audit.py --raw $OutFile"
