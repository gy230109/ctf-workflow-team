<#
.SYNOPSIS
  用 UTF-8 字节更新 GitHub Release 正文，并在更新后回读比对是否一致。

.DESCRIPTION
  - 正文从本脚本同目录（release/）的 Markdown 读取，默认 RELEASE-NOTES-<tag 去掉 v>.md
  - 所有写入都用 UTF-8 字节 + 显式 Content-Type: application/json; charset=utf-8，
    避免 PowerShell 默认编码把中文变成 "?"
  - 令牌只从环境变量读取：GITHUB_TOKEN 或 GH_TOKEN（不接受命令行明文，避免进历史）
  - Release 不存在时自动创建（tag 指向 main）；存在则 PATCH 正文
  - 写完 GET 回读，按规范化后的正文逐字比对，不一致即非零退出

.PARAMETER Tag
  Release tag，例如 v1.0.1

.PARAMETER Notes
  正文 Markdown 路径；省略时取同目录 RELEASE-NOTES-<去掉 v 的 tag>.md，找不到再退 RELEASE-NOTES-<tag>.md

.PARAMETER Repo
  owner/repo；省略时从 git remote origin 解析

.PARAMETER DryRun
  只做本地准备与校验（读出正文字节数、定位 release），不写 GitHub

.EXAMPLE
  $env:GITHUB_TOKEN = 'ghp_xxx'
  .\publish-notes.ps1 -Tag v1.0.1

.EXAMPLE
  .\publish-notes.ps1 -Tag v1.0.1 -Notes .\RELEASE-NOTES-1.0.1.md -DryRun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [string]$Notes,
    [string]$Repo,
    [string]$ApiBase = 'https://api.github.com',
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()

function Fail([string]$Message, [int]$Code = 1) {
    Write-Error $Message
    exit $Code
}

# ---- 令牌：只从环境变量取 ----
$token = $env:GITHUB_TOKEN
if (-not $token) { $token = $env:GH_TOKEN }
if (-not $token) {
    Fail "缺少令牌：请先设置环境变量 GITHUB_TOKEN（或 GH_TOKEN），例如：`n  `$env:GITHUB_TOKEN = 'ghp_xxx'`n本脚本不接受命令行明文令牌。" 2
}

# ---- 正文路径 ----
if (-not $Notes) {
    $short = $Tag.TrimStart('v', 'V')
    $candidates = @(
        (Join-Path $PSScriptRoot "RELEASE-NOTES-$short.md"),
        (Join-Path $PSScriptRoot "RELEASE-NOTES-$Tag.md")
    )
    $Notes = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $Notes) { Fail "找不到正文文件，试过：`n  $($candidates -join "`n  ")" 3 }
}
if (-not (Test-Path -LiteralPath $Notes)) { Fail "正文文件不存在：$Notes" 3 }
$notesPath = (Resolve-Path -LiteralPath $Notes).Path

# 读正文：显式 UTF-8，并把 CRLF 规范成 LF，避免平台差异影响比对
$bodyText = [IO.File]::ReadAllText($notesPath, [Text.Encoding]::UTF8)
$bodyText = ($bodyText -replace "`r`n", "`n").TrimEnd() + "`n"

# ---- 仓库 ----
if (-not $Repo) {
    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
    if (-not $gitExe) {
        foreach ($candidate in @(
            (Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),
            (Join-Path ${env:ProgramFiles(x86)} 'Git\cmd\git.exe'),
            'D:\工具\Git\cmd\git.exe'
        )) {
            if ($candidate -and (Test-Path -LiteralPath $candidate)) { $gitExe = $candidate; break }
        }
    }
    $remote = if ($gitExe) { (& $gitExe -C (Split-Path -Parent $PSScriptRoot) config --get remote.origin.url 2>$null) } else { $null }
    if (-not $remote) { Fail '无法从 git remote origin 解析仓库（git 不在 PATH 且未找到常见安装路径）；请显式传 -Repo owner/repo' 4 }
    if ($remote -match 'github\.com[:/](?<owner>[^/]+)/(?<name>[^/.]+)(\.git)?$') {
        $Repo = "$($Matches.owner)/$($Matches.name)"
    } else {
        Fail "无法解析仓库地址：$remote；请显式传 -Repo owner/repo" 4
    }
}

$headers = @{
    Authorization          = "Bearer $token"
    Accept                 = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2022-11-28'
    'User-Agent'           = 'ctf-purge-fusion-publish-notes'
}
$utf8Bytes = [Text.Encoding]::UTF8.GetBytes($bodyText)

Write-Output "repo       : $Repo"
Write-Output "tag        : $Tag"
Write-Output "notes      : $notesPath"
Write-Output "utf8 bytes : $($utf8Bytes.Length)"
if ($DryRun) {
    Write-Output 'dry-run    : 不写 GitHub'
    exit 0
}

# ---- 定位或创建 release ----
function Get-Release {
    try {
        return Invoke-RestMethod -Uri "$ApiBase/repos/$Repo/releases/tags/$Tag" -Headers $headers -Method Get
    } catch {
        $resp = $_.Exception.Response
        if ($resp -and [int]$resp.StatusCode -eq 404) { return $null }
        throw
    }
}

$release = Get-Release
if (-not $release) {
    $createPayload = @{
        tag_name         = $Tag
        target_commitish = 'main'
        name             = "ctf-purge-fusion $($Tag.TrimStart('v'))"
        body             = $bodyText
        draft            = $false
        prerelease       = $false
    } | ConvertTo-Json -Depth 4
    $createBytes = [Text.Encoding]::UTF8.GetBytes($createPayload)
    $release = Invoke-RestMethod -Uri "$ApiBase/repos/$Repo/releases" -Headers $headers -Method Post `
        -Body $createBytes -ContentType 'application/json; charset=utf-8'
    Write-Output "created    : id=$($release.id)"
} else {
    Write-Output "found      : id=$($release.id)"
}

# ---- 更新正文：UTF-8 字节 + 显式 charset ----
$payload = @{ body = $bodyText } | ConvertTo-Json -Depth 3
$bytes = [Text.Encoding]::UTF8.GetBytes($payload)
$updated = Invoke-RestMethod -Uri "$ApiBase/repos/$Repo/releases/$($release.id)" -Headers $headers -Method Patch `
    -Body $bytes -ContentType 'application/json; charset=utf-8'
Write-Output "patched    : id=$($updated.id)"

# ---- 回读比对 ----
$check = Invoke-RestMethod -Uri "$ApiBase/repos/$Repo/releases/tags/$Tag" -Headers $headers -Method Get
$remoteText = ($check.body -replace "`r`n", "`n").TrimEnd() + "`n"
$expected = $bodyText

$same = $remoteText -ceq $expected
$cjk = ([regex]::Matches($remoteText, '[\u4e00-\u9fff]')).Count
$qm = ([regex]::Matches($remoteText, '\?')).Count
Write-Output "readback   : chars=$($remoteText.Length) cjk=$cjk question_marks=$qm match=$same"

if (-not $same) {
    $limit = [Math]::Min($expected.Length, $remoteText.Length)
    $at = 0
    for ($i = 0; $i -lt $limit; $i++) { if ($expected[$i] -ne $remoteText[$i]) { $at = $i; break } }
    Write-Output "diff at $at"
    Write-Output ("expected: " + $expected.Substring([Math]::Max(0, $at - 40), [Math]::Min(120, $expected.Length - [Math]::Max(0, $at - 40))))
    Write-Output ("remote  : " + $remoteText.Substring([Math]::Max(0, $at - 40), [Math]::Min(120, $remoteText.Length - [Math]::Max(0, $at - 40))))
    Fail '回读正文与本地 Markdown 不一致（写入可能被转换过编码），请检查上方 diff。' 5
}

Write-Output "release    : $($check.html_url)"
exit 0
