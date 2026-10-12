param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Run setup.ps1 first.' }
& $python -X utf8 (Join-Path $PSScriptRoot 'tools\team_start.py')
if ($LASTEXITCODE -ne 0) { throw 'CTF system startup failed. Inspect logs/team-start/latest.json.' }
