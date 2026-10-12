$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'config\kali.json') -Raw -Encoding UTF8 | ConvertFrom-Json
& $cfg.python -X utf8 (Join-Path $PSScriptRoot 'kali_bridge.py') @args
exit $LASTEXITCODE
