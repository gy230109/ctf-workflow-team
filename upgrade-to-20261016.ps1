param([string]$Target='', [string]$Python='', [switch]$Plan)
$ErrorActionPreference='Stop'
if(!$Target){
    $registry=Join-Path $env:USERPROFILE '.ctf-system\location.json'
    if(Test-Path -LiteralPath $registry){$Target=(Get-Content -LiteralPath $registry -Raw | ConvertFrom-Json).root}
    else{$Target=$PSScriptRoot}
}
$Target=(Resolve-Path -LiteralPath $Target).Path
if(!$Python){
    $candidate=Join-Path $Target '.venv\Scripts\python.exe'
    if(Test-Path -LiteralPath $candidate){$Python=$candidate}
    else{$Python=(Get-Command python -ErrorAction Stop).Source}
}
$arguments=@('-X','utf8',(Join-Path $PSScriptRoot 'tools\team_upgrade.py'),'--source',$PSScriptRoot,'--target',$Target)
if($Plan){$arguments+='--plan'}
& $Python @arguments
if($LASTEXITCODE -ne 0){throw 'Upgrade stopped. Read the actual error; local configurations and evidence must be preserved.'}
if(!$Plan){
    & $Python -X utf8 (Join-Path $Target 'tools\connect_ai.py') --root $Target
    if($LASTEXITCODE -ne 0){throw 'Code updated; AI registration needs repair. Do not report full readiness.'}
}
