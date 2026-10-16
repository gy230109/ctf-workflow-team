param([string]$Target='', [string]$Python='', [switch]$Plan, [switch]$SkipWPDependencies)
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
    if($SkipWPDependencies){
        Write-Warning '已跳过 Word/PDF 依赖安装；保留 Markdown/HTML，不能据此宣称 Word/PDF 已就绪。'
    }else{
        & $Python -m pip install -r (Join-Path $Target 'requirements-wp.txt')
        if($LASTEXITCODE -ne 0){throw '代码更新但Word/PDF依赖未就绪：请检查 pip 输出，修复依赖后再继续 AI 接入。'}
    }
    & $Python -X utf8 (Join-Path $Target 'tools\connect_ai.py') --root $Target
    if($LASTEXITCODE -ne 0){throw 'Code updated; AI registration needs repair. Do not report full readiness.'}
}
