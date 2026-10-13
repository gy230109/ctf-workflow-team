param([string]$Source='', [switch]$Plan, [switch]$InstallSpecialists,
      [string]$Category='all', [string]$PipIndex='')
$ErrorActionPreference='Stop'
$runtime=Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if(!(Test-Path -LiteralPath $runtime)){throw 'Existing installation required. Run setup.ps1 first.'}
$entry=Join-Path $PSScriptRoot 'tools\team_upgrade.py'
$argsList=@('-X','utf8',$entry)
if($Source){$argsList+=@('--source',$Source)}
if($Plan){$argsList+='--plan'}
if($InstallSpecialists){$argsList+=@('--install-specialists','--category',$Category)}
if($PipIndex){$argsList+=@('--pip-index',$PipIndex)}
& $runtime @argsList
exit $LASTEXITCODE
