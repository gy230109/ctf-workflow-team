param([string]$ProjectDir='', [switch]$International, [switch]$Cli)
$ErrorActionPreference='Stop'
$runtime=Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if(!(Test-Path -LiteralPath $runtime)){throw 'Run setup.ps1 first.'}
$client=if($Cli){'trae-cli'}elseif($International){'trae-global'}else{'trae'}
$argsList=@('-X','utf8',(Join-Path $PSScriptRoot 'tools\install_skill.py'),'--client',$client)
if($ProjectDir){$argsList+=@('--project-dir',$ProjectDir)}
& $runtime @argsList
exit $LASTEXITCODE
