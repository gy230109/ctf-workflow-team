param([string]$Python='', [string]$ProjectDir='')
$ErrorActionPreference='Stop'
if (-not $Python) {
    $localPython=Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (Test-Path -LiteralPath $localPython) {$Python=$localPython}
    else {
        foreach ($candidate in @('python','py','python3')) {
            $found=Get-Command $candidate -ErrorAction SilentlyContinue
            if ($found) {
                $detected=& $found.Source -c 'import sys; print(sys.executable)' 2>$null
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $detected)) {$Python=$detected;break}
            }
        }
    }
}
if (-not $Python) {throw 'Python is missing. Run setup.ps1 once, then connect-ai.ps1.'}
$arguments=@('-X','utf8',(Join-Path $PSScriptRoot 'tools\connect_ai.py'))
if ($ProjectDir) {$arguments+=@('--project',$ProjectDir)}
& $Python @arguments
exit $LASTEXITCODE
