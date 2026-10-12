param(
    [string]$Python = '',
    [string]$Vmx = '',
    [string]$Vmrun = '',
    [string]$SshUser = 'kali',
    [string]$IdentityFile = '',
    [string]$KnownHosts = '',
    [string]$HostKeyAlias = '',
    [switch]$DiscoverOnly,
    [switch]$InstallGuest,
    [switch]$StartVM
)
$ErrorActionPreference = 'Stop'
function Find-TeamPython {
    if ($Python -and (Test-Path -LiteralPath $Python)) { return $Python }
    foreach ($name in @('python', 'python3', 'py')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            try {
                $path = & $command.Source -c 'import sys; print(sys.executable)' 2>$null
                if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $path)) { return $path }
            } catch {}
        }
    }
    foreach ($base in @($env:LOCALAPPDATA, $env:ProgramFiles)) {
        $root = Join-Path $base 'Programs\Python'
        if (Test-Path -LiteralPath $root) {
            $found = Get-ChildItem -LiteralPath $root -Filter python.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) { return $found.FullName }
        }
    }
    return $null
}
$runtime = Find-TeamPython
if (-not $runtime) {
    if ($DiscoverOnly) { throw 'Python not found. Install Python 3.12 or later, or supply -Python.' }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw 'Python and winget not found. Install Python from python.org, then retry.' }
    & winget install --exact --id Python.Python.3.12 --source winget --silent --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) { throw 'Python installation failed.' }
    $runtime = Find-TeamPython
    if (-not $runtime) { throw 'Python installed but not discoverable. Supply -Python with its path.' }
}
& $runtime -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ is required"'
if ($LASTEXITCODE -ne 0) { throw 'Unsupported Python version.' }
if ($DiscoverOnly) {
    & $runtime -X utf8 (Join-Path $PSScriptRoot 'tools\ctf_team.py') discover
    exit $LASTEXITCODE
}
$venv = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venv)) {
    & $runtime -m venv (Join-Path $PSScriptRoot '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create the isolated Python environment.' }
}
& $venv -m pip install -r (Join-Path $PSScriptRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed; inspect pip output.' }
& $venv -X utf8 (Join-Path $PSScriptRoot 'tools\ctf_os.py') --selftest
if ($LASTEXITCODE -ne 0) { throw 'CTF interface selftest failed.' }
$bridgeConfig = Join-Path $PSScriptRoot 'bridge\config\kali.json'
if (-not (Test-Path -LiteralPath $bridgeConfig)) {
    $arguments = @('configure', '--user', $SshUser)
    foreach ($pair in @(@('--vmx', $Vmx), @('--vmrun', $Vmrun), @('--identity-file', $IdentityFile), @('--known-hosts', $KnownHosts), @('--host-key-alias', $HostKeyAlias))) {
        if ($pair[1]) { $arguments += $pair }
    }
    if ($StartVM) { $arguments += '--start-vm' }
    & $venv -X utf8 (Join-Path $PSScriptRoot 'tools\ctf_team.py') @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Kali configuration requires the missing information shown above.' }
}
if ($InstallGuest) {
    & $venv -X utf8 (Join-Path $PSScriptRoot 'tools\ctf_team.py') install-guest
    if ($LASTEXITCODE -ne 0) { throw 'Guest dependency installation failed; inspect the actual error.' }
}
& $venv -X utf8 (Join-Path $PSScriptRoot 'tools\ctf_team.py') verify
exit $LASTEXITCODE
