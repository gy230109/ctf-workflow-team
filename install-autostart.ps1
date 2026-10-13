$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Run setup.ps1 first.' }
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$suffix = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'tools\team_start.py') -Algorithm SHA256).Hash.Substring(0, 8)
$taskName = 'CTF-Team-' + $suffix
$arguments = '-X utf8 "' + (Join-Path $PSScriptRoot 'tools\team_start.py') + '"'
$action = New-ScheduledTaskAction -Execute $python -Argument $arguments -WorkingDirectory $PSScriptRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.User.Value
$trigger.Delay = 'PT5S'
$principal = New-ScheduledTaskPrincipal -UserId $identity.User.Value -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Restore this team CTF checkout after user logon; no model/challenge calls.' -Force | Out-Null
Write-Output ('Installed logon task: ' + $taskName)
Write-Output ('Remove with: Unregister-ScheduledTask -TaskName "' + $taskName + '" -Confirm:$false')
