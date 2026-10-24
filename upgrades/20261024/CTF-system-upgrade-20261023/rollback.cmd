@echo off
setlocal
if "%~1"=="" goto usage
if defined CTF_PYTHON goto python_ready
if exist "%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe" set "CTF_PYTHON=%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
if defined CTF_PYTHON goto python_ready
set "CTF_PYTHON=python"
:python_ready
"%CTF_PYTHON%" -X utf8 -B "%~dp0upgrade.py" rollback --apply --journal "%~1"
set "CTF_UPGRADE_EXIT=%ERRORLEVEL%"
pause
exit /b %CTF_UPGRADE_EXIT%
:usage
echo Drag the journal.json from the completed upgrade onto this file to roll back.
pause
exit /b 1
