@echo off
setlocal
if defined CTF_PYTHON goto python_ready
if exist "%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe" set "CTF_PYTHON=%USERPROFILE%\.workbuddy\binaries\python\envs\default\Scripts\python.exe"
if defined CTF_PYTHON goto python_ready
where python >nul 2>nul
if errorlevel 1 goto no_python
set "CTF_PYTHON=python"
:python_ready
"%CTF_PYTHON%" -X utf8 -B "%~dp0upgrade.py" install --apply --harness-profile "%USERPROFILE%\.dsh\profiles\desktop\cordis.patch.yml" %*
set "CTF_UPGRADE_EXIT=%ERRORLEVEL%"
echo.
if not "%CTF_UPGRADE_EXIT%"=="0" echo Upgrade stopped. Read the error above; existing files were not blindly overwritten.
pause
exit /b %CTF_UPGRADE_EXIT%
:no_python
echo Python 3.11+ was not found. Set CTF_PYTHON to your Python executable and retry.
pause
exit /b 1
