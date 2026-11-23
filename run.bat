@echo off
setlocal
cd /d "%~dp0"
set "RSACRACKER_DISABLE_UPDATE=1"

"%~dp0rsacracker.exe" --json %*
set "EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %EXIT_CODE%
