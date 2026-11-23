@echo off
setlocal
cd /d "%~dp0"
set "RSACRACKER_DISABLE_UPDATE=1"

if not exist "data.txt" (
    echo [ERROR] data.txt not found. Copy examples\data.txt to data.txt or use --raw.
    pause
    exit /b 2
)

"%~dp0rsacracker.exe" --json %*
set "EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %EXIT_CODE%
