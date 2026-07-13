@echo off
setlocal
cd /d "%~dp0"

where powershell.exe >nul 2>&1
REM Handle the branch where the command condition evaluates to true.
if errorlevel 1 (
    echo PowerShell could not be found on this Windows installation.
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\Create-Setup.ps1"
set "EXIT_CODE=%ERRORLEVEL%"

REM Handle the branch where the command condition evaluates to true.
if not "%EXIT_CODE%"=="0" (
    echo.
    echo Setup build did not complete. Review the message above.
    pause
)

exit /b %EXIT_CODE%
