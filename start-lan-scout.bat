@echo off
rem English-named launcher for LAN Scout.
setlocal
cd /d "%~dp0"
set "PYW="
for /f "delims=" %%I in ('where pythonw.exe 2^>nul') do (
    if not defined PYW set "PYW=%%I"
)
if defined PYW (
    start "" "%PYW%" "%~dp0lan_scout.py"
) else (
    where python.exe >nul 2>nul
    if errorlevel 1 (
        echo Python 3.10+ was not found. Please install Python and add it to PATH.
        pause
        exit /b 1
    )
    python "%~dp0lan_scout.py"
)
endlocal
