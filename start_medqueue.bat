@echo off
setlocal

rem Run from the project folder even when this file is double-clicked elsewhere.
cd /d "%~dp0"

echo Starting MedQueue at http://127.0.0.1:8000
echo Keep this window open while using the website.
echo Press Ctrl+C here to stop the server.
echo.

rem Prefer the Windows Python launcher; fall back to the python command if needed.
where py >nul 2>&1
if not errorlevel 1 (
    py -3 server.py
) else (
    python server.py
)

rem Keep the window open if Python exits with an error so the message can be read.
if errorlevel 1 (
    echo.
    echo MedQueue could not start. Check that Python 3 is installed and port 8000 is free.
    pause
)

endlocal
