@echo off
title PERMAFROST Vault
echo.
echo   PERMAFROST Vault
echo.

where node >nul 2>&1 || (
    echo   ERROR: Node.js is not installed or not in PATH.
    echo   Download it from https://nodejs.org/
    echo.
    pause
    exit /b 1
)

echo   Starting relay...
start /B relay.exe -addr :8081

echo   Starting backend on http://localhost:8080
echo.
echo   Open http://localhost:8080 in your browser.
echo   Press Ctrl+C to stop.
echo.

node backend\server.js
