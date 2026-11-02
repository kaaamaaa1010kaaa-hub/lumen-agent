@echo off
setlocal EnableExtensions

rem Keep this file ASCII only. cmd parses batch files in the OEM code page,
rem so multibyte characters shift the read position and break parsing.
rem
rem Generic static file server for this folder (port 5050 by default).
rem It is independent of the execution core / MCP (start.bat, port 3777).

title Static file server

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
cd /d "%ROOT%"
if errorlevel 1 goto :cd_failed

where node >nul 2>&1
if errorlevel 1 goto :no_node
if not exist "%ROOT%\static-server.js" goto :no_script

rem ---- port: first argument, else SS_PORT, else 5050 ----
if not defined SS_PORT set "SS_PORT=5050"
if not "%~1"=="" set "SS_PORT=%~1"

rem ---- folders that must never be served (comma separated, names only) ----
if not defined SS_DENY_DIRS set "SS_DENY_DIRS=python-sandbox,nova-forge-e2e-tests"

echo [static] folder: %CD%
echo [static] port: %SS_PORT%
echo.

node "%ROOT%\static-server.js"

set "EC=%ERRORLEVEL%"
if "%EC%"=="0" goto :done
echo.
echo [ERROR] server exited with code %EC%
pause
:done
endlocal & exit /b %EC%

:cd_failed
echo [ERROR] cannot enter "%ROOT%"
pause
exit /b 1

:no_node
echo [ERROR] Node.js not found in PATH. Install Node.js from nodejs.org and retry.
pause
exit /b 1

:no_script
echo [ERROR] static-server.js not found in "%ROOT%"
pause
exit /b 1
