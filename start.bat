@echo off
setlocal EnableExtensions

rem Keep this file ASCII only. cmd parses batch files in the OEM code page,
rem so multibyte characters shift the read position and break parsing.

title Lumen Core

set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"
if not defined NODE_OPTIONS set "NODE_OPTIONS=--no-warnings"

rem ---- script directory without trailing backslash ----
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
cd /d "%ROOT%"
if errorlevel 1 goto :cd_failed

if not exist "%ROOT%\package.json" goto :no_package_json

rem ---- startup speed-ups (inherited by every child process, including npx-launched MCP servers) ----
rem Node 22+ caches compiled JS on disk: server.js, the MCP SDK and node-based MCP servers load faster from the 2nd start on.
if not defined NODE_COMPILE_CACHE set "NODE_COMPILE_CACHE=%ROOT%\.cache\node-compile"
rem npx / npm: use the local cache without re-checking the registry on every start, and skip update / fund / audit network calls.
if not defined npm_config_prefer_offline set "npm_config_prefer_offline=true"
if not defined npm_config_update_notifier set "npm_config_update_notifier=false"
if not defined npm_config_fund set "npm_config_fund=false"
if not defined npm_config_audit set "npm_config_audit=false"
if not defined npm_config_loglevel set "npm_config_loglevel=error"

rem ---- Node.js 24 or newer (server-filesystem 2.0.0 requires it) ----
rem One process does the "is node there" and the version check (no separate "where node").
set "NODE_MAJOR="
for /f "delims=." %%V in ('node -p "process.versions.node" 2^>nul') do set "NODE_MAJOR=%%V"
if not defined NODE_MAJOR goto :no_node
if %NODE_MAJOR% LSS 24 goto :old_node

rem ---- dependencies: skip npm only when everything is really loadable ----
rem The slow "can node load the SDK" test runs once; after it passes a stamp file lets later starts skip it.
set "LUMEN_TRIED=0"
set "STAMP=%ROOT%\node_modules\.lumen-deps-ok"
:check_deps
set "DEPS_OK=1"
if not exist "%ROOT%\node_modules\@modelcontextprotocol\client\dist\index.cjs" set "DEPS_OK=0"
if not exist "%ROOT%\node_modules\@modelcontextprotocol\server-filesystem\package.json" set "DEPS_OK=0"
if "%DEPS_OK%"=="0" if exist "%STAMP%" del /q "%STAMP%" >nul 2>&1
if "%DEPS_OK%"=="1" if exist "%STAMP%" goto :deps_ready
if "%DEPS_OK%"=="1" node -e "require('@modelcontextprotocol/client')" >nul 2>&1
if "%DEPS_OK%"=="1" if errorlevel 1 set "DEPS_OK=0"
if "%DEPS_OK%"=="1" echo ok> "%STAMP%"
if "%DEPS_OK%"=="1" goto :deps_ready
if "%LUMEN_TRIED%"=="1" goto :deps_not_loadable
set "LUMEN_TRIED=1"

rem ---- discard an empty or foreign lockfile (never npm ci on it) ----
if not exist "%ROOT%\package-lock.json" goto :do_install
node -e "try{var l=JSON.parse(require('fs').readFileSync('package-lock.json','utf8'));process.exit((l.name==='lumen-core'||l.name==='nova-forge-core')&&l.packages&&Object.keys(l.packages).length>0?0:1)}catch(e){process.exit(1)}" >nul 2>&1
if errorlevel 1 goto :drop_lock
goto :do_install

:drop_lock
echo [Lumen] discarding empty or foreign package-lock.json
del /q "%ROOT%\package-lock.json"

:do_install
echo [Lumen] installing dependencies...
call npm.cmd install --prefix "%ROOT%" --omit=dev --no-fund --no-audit
if errorlevel 1 goto :npm_failed
goto :check_deps

:deps_ready
rem ---- port: first argument, else LUMEN_PORT, else legacy NF_PORT, else 3777 ----
if not defined LUMEN_PORT if defined NF_PORT set "LUMEN_PORT=%NF_PORT%"
if not defined LUMEN_PORT set "LUMEN_PORT=3777"
if not "%~1"=="" set "LUMEN_PORT=%~1"

set "LUMEN_WORKSPACE=%ROOT%\workspace"
if not exist "%LUMEN_WORKSPACE%" mkdir "%LUMEN_WORKSPACE%"

echo [Lumen] directory: %CD%
echo [Lumen] port: %LUMEN_PORT%
echo [Lumen] workspace: %LUMEN_WORKSPACE%
echo [Lumen] MCP servers: %LUMEN_WORKSPACE%\.mcp.json
echo [Lumen] press Ctrl+C to stop
echo.

node "%ROOT%\server.js"

set "EC=%ERRORLEVEL%"
if "%EC%"=="0" goto :done
rem A failed run may mean a broken install: drop the stamp so the next start re-verifies the SDK.
if exist "%STAMP%" del /q "%STAMP%" >nul 2>&1
echo.
echo [ERROR] server exited with code %EC%
pause
:done
endlocal & exit /b %EC%

:cd_failed
echo [ERROR] cannot enter "%ROOT%"
pause
exit /b 1

:no_package_json
echo [ERROR] package.json not found in "%ROOT%"
pause
exit /b 1

:no_node
echo [ERROR] Node.js not found in PATH. Install Node.js 24 LTS from nodejs.org and retry.
pause
exit /b 1

:old_node
echo [ERROR] Node.js 24 or newer is required. Current major version: %NODE_MAJOR%
pause
exit /b 1

:npm_failed
echo [ERROR] npm install failed. Check your network and proxy settings.
pause
exit /b 1

:deps_not_loadable
echo [ERROR] @modelcontextprotocol/client is not loadable after npm install.
pause
exit /b 1
