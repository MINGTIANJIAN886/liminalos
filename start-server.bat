@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo ================================================================
echo   Liminal 灵眸 · 启动应用服务（静态站点 + 账号数据库）
echo ================================================================
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo [错误] 未检测到 Node.js，请先安装 Node 20 或更高版本。
  echo        本项目的账号服务使用 Node 24 内置的 node:sqlite，无需 npm install。
  pause
  exit /b 1
)

node server.js

echo.
echo [提示] 服务已停止。
pause
