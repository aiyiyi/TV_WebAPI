@echo off
setlocal
REM 在新窗口中启动 IPTV Web 服务
cd /d "%~dp0"
start "IPTV Service" cmd /K "python server.py"

