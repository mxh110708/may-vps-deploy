@echo off
setlocal
if exist "%~dp0May-VPS-Deploy.exe" (
  start "" "%~dp0May-VPS-Deploy.exe"
  exit /b 0
)
echo This source checkout has no desktop EXE. Build a desktop preview or use the Windows installer.
echo For the legacy command-line tool, run Start-VPSDeploy.Cli.cmd.
pause
exit /b 1
