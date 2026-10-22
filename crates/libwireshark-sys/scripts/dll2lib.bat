@echo off
setlocal
if "%~2"=="" goto usage
if /I "%~1"=="32" (set "architecture=x86") else if /I "%~1"=="64" (set "architecture=x64") else if /I "%~1"=="arm64" (set "architecture=arm64") else if /I "%~1"=="auto" (set "architecture=auto") else goto usage
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0dll2lib.ps1" -Architecture "%architecture%" -DllPath "%~2" -OutputPath "%~3"
exit /b %ERRORLEVEL%

:usage
echo Usage: dll2lib [32^|64^|arm64^|auto] some-file.dll [output.lib]
exit /b 2
