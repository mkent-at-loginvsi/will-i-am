@echo off
SET INSTALLDIR=%1
%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -Command "if (-not (get-itemproperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell -ea silent).ExecutionPolicy) {Set-Executionpolicy bypass -force}"
IF %ERRORLEVEL% NEQ 0 (
  exit 1
)
%windir%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -File "%~dp0PostConfig.ps1" -InstallDir %INSTALLDIR% %2
IF %ERRORLEVEL% NEQ 0 (
  exit 1
)
REM del /q "%~dp0PostConfig.ps1"
REM del /q "%~dp0dotnet-hosting-6.0.25-win.exe"
REM del /q "%~dp0IISConfig.msi"
REM start /b "" cmd /c del /q "%~f0"&exit /b
