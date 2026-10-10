@echo off
rem Rebuilds the test fixtures from sample.cpp with MSVC (Visual Studio 2022
rem or the Build Tools). /Brepro makes the output reproducible: the
rem TimeDateStamp becomes a content hash instead of the build time.
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VS=%%i"
if not defined VS (echo error: Visual Studio not found & exit /b 1)
cd /d "%~dp0"

call :build x64 sample64.dll || exit /b 1
call :build x64 sample64-v2.dll /DSAMPLE_V2 || exit /b 1
call :build x86 sample32.dll || exit /b 1
del /q *.obj *.lib *.exp 2>nul
dir /b *.dll
exit /b 0

:build
setlocal
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" %1 >nul || exit /b 1
cl /nologo /O2 /MD /EHsc /GR /LD /Brepro %3 sample.cpp /Fe:%2 /link /Brepro || exit /b 1
endlocal & exit /b 0
