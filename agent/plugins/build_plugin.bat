@echo off
:: Build ctxdebug x64dbg AI Agent Plugin
:: Requires: MSVC + x64dbg Plugin SDK (bridgemain.h + x64dbg.lib)
::
:: SDK search order:
::   1. agent\plugins\pluginsdk\
::   2. %X64DBG_SDK%  (folder that contains bridgemain.h)
::   3. next to x64dbg.exe (%X64DBG_PATH%\..\..\pluginsdk)
::
:: Output: build\mco_agent.dp64  — copy to x64dbg\x64\plugins\

setlocal EnableDelayedExpansion

set PLUGIN_NAME=mco_agent
set PLUGIN_DIR=%~dp0
set OUT_DIR=%PLUGIN_DIR%build
set INCLUDE_ROOT=

if exist "%PLUGIN_DIR%pluginsdk\bridgemain.h" set INCLUDE_ROOT=%PLUGIN_DIR:~0,-1%
if not defined INCLUDE_ROOT if defined X64DBG_SDK if exist "%X64DBG_SDK%\bridgemain.h" (
    for %%I in ("%X64DBG_SDK%\..") do set INCLUDE_ROOT=%%~fI
)
if not defined INCLUDE_ROOT if defined X64DBG_PATH if exist "%X64DBG_PATH%" (
    for %%I in ("%X64DBG_PATH%") do set _DBGDIR=%%~dpI
    if exist "!_DBGDIR!..\..\pluginsdk\bridgemain.h" (
        for %%I in ("!_DBGDIR!..\..") do set INCLUDE_ROOT=%%~fI
    )
)

if not defined INCLUDE_ROOT (
    echo [ERROR] x64dbg Plugin SDK not found.
    echo Set X64DBG_SDK to the pluginsdk folder that contains bridgemain.h
    echo or copy pluginsdk\ next to this script.
    exit /b 1
)

echo [MCO] SDK root: %INCLUDE_ROOT%

:: Find MSVC — include Preview editions, no component-id filter
set VS_PATH=
for /f "delims=" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -property installationPath 2^>nul') do set VS_PATH=%%i
if not defined VS_PATH if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Preview\VC\Auxiliary\Build\vcvars64.bat" (
    set VS_PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Preview
)
if not defined VS_PATH if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set VS_PATH=%ProgramFiles%\Microsoft Visual Studio\2022\Community
)

if not defined VS_PATH (
    echo [ERROR] Visual Studio with MSVC not found.
    exit /b 1
)

set VCVARS=%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
    echo [ERROR] vcvars64.bat not found at: %VCVARS%
    exit /b 1
)

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo [MCO] Setting up MSVC x64 environment...
call "%VCVARS%" >nul 2>&1

echo [MCO] Compiling x64dbg_plugin.cpp...
pushd "%PLUGIN_DIR%"
cl /LD /EHsc /std:c++20 /O2 /W3 /nologo /D_CRT_SECURE_NO_WARNINGS ^
    /I"%INCLUDE_ROOT%" ^
    /I"%INCLUDE_ROOT%\pluginsdk" ^
    x64dbg_plugin.cpp ^
    /link ^
    "%INCLUDE_ROOT%\pluginsdk\x64dbg.lib" ^
    "%INCLUDE_ROOT%\pluginsdk\x64bridge.lib" ^
    /OUT:"%OUT_DIR%\%PLUGIN_NAME%.dp64" ^
    /PDB:"%OUT_DIR%\%PLUGIN_NAME%.pdb" ^
    /MACHINE:X64 ^
    /DLL

set BUILD_ERR=%ERRORLEVEL%
popd
if %BUILD_ERR% neq 0 (
    echo [ERROR] Compilation failed!
    exit /b %BUILD_ERR%
)

echo.
echo [MCO] Build SUCCESS: %OUT_DIR%\%PLUGIN_NAME%.dp64
echo.
echo Install:
echo   copy "%OUT_DIR%\%PLUGIN_NAME%.dp64" "x64dbg\x64\plugins\"
echo   Restart x64dbg — plugin loads automatically.

endlocal
