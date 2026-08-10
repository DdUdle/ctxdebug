@echo off
:: Build MCO x64dbg AI Agent Plugin
:: Requires: MSVC (Visual Studio 2022) + x64dbg Plugin SDK
::
:: Download x64dbg SDK: https://github.com/x64dbg/x64dbg/tree/development/src/dbg
:: Place pluginsdk/ folder next to this file.
::
:: Output: mco_agent.dp64  (copy to x64dbg\x64\plugins\)

setlocal

set PLUGIN_NAME=mco_agent
set SDK_DIR=pluginsdk
set OUT_DIR=build

:: Find MSVC via vswhere
for /f "delims=" %%i in ('"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul') do set VS_PATH=%%i

if not defined VS_PATH (
    echo [ERROR] Visual Studio with MSVC not found.
    echo Install from: https://visualstudio.microsoft.com/vs/community/
    exit /b 1
)

set VCVARS=%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
    echo [ERROR] vcvars64.bat not found at: %VCVARS%
    exit /b 1
)

:: Check SDK
if not exist "%SDK_DIR%\bridgemain.h" (
    echo [ERROR] x64dbg Plugin SDK not found at %SDK_DIR%\
    echo.
    echo Download the SDK:
    echo   1. Get x64dbg source: https://github.com/x64dbg/x64dbg
    echo   2. Copy src\dbg\pluginsdk\ here
    echo   3. Copy x64dbg.lib from release\x64\ here
    exit /b 1
)

if not exist "%OUT_DIR%" mkdir "%OUT_DIR%"

echo [MCO] Setting up MSVC x64 environment...
call "%VCVARS%" >nul 2>&1

echo [MCO] Compiling x64dbg_plugin.cpp...
cl /LD /EHsc /std:c++20 /O2 /W3 /nologo ^
    /I"%SDK_DIR%" ^
    x64dbg_plugin.cpp ^
    /link ^
    "%SDK_DIR%\x64dbg.lib" ^
    /OUT:"%OUT_DIR%\%PLUGIN_NAME%.dp64" ^
    /PDB:"%OUT_DIR%\%PLUGIN_NAME%.pdb" ^
    /MACHINE:X64 ^
    /DLL ^
    /NODEFAULTLIB:MSVCRT

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Compilation failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [MCO] Build SUCCESS: %OUT_DIR%\%PLUGIN_NAME%.dp64
echo.
echo Install:
echo   copy "%OUT_DIR%\%PLUGIN_NAME%.dp64" "x64dbg\x64\plugins\"
echo   Restart x64dbg — plugin loads automatically.
echo.
echo Verify:
echo   In x64dbg log: [MCO] AI Agent plugin loaded
echo   Then run:      python -m agent --mcp   (from mco\ directory)

endlocal
