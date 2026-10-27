@echo off
rem ---------------------------------------------------------------------------
rem  Build WasysProcKiller.exe (MSVC x64).
rem
rem  The driver image (libwasys.sys) is compiled into the exe through
rem  WasysDriverResource.rc as RCDATA.  cl.exe feeds .rc files to rc.exe and
rem  links the resulting .res automatically.
rem ---------------------------------------------------------------------------
setlocal

set "VCVARS="
for %%E in (Enterprise Professional Community BuildTools) do (
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
)
for %%E in (Enterprise Professional Community BuildTools) do (
    if exist "%ProgramFiles%\Microsoft Visual Studio\18\%%E\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\18\%%E\VC\Auxiliary\Build\vcvars64.bat"
)
for %%E in (Enterprise Professional Community BuildTools) do (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\%%E\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\%%E\VC\Auxiliary\Build\vcvars64.bat"
)

if "%VCVARS%"=="" (
    echo [!] vcvars64.bat not found.  From an "x64 Native Tools Command Prompt for VS" run:
    echo     rc /nologo /fo WasysDriverResource.res WasysDriverResource.rc
    echo     cl /nologo /W4 /EHsc /std:c++14 /MT /O2 /DUNICODE /D_UNICODE ^
    echo        WasysProcKiller.cpp WasysDriverLoader.cpp ^
    echo        /Fe:WasysProcKiller.exe /link /SUBSYSTEM:WINDOWS,6.01 /MANIFEST:EMBED ^
    echo        WasysDriverResource.res ^
    echo        user32.lib gdi32.lib comctl32.lib advapi32.lib bcrypt.lib
    exit /b 1
)

if not exist "libwasys.sys" (
    echo [!] libwasys.sys not found next to this script.
    exit /b 1
)

echo Using %VCVARS%
call "%VCVARS%" >nul
if errorlevel 1 exit /b 1

rem --- 1. compile the resource script (embeds libwasys.sys as RCDATA) ---
rc /nologo /fo WasysDriverResource.res WasysDriverResource.rc
if errorlevel 1 (
    echo [!] rc.exe failed
    exit /b 1
)

rem --- 2. compile and link ---
cl /nologo /W4 /EHsc /std:c++14 /MT /O2 /DUNICODE /D_UNICODE ^
   WasysProcKiller.cpp ^
   WasysDriverLoader.cpp ^
   /Fe:WasysProcKiller.exe ^
   /link /SUBSYSTEM:WINDOWS,6.01 /MANIFEST:EMBED /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'" ^
   WasysDriverResource.res ^
   user32.lib gdi32.lib comctl32.lib advapi32.lib bcrypt.lib

if errorlevel 1 (
    echo.
    echo [!] Build FAILED
    exit /b 1
)
echo.
echo [+] Built WasysProcKiller.exe (driver embedded as RCDATA)
endlocal
