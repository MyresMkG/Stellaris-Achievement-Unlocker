@echo off
rem Build achievement_unlocker.dll with MinGW-w64.
rem
rem Set MINGW_BIN if g++ is not on PATH, e.g.
rem   set MINGW_BIN=D:\Program Files\mingw64\bin
rem Optional: --test runs all local versions except 3.14.*;
rem           --publish tests first, then updates the release DLL and evidence.
setlocal

if not "%~1"=="" if /I not "%~1"=="--test" if /I not "%~1"=="--publish" (
  echo usage: build.bat [--test ^| --publish]
  exit /b 2
)

if not "%MINGW_BIN%"=="" set "PATH=%MINGW_BIN%;%PATH%"

where g++ >nul 2>nul
if errorlevel 1 (
  echo g++ not found. Install MinGW-w64 and add its bin directory to PATH,
  echo or set MINGW_BIN to it.
  exit /b 1
)

set ROOT=%~dp0
set SRC=%ROOT%src
set OUT=%ROOT%build

if not exist "%OUT%" mkdir "%OUT%"

set COMMON=-std=c++17 -O2 -Wall -Wextra -static -static-libgcc -static-libstdc++
set SOURCES="%SRC%\dllmain.cpp" "%SRC%\unlocker.cpp" "%SRC%\scan.cpp" "%SRC%\log.cpp"

echo building achievement_unlocker.dll
g++ %COMMON% -shared -Wl,--no-insert-timestamp -o "%OUT%\achievement_unlocker.dll" %SOURCES% -lkernel32
if errorlevel 1 exit /b 1

set "TEST_ARGS="
if /I "%~1"=="--publish" set "TEST_ARGS=-Publish"
if not "%~1"=="" (
  call "%ROOT%tools\build_test.bat"
  if errorlevel 1 exit /b 1
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%tools\run_tests.ps1" %TEST_ARGS%
  if errorlevel 1 exit /b 1
)

echo.
echo done:
dir /b "%OUT%"
endlocal
