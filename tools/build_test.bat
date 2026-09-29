@echo off
rem Build the offline scan test (no game required).
setlocal

if not "%MINGW_BIN%"=="" set "PATH=%MINGW_BIN%;%PATH%"

set ROOT=%~dp0
set OUT=%ROOT%build_test
if not exist "%OUT%" mkdir "%OUT%"

echo building scan_test.exe
g++ -std=c++17 -O2 -Wall -Wextra -static -static-libgcc -static-libstdc++ ^
  -o "%OUT%\scan_test.exe" ^
  "%ROOT%scan_test.cpp" "%ROOT%..\src\scan.cpp" "%ROOT%..\src\unlocker.cpp" "%ROOT%..\src\log.cpp" ^
  -lkernel32
if errorlevel 1 exit /b 1

echo.
echo built: %OUT%\scan_test.exe
echo run:   scan_test.exe ^<path-to-stellaris.exe^>
endlocal
