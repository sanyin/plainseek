@echo off
rem ============================================================
rem  plainseek launcher (formerly autocrypt)
rem
rem  Two cmd.exe traps this file avoids on purpose:
rem   1) non-ASCII characters together with "chcp 65001" make cmd
rem      re-read the batch file at a wrong byte offset, which
rem      corrupts every following line (the window then closes
rem      instantly, pause included). So this file stays PURE ASCII;
rem      all Chinese text is printed by Python.
rem   2) a ")" inside a quoted path (e.g. "C:\x (1)") terminates an
rem      "if ... ( ... )" block early and silently skips the work.
rem      So no parenthesised blocks are used here, only "if ... goto".
rem ============================================================
chcp 65001 >nul
setlocal
pushd "%~dp0"

set "TARGET=%~1"
if defined TARGET for %%A in ("%TARGET%") do set "TARGET=%%~fA"

rem ---- find a Python interpreter ----
set "PY="
where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto :have_py
where py >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if defined PY goto :have_py
if exist "%USERPROFILE%\.conda\envs\ctf-tools\python.exe" set "PY=%USERPROFILE%\.conda\envs\ctf-tools\python.exe"
if defined PY goto :have_py
if exist "D:\Anaconda\python.exe" set "PY=D:\Anaconda\python.exe"
if defined PY goto :have_py
if exist "C:\Python313\python.exe" set "PY=C:\Python313\python.exe"
if defined PY goto :have_py
echo [X] Python not found in PATH.
echo     Install Python 3.8+ from https://www.python.org then reopen this window.
goto :end

:have_py
if defined TARGET goto :run

echo ============================================================
echo  plainseek - seek the plaintext, one layer at a time
echo ============================================================
echo  Drag a file, a folder or a .zip onto this .bat,
echo  or type a path below.
echo.
set /p "TARGET=Path: "
if not defined TARGET goto :end

:run
rem re-resolve the path (drops a trailing backslash, keeps spaces)
if defined TARGET for %%A in ("%TARGET%") do set "TARGET=%%~fA"
if exist "%TARGET%" goto :go
echo [X] Path not found: %TARGET%
goto :end

:go
"%PY%" -X utf8 "%~dp0plainseek.py" auto "%TARGET%" -o "%~dp0recovered" --timeout 60 --menu
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" goto :failed
echo [OK] Done. Output folder: %~dp0recovered
goto :end

:failed
echo [!] No confident result this time. Options to try:
echo     - bigger budget    : --timeout 180 --deep
echo     - exact key        : --key YOURKEY
echo     - key derivation   : --key-script myscript.py
echo     - known plaintext  : --crib "flag{"
echo     - key confirmation : --verify-binary app.exe --ciphertext-offset 0x... --key-script k.py
echo     - more detail      : python plainseek.py --help
echo.
echo     Output folder: %~dp0recovered  (a report is written inside)
echo     Useful commands  : python plainseek.py scan / identify / carve / crack / fragments

:end
echo.
pause
popd
endlocal
