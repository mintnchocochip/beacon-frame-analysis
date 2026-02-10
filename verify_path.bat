@echo off
echo ==========================================
echo      Environment Variable Verification
echo ==========================================
echo.
echo Checking if 'cmd.exe' is reachable...
where cmd
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] 'cmd.exe' was found!
    echo Location:
    where cmd
    echo.
    echo If this script works but Arduino IDE fails, try:
    echo 1. Restarting the Arduino IDE.
    echo 2. Restarting your computer (Recommended).
) else (
    echo [FAIL] 'cmd.exe' was NOT found in your PATH.
    echo.
    echo Your current PATH is:
    echo %PATH%
    echo.
    echo Please ensure 'C:\Windows\System32' is added to your System PATH environment variable.
    echo Don't forget to RESTART YOUR COMPUTER after adding it.
)
echo.
pause
