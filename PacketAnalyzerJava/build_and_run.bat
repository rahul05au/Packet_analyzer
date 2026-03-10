@echo off
REM =============================================
REM  Packet Analyzer Java - Build & Run Script
REM =============================================
REM  Requires: Java JDK 11+ installed and in PATH
REM  Download: https://adoptium.net/
REM =============================================

SET SRC_DIR=src\main\java
SET OUT_DIR=out
SET MAIN_CLASS=com.packetanalyzer.Main

echo ============================================
echo  Packet Analyzer Java - Build Script
echo ============================================

REM -- Check Java is available --
java -version >nul 2>&1
IF ERRORLEVEL 1 (
    echo ERROR: Java is not installed or not in PATH.
    echo Please install JDK 11 or later from: https://adoptium.net/
    pause
    exit /b 1
)

javac -version >nul 2>&1
IF ERRORLEVEL 1 (
    echo ERROR: javac not found. Please install JDK ^(not just JRE^).
    echo Download: https://adoptium.net/
    pause
    exit /b 1
)

REM -- Compile --
echo.
echo [1/2] Compiling Java sources...
if not exist %OUT_DIR% mkdir %OUT_DIR%
javac -d %OUT_DIR% %SRC_DIR%\com\packetanalyzer\*.java

IF ERRORLEVEL 1 (
    echo ERROR: Compilation failed.
    pause
    exit /b 1
)
echo Compilation successful!

REM -- Run --
echo.
echo [2/2] Running the Packet Analyzer...
echo.
echo Usage examples:
echo   Packet display mode:
echo     run.bat capture.pcap
echo     run.bat capture.pcap 10
echo.
echo   DPI engine mode (multi-threaded):
echo     run.bat --dpi input.pcap output.pcap
echo     run.bat --dpi input.pcap output.pcap rules.txt
echo.

IF "%~1"=="" (
    echo No arguments provided. Showing usage.
    java -cp %OUT_DIR% %MAIN_CLASS%
) ELSE (
    java -cp %OUT_DIR% %MAIN_CLASS% %*
)

pause
