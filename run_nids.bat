@echo off
setlocal enabledelayedexpansion
title NIDS Launcher
cd /d "%~dp0"

:: ============================================================
:: NIDS Launcher (Windows)
:: Run this from the project root (same folder as pipeline.py)
:: Live capture (option 4) requires: Npcap installed, and this
:: .bat run "as Administrator" (right-click > Run as administrator).
:: Only monitor interfaces/networks you are authorized to observe.
:: ============================================================

if not exist "venv\Scripts\activate.bat" (
    echo [setup] No virtual environment found. Creating one...
    python -m venv venv
    if errorlevel 1 (
        echo [error] Could not create a virtual environment. Is Python installed and on PATH?
        pause
        exit /b 1
    )
)

call venv\Scripts\activate.bat

if not exist "venv\.deps_installed" (
    echo [setup] Installing dependencies from requirements.txt...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [error] pip install failed. Check your internet connection and try again.
        pause
        exit /b 1
    )
    echo done> venv\.deps_installed
)

:menu
cls
echo ============================================
echo   NIDS - Network Intrusion Detection System
echo ============================================
echo.
echo   1. Run synthetic traffic simulation (no admin/NIC needed)
echo   2. Start API server (FastAPI, port 8000)
echo   3. Open dashboard in browser
echo   4. Start LIVE sensor pipeline (needs Admin + Npcap)
echo   5. Analyze a PCAP file
echo   6. Train anomaly model from a features CSV
echo   7. Reinstall / update dependencies
echo   8. Exit
echo.
set /p choice="Select an option (1-8): "

if "%choice%"=="1" goto simulate
if "%choice%"=="2" goto api
if "%choice%"=="3" goto dashboard
if "%choice%"=="4" goto live
if "%choice%"=="5" goto pcap
if "%choice%"=="6" goto train
if "%choice%"=="7" goto reinstall
if "%choice%"=="8" goto end
echo Invalid choice.
pause
goto menu

:simulate
echo.
echo [run] Generating synthetic traffic and populating nids.db ...
python -m tests.simulate_traffic
pause
goto menu

:api
echo.
echo [run] Starting FastAPI on http://localhost:8000
echo       Press CTRL+C in this window to stop the server.
echo.
uvicorn api.main:app --reload --port 8000
pause
goto menu

:dashboard
echo.
echo [run] Opening dashboard\index.html in your default browser...
start "" "dashboard\index.html"
echo Make sure the API server (option 2) is running in another window.
pause
goto menu

:live
echo.
echo [run] Starting LIVE capture pipeline.
echo       This window must be running "as Administrator", and Npcap
echo       must be installed (https://npcap.com/#download).
echo.
set /p iface="Interface name (leave blank to use Scapy's default): "
set /p bpf="BPF filter (leave blank for default 'ip'): "

if "%iface%"=="" (
    if "%bpf%"=="" (
        python pipeline.py
    ) else (
        python pipeline.py --filter "%bpf%"
    )
) else (
    if "%bpf%"=="" (
        python pipeline.py --iface "%iface%"
    ) else (
        python pipeline.py --iface "%iface%" --filter "%bpf%"
    )
)
pause
goto menu

:pcap
echo.
set /p pcapfile="Path to .pcap/.pcapng file: "
if not exist "%pcapfile%" (
    echo [error] File not found: %pcapfile%
    pause
    goto menu
)
set /p exportcsv="Export features to CSV? Path, or leave blank to skip: "
if "%exportcsv%"=="" (
    python -m pcap.analyzer "%pcapfile%"
) else (
    python -m pcap.analyzer "%pcapfile%" --export-features "%exportcsv%"
)
pause
goto menu

:train
echo.
set /p csvfile="Path to baseline features CSV (from option 5's export): "
if not exist "%csvfile%" (
    echo [error] File not found: %csvfile%
    pause
    goto menu
)
python -m detection.anomaly "%csvfile%"
pause
goto menu

:reinstall
echo.
echo [setup] Reinstalling dependencies...
pip install -r requirements.txt --upgrade
echo done> venv\.deps_installed
pause
goto menu

:end
endlocal
exit /b 0
