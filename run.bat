@echo off
setlocal enabledelayedexpansion
title Network Traffic Analyser
cd /d "%~dp0"

:: Try py first, then python, then local user install
set "PYTHON_EXE="

where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -c "import sys" >nul 2>&1
    if !ERRORLEVEL! EQU 0 set "PYTHON_EXE=py"
)

if not defined PYTHON_EXE (
    where python >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        python -c "import sys" >nul 2>&1
        if !ERRORLEVEL! EQU 0 set "PYTHON_EXE=python"
    )
)

if not defined PYTHON_EXE (
    if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    ) else (
        for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
            if exist "%%D\python.exe" set "PYTHON_EXE=%%D\python.exe"
        )
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] Python not found.
    echo Please install Python 3.9+ from https://www.python.org/ or ensure it is added to your PATH.
    pause
    exit /b 1
)

echo [LAUNCHER] Using Python: %PYTHON_EXE%
"%PYTHON_EXE%" run.py %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [INFO] Launcher exited with code %ERRORLEVEL%.
    pause
)
