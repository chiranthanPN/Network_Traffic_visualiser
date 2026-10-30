@echo off
setlocal enabledelayedexpansion
title Network Traffic Analyser
cd /d "%~dp0"

set "PYTHON_EXE="

:: 1. Check Python 3.13 explicit install path first (preferred)
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" -c "import uvicorn, fastapi" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        goto :FOUND_PYTHON
    )
)

:: 2. Check py command with -3.13 or default
where py >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py -3.13 -c "import uvicorn, fastapi" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PYTHON_EXE=py -3.13"
        goto :FOUND_PYTHON
    )
    py -c "import uvicorn, fastapi" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PYTHON_EXE=py"
        goto :FOUND_PYTHON
    )
)

:: 3. Check python on PATH
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python -c "import uvicorn, fastapi" >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PYTHON_EXE=python"
        goto :FOUND_PYTHON
    )
)

:: 4. Search any other Python in Programs
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python*") do (
    if exist "%%D\python.exe" (
        "%%D\python.exe" -c "import uvicorn, fastapi" >nul 2>&1
        if !ERRORLEVEL! EQU 0 (
            set "PYTHON_EXE=%%D\python.exe"
            goto :FOUND_PYTHON
        )
    )
)

:: 5. Fallback if no Python has uvicorn yet
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set "PYTHON_EXE=python"
    ) else (
        echo [ERROR] No Python installation found on system.
        pause
        exit /b 1
    )
)

:FOUND_PYTHON
echo [LAUNCHER] Using Python: %PYTHON_EXE%
%PYTHON_EXE% run.py %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [INFO] Launcher exited with code %ERRORLEVEL%.
    pause
)
