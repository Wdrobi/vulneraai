@echo off
REM VulneraAI Quick Start Script for Windows

echo.
echo ====================================
echo   VulneraAI - Quick Start
echo ====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo [1/4] Checking Python installation...
python --version
echo.

echo [2/4] Installing backend dependencies...
cd backend
pip install -r requirements.txt -q
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
cd ..
echo Dependencies installed successfully!
echo.

echo [3/4] Starting VulneraAI Backend...
echo Backend will run on: http://localhost:5000
echo.
start python backend/app.py

REM Wait for backend to start
timeout /t 2 /nobreak

echo [4/4] Opening VulneraAI Frontend...
echo Frontend will open in your default browser...
echo.

REM Open frontend in default browser
start "" frontend/home.html

echo.
echo ====================================
echo   VulneraAI is starting!
echo ====================================
echo.
echo Frontend: Open frontend/home.html in your browser
echo Backend: http://localhost:5000
echo.
echo Press Ctrl+C in the backend window to stop the server
echo.
pause
