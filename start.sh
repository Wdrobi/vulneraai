#!/bin/bash

# VulneraAI Quick Start Script for macOS/Linux

echo ""
echo "===================================="
echo "  VulneraAI - Quick Start"
echo "===================================="
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python3 is not installed"
    echo "Please install Python 3.8+ from python.org"
    exit 1
fi

echo "[1/4] Checking Python installation..."
python3 --version
echo ""

echo "[2/4] Installing backend dependencies..."
cd backend
pip3 install -r requirements.txt -q
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi
cd ..
echo "Dependencies installed successfully!"
echo ""

echo "[3/4] Starting VulneraAI Backend..."
echo "Backend will run on: http://localhost:5000"
echo ""
python3 backend/app.py &
BACKEND_PID=$!

# Wait for backend to start
sleep 2

echo "[4/4] Opening VulneraAI Frontend..."
echo "Frontend will open in your default browser..."
echo ""

# Open frontend in default browser (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$(pwd)/frontend/home.html"
# Open frontend in default browser (Linux)
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open "file://$(pwd)/frontend/home.html" 2>/dev/null || echo "Please open: file://$(pwd)/frontend/index.html"
fi

echo ""
echo "===================================="
echo "  VulneraAI is starting!"
echo "===================================="
echo ""
echo "Backend: http://localhost:5000"
echo "Frontend: file://$(pwd)/frontend/home.html"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

wait $BACKEND_PID
