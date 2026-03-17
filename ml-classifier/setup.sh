#!/bin/bash

# Find the most up-to-date Python version available in PATH
PYTHON_CMD="python3"
for VER in {20..7}; do
    if command -v "python3.$VER" > /dev/null 2>&1; then
        PYTHON_CMD="python3.$VER"
        break
    fi
done

echo "Creating virtual environment using $PYTHON_CMD..."
$PYTHON_CMD -m venv .venv

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "Error: requirements.txt not found!"
    exit 1
fi

echo "Setup complete!"