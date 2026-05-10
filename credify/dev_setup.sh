#!/bin/bash
set -e

echo "======================================"
echo " Credify Developer Setup Script       "
echo "======================================"

echo "[1/4] Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

echo "[2/4] Installing Python requirements..."
pip install -r requirements.txt

echo "[3/4] Setting up environment variables..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "Copied .env.example to .env. Please update it with real values if needed."
    else
        echo "Warning: .env.example not found. Creating a blank .env file."
        touch .env
    fi
else
    echo ".env already exists, skipping."
fi

echo "[4/4] Initializing database..."
python -c "
from app import create_app, db
app = create_app()
with app.app_context():
    db.create_all()
print('Database tables created successfully.')
"

echo ""
echo "======================================"
echo " Setup complete! "
echo " Run: python run.py"
echo "======================================"
