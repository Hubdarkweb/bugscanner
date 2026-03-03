#!/bin/bash
# install.sh - Setup script for WebScanner

echo -e "\033[96m[+]\033[0m Setting up WebScanner environment..."

# Check if termux-setup-storage is needed (for Termux only, optional depending on requirements)
if [ -d "/data/data/com.termux/files/usr" ]; then
    echo -e "\033[96m[+]\033[0m Termux environment detected."
    # Ensure system is up to date
    pkg update -y
    pkg upgrade -y
    # Install dependencies
    pkg install python -y
    pkg install ping -y
    pkg install nmap -y # fallback tools
fi

# Install Python dependencies
echo -e "\033[96m[+]\033[0m Installing Python dependencies..."
pip install --upgrade pip
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    pip install flask websocket-client multithreading loguru requests
fi

echo -e "\033[92m[+]\033[0m Setup complete! You can now run:"
echo -e "    \033[93mpython3 app.py\033[0m"
