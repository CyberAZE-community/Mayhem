#!/usr/bin/env bash
# Bootstrap the development environment.
#   Run with:  ./dependencies.sh
#   Then:      source venv/bin/activate
set -euo pipefail

# Havoc's python service library targets Python 3.10.
if ! command -v python3.10 >/dev/null 2>&1; then
    echo "[*] Installing Python 3.10..."
    sudo add-apt-repository -y ppa:deadsnakes/ppa
    sudo apt update
    sudo apt install -y python3.10 python3.10-dev python3.10-venv
fi

if [ ! -d venv ]; then
    echo "[*] Creating virtualenv..."
    python3.10 -m venv venv
fi

echo "[*] Installing dependencies..."
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

if [ ! -f .env ]; then
    cp .env.example .env
    echo "[!] Created .env from template — fill in service_endpoint and service_password."
fi

echo
echo "[+] Done. Activate the environment with:  source venv/bin/activate"
