#!/bin/bash
set -e

echo "[*] Welcome to the SoftGate Linux Installer"
echo "[*] Requesting administrative privileges..."
sudo -v

echo "[*] Step 1: Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential wget isc-dhcp-client net-tools tor curl

echo "[*] Step 2: Downloading and compiling SoftEther VPN Client..."
if [ ! -f "/usr/local/vpnclient/vpnclient" ]; then
    cd /tmp
    
    wget -qO softether.tar.gz https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.38-9760-rtm/softether-vpnclient-v4.38-9760-rtm-2021.08.17-linux-x64-64bit.tar.gz
    tar -xzf softether.tar.gz
    cd vpnclient
    
    echo "[*] Compiling SoftEther (auto-accepting licenses)..."
    make i_read_and_agree_the_license_agreement=1 > /dev/null 2>&1
    
    echo "[*] Moving SoftEther to /usr/local/vpnclient..."
    cd ..
    sudo mv vpnclient /usr/local/
    sudo chmod 600 /usr/local/vpnclient/*
    sudo chmod 700 /usr/local/vpnclient/vpncmd
    sudo chmod 700 /usr/local/vpnclient/vpnclient
    rm -f /tmp/softether.tar.gz
else
    echo "[+] SoftEther is already installed."
fi

echo "[*] Step 3: Installing the 'uv' Python package manager..."
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | env UV_UNMANAGED_INSTALL="/usr/local/bin" sh
else
    echo "[+] uv is already installed."
fi

echo "[*] Step 4: Installing the SoftGate Python CLI..."

uv tool install vpngate-linux --force

echo "--------------------------------------------------------"
echo "[+] Installation Complete!"
echo "[+] You can now launch the TUI by typing: vpngate gui"
echo "--------------------------------------------------------"