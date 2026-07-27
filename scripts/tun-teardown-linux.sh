#!/bin/bash
# TUN teardown script for Linux
# This script removes routing configuration for the TUN interface

TUN_NAME="${AETHER_TUN_NAME:-aether-tun0}"
MARK="${AETHER_TUN_MARK:-438}"
TABLE="${AETHER_TUN_TABLE:-20}"

echo "[*] Tearing down TUN interface: $TUN_NAME"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] This script must be run as root (or with sudo)"
    exit 1
fi

# Remove routing rules
echo "[*] Removing routing rules"
# ip rule del fwmark $MARK lookup main pref 10 2>/dev/null
# ip -6 rule del fwmark $MARK lookup main pref 10 2>/dev/null
# ip rule del lookup $TABLE pref 20 2>/dev/null
# ip -6 rule del lookup $TABLE pref 20 2>/dev/null

# Remove routes
echo "[*] Removing routes"
# ip route del default dev $TUN_NAME table $TABLE 2>/dev/null
# ip -6 route del default dev $TUN_NAME table $TABLE 2>/dev/null

# Bring interface down
echo "[*] Bringing down $TUN_NAME"
ip link set $TUN_NAME down 2>/dev/null

echo "[+] TUN teardown complete"
