#!/bin/bash
# TUN setup script for Linux
# This script configures routing for the TUN interface

TUN_NAME="${AETHER_TUN_NAME:-aether-tun0}"
TUN_IPV4="${AETHER_TUN_IPV4:-198.18.0.1/24}"
MARK="${AETHER_TUN_MARK:-438}"
TABLE="${AETHER_TUN_TABLE:-20}"

echo "[*] Setting up TUN interface: $TUN_NAME"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] This script must be run as root (or with sudo)"
    exit 1
fi

# Disable reverse path filter
echo "[*] Disabling reverse path filter"
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.${TUN_NAME}.rp_filter=0

# Add routing rules to bypass the SOCKS5 server
# You need to adjust this based on your SOCKS5 server address
echo "[*] Adding routing rules (bypass for SOCKS5 server)"
# ip rule add fwmark $MARK lookup main pref 10
# ip -6 rule add fwmark $MARK lookup main pref 10

# Add default routes through TUN
# Create a custom routing table
echo "[*] Adding default routes through $TUN_NAME"
# ip route add default dev $TUN_NAME table $TABLE
# ip rule add lookup $TABLE pref 20
# ip -6 route add default dev $TUN_NAME table $TABLE
# ip -6 rule add lookup $TABLE pref 20

echo "[+] TUN setup complete"
echo ""
echo "To route all traffic through the TUN, run:"
echo "  sudo ip route add default dev $TUN_NAME table $TABLE"
echo "  sudo ip rule add lookup $TABLE pref 20"
echo ""
echo "To bypass the SOCKS5 server, add:"
echo "  sudo ip rule add fwmark $MARK lookup main pref 10"
echo ""
echo "To undo these changes, run: ./tun-teardown-linux.sh"
