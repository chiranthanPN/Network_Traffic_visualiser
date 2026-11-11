#!/usr/bin/env bash
# Network Traffic Analyser - macOS BPF Device Permission Helper
# Grants read/write permissions to /dev/bpf* so Scapy can capture raw frames without running python as root.

echo "=========================================================="
echo "  Network Traffic Analyser — macOS BPF Permission Setup"
echo "=========================================================="
echo ""
echo "This will grant read/write permissions to /dev/bpf* devices."
echo "You will be prompted for your macOS administrator password."
echo ""

sudo chmod 666 /dev/bpf*

if [ $? -eq 0 ]; then
    echo ""
    echo " [SUCCESS] Permissions updated successfully!"
    echo " Scapy raw packet capturing is now enabled for non-root users."
    echo " You can now run 'python run.py' and enjoy raw BPF live packet sniffing!"
else
    echo ""
    echo " [ERROR] Failed to update /dev/bpf* permissions."
    echo " Note: Network Traffic Analyser includes a zero-privilege Live System Sniffer"
    echo " that works automatically without root permissions."
fi
