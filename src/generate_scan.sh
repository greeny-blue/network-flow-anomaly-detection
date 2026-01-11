#!/usr/bin/env bash
# ------------------------------------------------------------
# generate_scan.sh — produce scan_flows.csv from localhost SYN scan
# ------------------------------------------------------------
set -euo pipefail

PCAP_DIR="../data/pcap"
FEATURE_DIR="../data/features"
RAW_CSV="$FEATURE_DIR/scan_raw.csv"
FLOW_CSV="$FEATURE_DIR/scan_flows.csv"
PCAP_FILE="$PCAP_DIR/scan.pcapng"
PORTS="${1:-1-2000}"     # port range for nmap (default 1-2000)
DURATION="${2:-10}"      # capture duration (default 10s)

mkdir -p "$PCAP_DIR" "$FEATURE_DIR"

echo "[Scan] Capturing on loopback for ${DURATION}s while scanning ${PORTS}..."
tshark -i lo -s 96 -a "duration:${DURATION}" -w "$PCAP_FILE" >/dev/null 2>&1 &
CAP_PID=$!
sleep 1

# Quick TCP SYN scan; -Pn to skip host discovery on localhost
nmap -sS -T4 -Pn -p "$PORTS" 127.0.0.1 >/dev/null 2>&1 || true

wait "$CAP_PID" || true

echo "[Scan] Extracting packet CSV..."
./sharkout.sh "$PCAP_FILE" "$RAW_CSV" -p extended_tcp

echo "[Scan] Aggregating to flow features..."
python3 pcap2features.py "$RAW_CSV" "$FLOW_CSV" --summary

echo "[Scan] Done → $FLOW_CSV"

