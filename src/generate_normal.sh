#!/usr/bin/env bash
# ------------------------------------------------------------
# generate_normal.sh — produce normal_flows.csv from localhost HTTP traffic
#
# Usage:
#   ./generate_normal.sh [REQUESTS] [DURATION_SECONDS]
#   e.g. ./generate_normal.sh 200 15
#
# Notes:
#   - Spins up a temp web root with index.html and a 100KB blob.bin
#   - Starts a local python http.server bound to that directory
#   - Sends many short HTTP/1.0 requests with Connection: close (new flows)
#   - Captures on loopback with payload truncation (-s 96)
#   - Requires tshark and curl
#
#   Interface:
#     Linux/WSL: lo
#     macOS:     lo0
#   You can override with IFACE env var, e.g.: IFACE=lo0 ./generate_normal.sh
# ------------------------------------------------------------
set -euo pipefail

# --- Config / Args ---
REQS="${1:-200}"       # number of requests to send
DURATION="${2:-15}"    # capture duration in seconds

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCAP_DIR="$ROOT_DIR/data/pcap"
FEATURE_DIR="$ROOT_DIR/data/features"
RAW_CSV="$FEATURE_DIR/normal_raw.csv"
FLOW_CSV="$FEATURE_DIR/normal_flows.csv"
PCAP_FILE="$PCAP_DIR/normal.pcapng"

mkdir -p "$PCAP_DIR" "$FEATURE_DIR"

# Pick loopback interface (override with IFACE=... if you like)
IFACE_DEFAULT="lo"
if [[ "$(uname -s)" == "Darwin" ]]; then
  IFACE_DEFAULT="lo0"
fi
IFACE="${IFACE:-$IFACE_DEFAULT}"

# --- Dependencies ---
command -v tshark >/dev/null 2>&1 || { echo "Error: tshark not found"; exit 1; }
command -v curl   >/dev/null 2>&1 || { echo "Error: curl not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 not found"; exit 1; }

# --- Temp web root with known files ---
TMPWEB="$(mktemp -d)"
trap 'rm -rf "$TMPWEB"' EXIT

echo "<h1>ok</h1>" > "$TMPWEB/index.html"

# Create a 100KB blob without relying on dd (portable)
python3 - "$TMPWEB" <<'PY'
import os, sys
root = sys.argv[1]
with open(os.path.join(root, "blob.bin"), "wb") as f:
    f.write(b"\0"*102400)
PY

# --- Start local server in the temp dir ---
echo "[Normal] Starting local server in: $TMPWEB"
(
  cd "$TMPWEB"
  python3 -m http.server 8000
) >/dev/null 2>&1 &
SERVER_PID=$!

# Wait for server to be healthy
for i in {1..30}; do
  if curl -sSf http://127.0.0.1:8000/ >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

# Check blob availability
USE_BLOB=true
if ! curl -sSf http://127.0.0.1:8000/blob.bin >/dev/null 2>&1; then
  echo "[Normal][WARN] /blob.bin not served; will request / only."
  USE_BLOB=false
fi

# --- Capture ---
echo "[Normal] Capturing on $IFACE for ${DURATION}s (payload snaplen 96) → $PCAP_FILE"
tshark -i "$IFACE" -s 96 -a "duration:${DURATION}" -w "$PCAP_FILE" >/dev/null 2>&1 &
CAP_PID=$!
sleep 0.5

# --- Traffic generation: many short flows (disable keep-alive) ---
echo "[Normal] Generating ${REQS} short HTTP requests (HTTP/1.0, Connection: close)…"
for i in $(seq 1 "$REQS"); do
  if $USE_BLOB && (( i % 2 )); then
    curl -s --http1.0 -H 'Connection: close' http://127.0.0.1:8000/blob.bin >/dev/null || true
  else
    curl -s --http1.0 -H 'Connection: close' http://127.0.0.1:8000/ >/dev/null || true
  fi
done

# --- Wrap up capture & server ---
wait "$CAP_PID" || true
kill "$SERVER_PID" 2>/dev/null || true

# --- Extract and aggregate ---
echo "[Normal] Extracting packet CSV with sharkout.sh (preset: default)…"
"$ROOT_DIR/src/sharkout.sh" "$PCAP_FILE" "$RAW_CSV" -p default

echo "[Normal] Aggregating to per-flow features…"
python3 "$ROOT_DIR/src/pcap2features.py" "$RAW_CSV" "$FLOW_CSV" --summary

echo "[Normal] Done."
echo "  Packet CSV:  $RAW_CSV"
echo "  Flow CSV:    $FLOW_CSV"
echo "  PCAP:        $PCAP_FILE"

