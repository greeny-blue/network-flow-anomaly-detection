#!/usr/bin/env bash
# ------------------------------------------------------------
# sharkout.sh — export chosen tshark fields from a PCAP to CSV
# Usage:
#   ./sharkout.sh <input.pcapng> <output.csv> [options]
#
# Options:
#   -p, --preset <name>      Use a preset field list (see --list-presets)
#   -f, --fields "<csv>"     Comma-separated tshark fields to export
#   -F, --fields-file <path> File with one field per line to export
#   -Y, --display "<expr>"   Tshark display filter (e.g., 'tcp || udp')
#   -S, --separator "<c>"    CSV separator (default: ,)
#       --no-header          Do not write a header row
#       --list-presets       Show available presets and exit
#       --list-fields        Dump all tshark fields and exit
#       --search-fields str  Fuzzy search tshark fields and exit
#
# Notes:
# - If no fields are specified, the 'default' preset is used.
# - Validates tshark presence and input file; creates output dir if needed.
# ------------------------------------------------------------

set -euo pipefail

# -------- Utilities --------
die() { echo "Error: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found"; }

ensure_parent_dir() {
  local f="$1"
  local d
  d="$(dirname "$f")"
  [ -d "$d" ] || mkdir -p "$d"
}

# -------- Presets --------
# Add or tweak presets as you like.
declare -A PRESETS
# Your original "default" packet-level fields:
PRESETS[default]="frame.time_relative,frame.time_delta,frame.len,ip.src,ip.dst,tcp.srcport,tcp.dstport,tcp.flags,udp.length"

# Minimal core fields (good for quick testing)
PRESETS[minimal]="frame.time_relative,ip.src,ip.dst,frame.len"

# TCP-focused (richer handshake/flags visibility)
PRESETS[extended_tcp]="frame.time_relative,frame.time_delta,frame.len,ip.src,ip.dst,tcp.srcport,tcp.dstport,tcp.len,tcp.stream,tcp.seq,tcp.ack,tcp.flags.syn,tcp.flags.ack,tcp.flags.fin,tcp.flags.reset"

# UDP-focused
PRESETS[udp]="frame.time_relative,frame.time_delta,frame.len,ip.src,ip.dst,udp.srcport,udp.dstport,udp.length"

# HTTP headers (only present if HTTP is in capture)
PRESETS[http]="frame.time_relative,ip.src,ip.dst,tcp.srcport,tcp.dstport,http.request.method,http.request.uri,http.host,http.user_agent,http.response.code"

list_presets() {
  echo "Available presets:"
  for k in "${!PRESETS[@]}"; do echo "  - $k"; done
}

# -------- Args --------
INPUT_PCAP="${1-}"
OUTPUT_CSV="${2-}"
shift 2 || true

[ -n "${INPUT_PCAP}" ] || die "Missing input pcap. Usage: ./sharkout.sh <input.pcapng> <output.csv> [options]"
[ -n "${OUTPUT_CSV}" ] || die "Missing output csv.  Usage: ./sharkout.sh <input.pcapng> <output.csv> [options]"

PRESET="default"
FIELDS=""
FIELDS_FILE=""
DISPLAY_FILTER=""
SEPARATOR=","
HEADER="y"
SEARCH_TERM=""

# Simple arg parser
while (( "$#" )); do
  case "$1" in
    -p|--preset)        PRESET="${2-}"; shift 2 ;;
    -f|--fields)        FIELDS="${2-}"; shift 2 ;;
    -F|--fields-file)   FIELDS_FILE="${2-}"; shift 2 ;;
    -Y|--display)       DISPLAY_FILTER="${2-}"; shift 2 ;;
    -S|--separator)     SEPARATOR="${2-}"; shift 2 ;;
    --no-header)        HEADER="n"; shift ;;
    --list-presets)     list_presets; exit 0 ;;
    --list-fields)      need tshark; tshark -G fields; exit 0 ;;
    --search-fields)    SEARCH_TERM="${2-}"; shift 2 ;;
    --)                 shift; break ;;
    -*)
      die "Unknown option: $1"
      ;;
    *) break ;;
  esac
done

# Field search helper
if [ -n "$SEARCH_TERM" ]; then
  need tshark
  # tshark -G fields prints "F\tAbbrev\t..."; search abbrev & description
  tshark -G fields | grep -iE "$SEARCH_TERM" || true
  exit 0
fi

# -------- Preconditions --------
need tshark
[ -f "$INPUT_PCAP" ] || die "Input file not found: $INPUT_PCAP"
ensure_parent_dir "$OUTPUT_CSV"

# Resolve field list precedence: --fields > --fields-file > --preset
FIELD_LIST=""
if [ -n "$FIELDS" ]; then
  FIELD_LIST="$FIELDS"
elif [ -n "$FIELDS_FILE" ]; then
  [ -f "$FIELDS_FILE" ] || die "Fields file not found: $FIELDS_FILE"
  # join lines with commas, strip blanks/comments starting with #
  FIELD_LIST="$(grep -vE '^\s*(#|$)' "$FIELDS_FILE" | paste -sd, -)"
else
  if [[ -z "${PRESETS[$PRESET]+x}" ]]; then
    echo "Unknown preset: $PRESET" >&2
    list_presets
    exit 1
  fi
  FIELD_LIST="${PRESETS[$PRESET]}"
fi

# Build tshark command
CMD=(tshark -r "$INPUT_PCAP" -T fields -E "header=$HEADER" -E "separator=$SEPARATOR")
IFS=',' read -r -a F_ARR <<< "$FIELD_LIST"
for f in "${F_ARR[@]}"; do
  # trim whitespace
  f_trim="$(echo "$f" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -n "$f_trim" ] && CMD+=(-e "$f_trim")
done

# Optional display filter
if [ -n "$DISPLAY_FILTER" ]; then
  CMD+=(-Y "$DISPLAY_FILTER")
fi

echo "[+] Running:"
printf ' %q' "${CMD[@]}"; echo " > $OUTPUT_CSV"

# Execute
"${CMD[@]}" > "$OUTPUT_CSV"

echo "[+] Saved CSV: $OUTPUT_CSV"
echo "[+] Fields: $FIELD_LIST"
[ "$HEADER" = "y" ] && echo "[+] Header included" || echo "[+] No header requested"

