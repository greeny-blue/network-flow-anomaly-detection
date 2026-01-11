#!/usr/bin/env python3
"""
pcap2features.py — aggregate packet-level CSV (from tshark) into per-flow features.

Input:  CSV produced by sharkout.sh (tshark -T fields ...).
Output: Per-flow feature table with ~10–15 interpretable features.

Flow key: (src_ip, src_port, dst_ip, dst_port, protocol)

Required (best-effort) columns the script can use if present:
- frame.time_relative, frame.time_delta, frame.len
- ip.src, ip.dst
- tcp.srcport, tcp.dstport, tcp.flags (or tcp.flags.syn/ack/fin/reset if exported)
- udp.srcport, udp.dstport, udp.length

Example:
    python src/pcap2features.py data/features/normal_raw.csv data/features/normal_flows.csv --summary
"""

from __future__ import annotations
import argparse
import sys
from typing import Optional, Tuple, List
import pandas as pd
import numpy as np
from pathlib import Path

# TCP flag bitmasks (standard)
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_ECE = 0x40
TCP_CWR = 0x80

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Aggregate tshark packet CSV into per-flow features.")
    p.add_argument("input_csv", help="Packet-level CSV (from sharkout.sh).")
    p.add_argument("output_csv", help="Output features CSV.")
    p.add_argument("--summary", action="store_true", help="Print a brief sanity summary to stdout.")
    p.add_argument("--time-unit", choices=["s"], default="s",
                   help="Time unit for duration/IAT (currently seconds only).")
    return p.parse_args()

def load_packets(path: str | Path) -> pd.DataFrame:
    # Read as strings first, we’ll coerce numerics selectively to keep robustness.
    df = pd.read_csv(path, dtype=str, na_filter=True)
    # Normalize column names (strip spaces, keep exact abbreviations)
    df.columns = [c.strip() for c in df.columns]
    return df

def coalesce_cols(df: pd.DataFrame, candidates: List[str], cast: Optional[str] = None) -> pd.Series:
    """Return the first existing column among candidates; otherwise a NaN series."""
    for c in candidates:
        if c in df.columns:
            s = df[c]
            if cast == "float":
                return pd.to_numeric(s, errors="coerce")
            if cast == "int":
                return pd.to_numeric(s, errors="coerce", downcast="integer")
            return s
    return pd.Series([np.nan] * len(df))

def infer_protocol(df: pd.DataFrame) -> pd.Series:
    """Infer protocol per packet: 'tcp', 'udp', or 'other'."""
    has_tcp = df.filter(regex=r"^tcp\.").notna().any(axis=1) if df.filter(regex=r"^tcp\.").shape[1] else pd.Series(False, index=df.index)
    has_udp = df.filter(regex=r"^udp\.").notna().any(axis=1) if df.filter(regex=r"^udp\.").shape[1] else pd.Series(False, index=df.index)
    proto = np.where(has_tcp, "tcp", np.where(has_udp, "udp", "other"))
    return pd.Series(proto, index=df.index)

def to_int_autobase(x) -> int:
    """Parse tcp.flags which may appear as decimal or hex (e.g., '0x00000012')."""
    if pd.isna(x):
        return 0
    s = str(x).strip()
    if s == "":
        return 0
    try:
        # int(string, 0) auto-detects 0x for hex
        return int(s, 0)
    except Exception:
        # Sometimes tshark prints like '0x0010(ACK)'; strip after '('
        if "(" in s:
            s = s.split("(", 1)[0]
            try:
                return int(s, 0)
            except Exception:
                return 0
        return 0

def compute_flag_counts(g: pd.DataFrame) -> Tuple[int, int, int, int, int, int, int, int]:
    """Return counts of FIN,SYN,RST,PSH,ACK,URG,ECE,CWR in the group."""
    # Prefer explicit boolean columns if present; else decode tcp.flags int/hex.
    cols = g.columns
    if "tcp.flags.syn" in cols or "tcp.flags.ack" in cols:
        def count_true(col: str) -> int:
            if col not in cols:
                return 0
            s = g[col]
            # tshark booleans often '1' or 'True'; coerce to numeric then sum
            return int(pd.to_numeric(s, errors="coerce").fillna(0).astype(int).sum())
        fin = count_true("tcp.flags.fin")
        syn = count_true("tcp.flags.syn")
        rst = count_true("tcp.flags.reset") + count_true("tcp.flags.rst")  # some variants
        psh = count_true("tcp.flags.push") + count_true("tcp.flags.psh")
        ack = count_true("tcp.flags.ack")
        urg = count_true("tcp.flags.urg")
        ece = count_true("tcp.flags.ece")
        cwr = count_true("tcp.flags.cwr")
        return fin, syn, rst, psh, ack, urg, ece, cwr
    else:
        if "tcp.flags" not in cols:
            return (0,)*8
        flags_int = g["tcp.flags"].map(to_int_autobase).astype(int)
        fin = int(((flags_int & TCP_FIN) != 0).sum())
        syn = int(((flags_int & TCP_SYN) != 0).sum())
        rst = int(((flags_int & TCP_RST) != 0).sum())
        psh = int(((flags_int & TCP_PSH) != 0).sum())
        ack = int(((flags_int & TCP_ACK) != 0).sum())
        urg = int(((flags_int & TCP_URG) != 0).sum())
        ece = int(((flags_int & TCP_ECE) != 0).sum())
        cwr = int(((flags_int & TCP_CWR) != 0).sum())
        return fin, syn, rst, psh, ack, urg, ece, cwr

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    # Basic columns
    src_ip = coalesce_cols(df, ["ip.src"])
    dst_ip = coalesce_cols(df, ["ip.dst"])
    tcp_sport = coalesce_cols(df, ["tcp.srcport"], cast="int")
    tcp_dport = coalesce_cols(df, ["tcp.dstport"], cast="int")
    udp_sport = coalesce_cols(df, ["udp.srcport"], cast="int")
    udp_dport = coalesce_cols(df, ["udp.dstport"], cast="int")

    # protocol per packet
    proto = infer_protocol(df)

    # Choose ports depending on protocol (falls back to whichever is present)
    src_port = tcp_sport.fillna(udp_sport)
    dst_port = tcp_dport.fillna(udp_dport)

    # Times & sizes
    t_rel = coalesce_cols(df, ["frame.time_relative"], cast="float")
    t_delta = coalesce_cols(df, ["frame.time_delta"], cast="float")
    frame_len = coalesce_cols(df, ["frame.len"], cast="float")
    udp_len = coalesce_cols(df, ["udp.length"], cast="float")

    # Build a working DataFrame
    packets = pd.DataFrame({
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "t_rel": t_rel,
        "t_delta": t_delta,
        "frame_len": frame_len,
        "udp_len": udp_len
    })

    # Coerce NaNs for grouping keys (string keys ok; ports: set to -1 if NaN)
    packets["src_port"] = packets["src_port"].fillna(-1).astype(int)
    packets["dst_port"] = packets["dst_port"].fillna(-1).astype(int)
    packets["src_ip"] = packets["src_ip"].fillna("NA")
    packets["dst_ip"] = packets["dst_ip"].fillna("NA")
    packets["protocol"] = packets["protocol"].fillna("other")

    # Group by 5-tuple
    grp = packets.groupby(["src_ip", "src_port", "dst_ip", "dst_port", "protocol"], dropna=False, sort=False)

    # Aggregations
    agg = grp.agg(
        packet_count=("frame_len", "size"),
        bytes_total=("frame_len", "sum"),
        bytes_mean=("frame_len", "mean"),
        bytes_std=("frame_len", "std"),
        bytes_min=("frame_len", "min"),
        bytes_max=("frame_len", "max"),
        iat_mean=("t_delta", "mean"),
        iat_std=("t_delta", "std"),
        iat_min=("t_delta", "min"),
        iat_max=("t_delta", "max"),
        first_seen=("t_rel", "min"),
        last_seen=("t_rel", "max"),
    ).reset_index()

    # Duration
    agg["duration"] = (agg["last_seen"] - agg["first_seen"]).fillna(0.0)

    # TCP flags per flow (need original per-packet rows per group)
    # We'll compute by iterating groups minimally for flags only.
    fin_list = []
    syn_list = []
    rst_list = []
    psh_list = []
    ack_list = []
    urg_list = []
    ece_list = []
    cwr_list = []

    # For flag extraction, subset original df to tcp.* and grouping keys
    df_for_flags = df.copy()
    # Bring key columns into df_for_flags to allow groupby on same key
    df_for_flags["src_ip"] = packets["src_ip"]
    df_for_flags["dst_ip"] = packets["dst_ip"]
    df_for_flags["src_port"] = packets["src_port"]
    df_for_flags["dst_port"] = packets["dst_port"]
    df_for_flags["protocol"] = packets["protocol"]

    for key, g in df_for_flags.groupby(["src_ip", "src_port", "dst_ip", "dst_port", "protocol"], sort=False):
        fin, syn, rst, psh, ack, urg, ece, cwr = compute_flag_counts(g)
        fin_list.append(fin); syn_list.append(syn); rst_list.append(rst); psh_list.append(psh)
        ack_list.append(ack); urg_list.append(urg); ece_list.append(ece); cwr_list.append(cwr)

    agg["tcp_fin_count"] = fin_list
    agg["tcp_syn_count"] = syn_list
    agg["tcp_rst_count"] = rst_list
    agg["tcp_psh_count"] = psh_list
    agg["tcp_ack_count"] = ack_list
    agg["tcp_urg_count"] = urg_list
    agg["tcp_ece_count"] = ece_list
    agg["tcp_cwr_count"] = cwr_list

    # Replace NaNs from std with 0 (single-packet flows)
    for col in ["bytes_std", "iat_std"]:
        if col in agg.columns:
            agg[col] = agg[col].fillna(0.0)

    # Reorder columns (flow id first, then features)
    agg.insert(0, "flow_id", (
        agg["src_ip"].astype(str) + "-" +
        agg["src_port"].astype(str) + "-" +
        agg["dst_ip"].astype(str) + "-" +
        agg["dst_port"].astype(str) + "-" +
        agg["protocol"].astype(str)
    ))

    # Final tidy types
    numeric_cols = [
        "packet_count","bytes_total","bytes_mean","bytes_std","bytes_min","bytes_max",
        "iat_mean","iat_std","iat_min","iat_max","first_seen","last_seen","duration",
        "tcp_fin_count","tcp_syn_count","tcp_rst_count","tcp_psh_count",
        "tcp_ack_count","tcp_urg_count","tcp_ece_count","tcp_cwr_count"
    ]
    for c in numeric_cols:
        if c in agg.columns:
            agg[c] = pd.to_numeric(agg[c], errors="coerce")

    return agg

def main():
    args = parse_args()
    in_path = Path(args.input_csv)
    out_path = Path(args.output_csv)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    df = load_packets(in_path)
    if df.empty:
        print("Warning: input CSV is empty. Writing empty features file.", file=sys.stderr)
        pd.DataFrame().to_csv(out_path, index=False)
        return

    features = build_features(df)
    features.to_csv(out_path, index=False)

    if args.summary:
        print(f"[+] Wrote features: {out_path}")
        print(f"[+] Shape: {features.shape[0]} flows × {features.shape[1]} cols")
        # Brief peek
        with pd.option_context('display.max_columns', 0):
            print(features.head(5))

if __name__ == "__main__":
    main()

