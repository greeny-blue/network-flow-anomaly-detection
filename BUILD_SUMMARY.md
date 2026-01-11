# Initial Build Summary

This document summarises the first end-to-end build of the  
**PCAP → Features → One-Class Anomaly Detection** pipeline.  
It records the core components constructed, the decisions made, and the rationale behind them.

---

## 1. Safe Data Capture Setup

A fully sandboxed, reproducible environment was created for generating network traffic:

- **Normal traffic** produced via a local Python HTTP server and `curl`.
- **Anomaly traffic** generated using a safe SYN scan (`nmap -sS -T4 localhost`).
- All packet captures:
  - restricted to loopback / host-only interfaces  
  - truncated with `-s 96` to remove payload content  
  - kept short (≤60 seconds)  
  - sanitised before publication

A minimal, sanitised **fixture PCAP (~5 packets)** is included only for unit tests.  
No real-world traffic is captured or published.

---

## 2. Packet → Flow Feature Extraction

Two stages were implemented:

### 2.1 Per-packet export (tshark)
A flexible script (`sharkout.sh`) wraps `tshark` to export selected packet fields into CSV.  
It allows quick experimentation with different field sets.

### 2.2 Flow aggregation (pcap2features.py)
A Python tool was built to convert per-packet CSVs into **per-flow** feature vectors.  
Implemented features include:

- packet count  
- total bytes  
- flow duration  
- inter-arrival mean / std  
- TCP flag counts  
- unique destination ports  
- and other lightweight numeric descriptors  

Both scripts are modular and reusable outside this project.

---

## 3. Synthetic Dataset Generation

Two short scripts were added:

- `generate_normal.sh` — produces normal HTTP GET traffic  
- `generate_scan.sh` — produces SYN scan traffic over a port range  

The Makefile target:

make dataset

runs both, producing:

- `data/features/normal_flows.csv`
- `data/features/scan_flows.csv`

This establishes a clean training/evaluation dataset with a clear separation of normal vs anomalous behaviour.

---

## 4. Baseline One-Class Models

Two models were implemented using standard, well-understood algorithms:

### 4.1 Isolation Forest (`train_iforest.py`)
- Trained only on normal flows  
- Evaluated on normal hold-out + scan flows  
- Supports:
  - summary metrics  
  - score export  
  - configurable contamination  
  - **optional threshold calibration** via `--target-fpr`

### 4.2 One-Class SVM (`train_ocsvm.py`)
- RBF kernel with scaling (RobustScaler)
- Mirrors the Isolation Forest evaluation pipeline  
- Supports:
  - nu/gamma parameter control  
  - score export  
  - **resolved gamma reporting**  
  - the same `--target-fpr` threshold calibration

Both models show excellent separation on the synthetic dataset (without threshold calibration), validating the pipeline.

---

## 5. Reproducible Build System (Makefile)

A clear, documented Makefile was added with:

- `make dataset` — generate synthetic dataset  
- `make train_iforest` — train and evaluate Isolation Forest  
- `make train_svm` — train and evaluate One-Class SVM  
- `make reset` / `make purge` — cleanup utilities  
- `make help` — auto-documented command list  

This provides a polished, developer-friendly interface for running the entire pipeline.

---

## 6. Documentation and Safety Practices

- A full `README.txt` was written describing the project, safety constraints, usage, and directory structure.
- All code stays within strict ethical boundaries:  
  no real traffic, no payloads, no identifiable data, and fully reproducible synthetic captures.

---

## Summary

The initial build successfully establishes:

- a **safe and controlled capture workflow**
- a **flexible feature extraction layer**
- a **clean synthetic dataset**
- two **working one-class anomaly detectors**
- a **reproducible Makefile pipeline**
- clear documentation and ethical safeguards

This provides a strong foundation for further work, including richer datasets, threshold analysis, comparison notebooks, and performance benchmarking.
