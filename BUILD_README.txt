PCAP → Features → One-Class Anomaly Detector
============================================

This project demonstrates an end-to-end workflow for turning raw network captures into structured flow features and training lightweight anomaly detectors. It is designed to be fast, reproducible, and ethically safe—an ideal minimal baseline for security-focused data science.

----------------------------------------------------------------------
PROJECT OVERVIEW
----------------------------------------------------------------------

Goal:
Build a defensible baseline anomaly-detection pipeline that runs entirely on local, sandboxed traffic. The full flow is:

    PCAP → per-packet fields → aggregated flows → one-class model

Why it matters:
- Demonstrates collection, feature engineering, modelling, and evaluation in a security context.
- Runs entirely in a controlled environment (no external data exposure).
- Produces clear, inspectable features and metrics.
- Supports both Isolation Forest (tree-based) and One-Class SVM (boundary-based) models.

----------------------------------------------------------------------
DIRECTORY STRUCTURE
----------------------------------------------------------------------

ds-cyber-pcap-oc/
  ├─ src/                  
  │   ├─ pcap2features.py      - Flow aggregation (packet → flow features)
  │   ├─ train_iforest.py      - Isolation Forest baseline
  │   └─ train_ocsvm.py        - One-Class SVM (extension)
  ├─ data/
  │   ├─ features/             - Derived feature CSVs (safe to publish)
  │   ├─ pcap/                 - Minimal sanitised fixture PCAP (~5 packets)
  │   └─ demo/		       - Demo features and pcap datasets 
  ├─ models_iforest	       - Isolation forest model objects
  ├─ models_iforest_demo       - Isolation forest model objects created for demo
  ├─ models_ocsvm	       - One-Class SVM model objects
  ├─ models_ocsvm_demo         - One-Class SVM model objects created for demo               
  ├─ notebooks/                - Optional analysis/visualisation notebooks
  ├─ tests/                    - Unit tests
  ├─ Makefile                  - Reproducible pipeline commands
  └─ README.txt

----------------------------------------------------------------------
SAFE CAPTURE SETUP
----------------------------------------------------------------------

All captures in this project are:
- Local only (loopback or host-only interface)
- Short (≤60 seconds)
- Truncated to 96 bytes per packet to remove payloads
- Sanitised before any inclusion in the repository

Example safe workflow:

  # Start a simple local HTTP server
  python -m http.server 8000

  # Capture 60 seconds of local traffic
  tshark -i lo -s 96 -a duration:60 -w normal.pcapng

  # Generate normal behaviour
  curl http://127.0.0.1:8000

Generate anomaly traffic, also locally and safely:

  nmap -sS -T4 localhost

No real-world traffic, external IPs, or payloads are captured or published.

----------------------------------------------------------------------
FEATURE EXTRACTION & MODEL TRAINING
----------------------------------------------------------------------

Feature extraction:
1. tshark exports selected per-packet fields.
2. pcap2features.py aggregates them into per-flow statistics, such as:
   - Flow duration
   - Packet count
   - Total bytes
   - Mean / std of inter-arrival times
   - TCP flag counts
   - Unique destination-port count

Models supported:
- Isolation Forest (tree-based baseline)
- One-Class SVM (RBF-kernel boundary model)

Both support optional **threshold calibration** via:

    --target-fpr <fraction>

This sets the decision threshold so that a chosen percentage of hold-out NORMAL flows are flagged, enabling fair comparison between models.

----------------------------------------------------------------------
REPRODUCIBLE PIPELINE (Makefile)
----------------------------------------------------------------------

Run the entire workflow with:

  make dataset         # capture → tshark export → flow aggregation
  make train_iforest   # train Isolation Forest
  make train_ocsvm     # train One-Class SVM

To export decision scores for notebooks:

  make train_iforest SCORES=1
  make train_ocsvm SCORES=1

----------------------------------------------------------------------
ETHICAL AND SECURITY NOTES
----------------------------------------------------------------------

This repository intentionally:
- Publishes only derived feature CSVs, never full captures.
- Includes at most one tiny, sanitised PCAP fixture (~5 packets).
- Avoids any external, personal, or identifiable data.

If you extend this project, please:
- Capture only traffic from your own isolated environment.
- Never upload PCAPs containing real IPs, domains, or payloads.
- Prefer publishing features rather than raw packets.

----------------------------------------------------------------------
DEPENDENCIES
----------------------------------------------------------------------

- Python 3.10+
- tshark (Wireshark CLI)
- pandas
- numpy
- scikit-learn
- pyarrow

----------------------------------------------------------------------
NEXT STEPS
----------------------------------------------------------------------

1. Explore different thresholds using --target-fpr.
2. Introduce harder anomalies (low-and-slow scans, mixed protocols).
3. Benchmark speed (fit/predict) for IF vs OCSVM.
4. Create a small analysis notebook visualising decision scores.

----------------------------------------------------------------------
AUTHOR NOTE
----------------------------------------------------------------------

This project forms part of a data-science-meets-cybersecurity learning portfolio. 
It emphasises safe, disciplined experimentation, clear methodology, and reproducible results.

