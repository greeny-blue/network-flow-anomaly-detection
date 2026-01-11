# Network Flow Anomaly Detection

## Overview

This project explores anomaly detection techniques applied to synthetic network flow data, motivated by defensive monitoring and SOC-style analysis.  
The emphasis is on evaluation behaviour, calibration, and interpretability rather than maximising model performance.

Synthetic data is used throughout to allow controlled experimentation and clear reasoning about model behaviour.

---

## Why this matters (defensive context)

Network anomaly detection is commonly proposed for identifying scanning, reconnaissance or misconfigured services.
In practice, detector behaviour, operating points and false positive rates are often more important than headline metrics.

This project focuses on understanding those behaviours explicitly.

---

## Methods

- Synthetic network flow generation representing baseline and anomalous activity
- Feature engineering aligned with common flow-level signals
- Comparison of anomaly detection approaches (Isolation Forest and One-Class Support Vector Machine)
- Evaluation across operating points rather than single thresholds

---

## Repository contents

- Jupyter notebooks for data generation, modelling and evaluation
- Utility functions for reproducible experiments
- Figures illustrating detector behaviour and calibration

---

## Outputs

Key outputs include:
- operating characteristic plots
- calibration-style views of recall vs false positive rate
- qualitative discussion of detector strengths and limitations

---

## Build & Pipeline

In addition to analysis notebooks, this project includes an end-to-end build pipeline for turning raw PCAP data into structured flow-level features and training lightweight one-class anomaly detectors.

The pipeline covers:
- safe, local-only packet capture
- packet-to-flow aggregation and feature engineering
- reproducible model training and threshold calibration
- unit-tested Python scripts and Makefile-based orchestration

Detailed build documentation is provided in `BUILD.md`.

---

## Limitations & boundaries

- Data is synthetic and simplified
- No claim is made about real-world deployment readiness
- The project is exploratory and educational, not a production system

---

## Ethics & use

This work is defensive in nature and intended for learning and analysis.  
No real network data or sensitive information is used.
