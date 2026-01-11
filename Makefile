# ------------------------------------------------------------
# Makefile for PCAP → Features → One-Class Detector Project
# ------------------------------------------------------------

# Variables (you can change these paths if needed)
PYTHON      := python3
SRC_DIR     := src
DATA_DIR    := data
PCAP_DIR    := $(DATA_DIR)/pcap
FEATURE_DIR := $(DATA_DIR)/features
IF_MOD_DIR  := models_iforest
SVM_MOD_DIR := models_ocsvm
VENV_DIR    := .venv


# ============================================================
# Setup & environment
# ============================================================

# Create virtual environment and install dependencies
setup: ## Create a virtual environment and install Python dependencies
	@echo "[Setup] Creating virtual environment and installing dependencies..."
	@$(PYTHON) -m venv $(VENV_DIR)
	@. $(VENV_DIR)/bin/activate && pip install --upgrade pip && pip install -r requirements.txt
	@echo "[Setup] Done."


# ============================================================
# Pipeline demos
# ============================================================

# Run the full safe capture → features pipeline
demo: ## Run the demo pipeline: safe capture → features
	@echo "[Demo] Running PCAP → Features pipeline..."
	cd $(SRC_DIR) && ./sharksign_demo.sh

# Extract fields from any PCAP (wrapper for sharkout.sh)
# Example: make extract PCAP=../data/pcap/normal.pcapng OUT=../data/features/normal_raw.csv
extract: ## Extract per-packet fields from a PCAP into CSV (wrapper for sharkout.sh)
	@[ -n "$(PCAP)" ] || (echo "Usage: make extract PCAP=<path> OUT=<path>"; exit 1)
	cd $(SRC_DIR) && ./sharkout.sh $(PCAP) $(OUT)

# Aggregate a raw packet CSV into flow-level features
# Example: make aggregate IN=../data/features/normal_raw.csv OUT=../data/features/normal_flows.csv
aggregate: ## Aggregate a raw packet CSV into per-flow features
	@[ -n "$(IN)" ] || (echo "Usage: make aggregate IN=<path> OUT=<path>"; exit 1)
	cd $(SRC_DIR) && $(PYTHON) pcap2features.py $(IN) $(OUT) --summary


# ============================================================
# Dataset generation
# ============================================================

normal: ## Generate NORMAL flows from local HTTP traffic
	@echo "[Make] Generate NORMAL flows (200 reqs, 15s)…"
	cd $(SRC_DIR) && ./generate_normal.sh 200 15

scan: ## Generate SCAN flows using a local nmap SYN scan
	@echo "[Make] Generate SCAN flows (ports 1-2000, 10s)…"
	cd $(SRC_DIR) && ./generate_scan.sh 1-2000 10

dataset: normal scan ## Generate both NORMAL and SCAN flow datasets
	@echo "[Make] Dataset ready: data/features/normal_flows.csv + scan_flows.csv"


# ============================================================
# Maintenance
# ============================================================

# Remove demo files
clean: ## Remove demo artefacts (demo PCAP and features)
	@echo "[Clean] Removing demo artefacts..."
	rm -f $(PCAP_DIR)/demo_capture.pcapng
	rm -f $(FEATURE_DIR)/demo_raw.csv $(FEATURE_DIR)/demo_flows.csv

# Clears all PCAP and CSV files
reset: ## Remove all PCAP and feature CSV files, and model PKL and JSON files (clean slate)
	@echo "[Reset] Removing all PCAPs and features (clean slate)..."
	rm -f $(PCAP_DIR)/*.pcapng $(FEATURE_DIR)/*.csv
	rm -f $(IF_MOD_DIR)/*.pkl $(IF_MOD_DIR)/*.json
	rm -f $(SVM_MOD_DIR)/*.pkl $(SVM_MOD_DIR)/*.json

# Remove Python bytecode and cache dirs
purge: ## Remove Python cache directories (__pycache__, .pytest_cache)
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	@echo "[Purge] Cache directories removed."


# ============================================================
# Model training
# ============================================================

# Isolation forest
train_iforest: ## Train Isolation Forest on NORMAL, evaluate on NORMAL+SCAN
	@echo "[Train] IsolationForest on normal, evaluate on normal+anomaly..."
	$(PYTHON) src/train_iforest.py \
		--normal data/features/normal_flows.csv \
		--anomaly data/features/scan_flows.csv \
		--outdir models \
		--contamination 0.05 \
		--summary

# One-class support vector machine (OCSVM)
train_ocsvm: ## Train One-Class SVM on NORMAL, evaluate on NORMAL+SCAN
	@echo "[Train] One-Class SVM on normal, evaluate on normal+anomaly..."
	$(PYTHON) src/train_ocsvm.py \
		--normal data/features/normal_flows.csv \
		--anomaly data/features/scan_flows.csv \
		--outdir models_svm \
		--train-frac 0.8 \
		--nu 0.05 \
		--gamma scale \
		--summary


# ============================================================
# Info / helpers
# ============================================================

# List all available make targets with descriptions
help: ## List available make targets and their descriptions
	@echo ""
	@echo "Available make targets:"
	@echo "-----------------------"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""

.PHONY: setup demo extract aggregate normal scan dataset clean train_iforest train_ocsvm reset purge help

