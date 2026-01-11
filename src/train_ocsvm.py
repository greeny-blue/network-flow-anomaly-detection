#!/usr/bin/env python3
"""
train_ocsvm.py — Train & evaluate a One-Class SVM on flow features
with a proper normal hold-out split + optional target-FPR calibration.

Usage (CLI):
  python src/train_ocsvm.py \
      --normal data/features/normal_flows.csv \
      --anomaly data/features/scan_flows.csv \
      --outdir models_ocsvm \
      --train-frac 0.8 \
      --nu 0.05 \
      --gamma scale \
      --target-fpr 0.01 \
      --summary

Saves:
  <outdir>/ocsvm.pkl
  <outdir>/feature_columns.json
  <outdir>/metrics.json
  (optional) scores CSV via --score-csv

Also usable from Python / notebooks:

  from train_ocsvm import train_ocsvm_pipeline

  result = train_ocsvm_pipeline(
      normal="data/demo/features/normal_flows.csv",
      anomaly="data/demo/features/scan_flows.csv",
      outdir="models_ocsvm_demo",
      train_frac=0.8,
      nu=0.05,
      gamma="scale",
      target_fpr=None,
      summary=True,
  )
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import RobustScaler
from sklearn.pipeline import Pipeline
import joblib

ID_COLS = [
    "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "first_seen", "last_seen",
]


def parse_args():
    p = argparse.ArgumentParser(
        description="Train & evaluate One-Class SVM with normal hold-out."
    )
    p.add_argument(
        "--normal",
        required=True,
        help="CSV of NORMAL flows (train + holdout).",
    )
    p.add_argument(
        "--anomaly",
        required=False,
        help="CSV of ANOMALY flows (e.g., scan flows).",
    )
    p.add_argument(
        "--outdir",
        default="models_ocsvm",
        help="Directory to write model & metrics.",
    )
    p.add_argument(
        "--train-frac",
        type=float,
        default=0.8,
        help="Fraction of NORMAL used for training (rest is holdout).",
    )
    p.add_argument(
        "--nu",
        type=float,
        default=0.05,
        help=(
            "OCSVM nu (upper bound on training outlier fraction; "
            "also a margin parameter)."
        ),
    )
    p.add_argument(
        "--gamma",
        default="scale",
        help="OCSVM RBF kernel gamma (float, 'scale', or 'auto').",
    )
    p.add_argument(
        "--target-fpr",
        type=float,
        default=None,
        help=(
            "If set (e.g., 0.01), set threshold at this quantile of "
            "HOLDOUT-NORMAL scores."
        ),
    )
    p.add_argument(
        "--score-csv",
        default=None,
        help="Optional path to write per-sample decision_function scores and labels.",
    )
    p.add_argument(
        "--summary",
        action="store_true",
        help="Print a brief summary.",
    )
    return p.parse_args()


def load_features(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    return df


def select_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    X = df.select_dtypes(include=[np.number]).copy()
    # treat ports as identifiers for now (comment out to include them)
    for col in ("src_port", "dst_port"):
        if col in X.columns:
            X.drop(columns=[col], inplace=True)
    X.drop(columns=[c for c in ID_COLS if c in X.columns], errors="ignore", inplace=True)
    return X.fillna(0.0)


def fit_ocsvm(X_train: pd.DataFrame, nu: float, gamma):
    # SVMs benefit from scaling; RobustScaler resists outliers
    pipe = Pipeline(
        [
            ("scaler", RobustScaler()),
            ("ocsvm", OneClassSVM(kernel="rbf", nu=nu, gamma=gamma)),
        ]
    )
    pipe.fit(X_train)
    return pipe


def metrics_from_cm(tp, fp, tn, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"precision": prec, "recall": rec, "f1": f1}


def train_ocsvm_pipeline(
    normal: str | Path,
    anomaly: str | Path | None = None,
    outdir: str | Path = "models_ocsvm",
    train_frac: float = 0.8,
    nu: float = 0.05,
    gamma: float | str = "scale",
    target_fpr: float | None = None,
    score_csv: str | Path | None = None,
    summary: bool = False,
):
    """
    Core training + evaluation logic for One-Class SVM.

    Parameters mirror the CLI flags. Returns a dict with training/eval metadata.

    Artifacts written:
      - <outdir>/ocsvm.pkl
      - <outdir>/feature_columns.json
      - <outdir>/metrics.json
      - Optional: score_csv if provided
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # ---- Load & split normals ----
    df_norm = load_features(normal)
    if df_norm.empty:
        raise ValueError("Normal dataset is empty; cannot train.")

    df_norm = df_norm.sample(frac=1.0, random_state=42).reset_index(drop=True)
    n_train = max(1, min(int(len(df_norm) * train_frac), len(df_norm) - 1))
    df_train = df_norm.iloc[:n_train].copy()
    df_hold = df_norm.iloc[n_train:].copy()

    X_train = select_feature_matrix(df_train)
    model = fit_ocsvm(X_train, nu=nu, gamma=gamma)

    # Report resolved gamma used by the fitted OCSVM
    ocsvm = model.named_steps["ocsvm"]
    resolved_gamma = getattr(ocsvm, "_gamma", ocsvm.get_params()["gamma"])
    if isinstance(resolved_gamma, float):
        resolved_gamma = round(resolved_gamma, 5)

    # ---- Build eval set ----
    eval_frames = []
    y_true = []

    X_hold = select_feature_matrix(df_hold)
    eval_frames.append(X_hold)
    y_true.extend([0] * len(X_hold))  # 0 = normal

    df_anom = None
    if anomaly:
        df_anom = load_features(anomaly)
        if not df_anom.empty:
            X_anom = select_feature_matrix(df_anom)
            eval_frames.append(X_anom)
            y_true.extend([1] * len(X_anom))  # 1 = anomaly

    X_eval = pd.concat(eval_frames, axis=0, ignore_index=True)
    y_true = np.array(y_true, dtype=int)

    # ---- Threshold calibration on HOLDOUT NORMALS (if requested) ----
    # decision_function: >0 = inlier, <0 = outlier
    scores_norm_hold = model.decision_function(X_hold)
    scores_eval = model.decision_function(X_eval)

    if (
        target_fpr is not None
        and 0.0 < target_fpr < 0.5
        and len(scores_norm_hold) > 0
    ):
        thresh = float(np.quantile(scores_norm_hold, target_fpr))
    else:
        thresh = 0.0  # default SVM convention

    y_pred = (scores_eval < thresh).astype(int)  # 1 = anomaly

    # ---- Metrics ----
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    metrics = metrics_from_cm(tp, fp, tn, fn)

    result = {
        "nu": float(nu),
        "gamma_input": gamma,
        "gamma_resolved": float(resolved_gamma)
        if isinstance(resolved_gamma, float)
        else str(resolved_gamma),
        "train_frac": float(train_frac),
        "target_fpr": None if target_fpr is None else float(target_fpr),
        "threshold": float(thresh),
        "counts": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "n_eval": int(len(y_true)),
            "n_train_normals": int(len(df_train)),
            "n_holdout_normals": int(len(df_hold)),
            "n_anomalies": int(0 if df_anom is None else len(df_anom)),
        },
        "metrics": metrics,
    }

    # ---- Save artifacts ----
    joblib.dump(model, outdir / "ocsvm.pkl")
    feature_cols = list(X_train.columns)
    (outdir / "feature_columns.json").write_text(
        json.dumps(feature_cols, indent=2)
    )
    (outdir / "metrics.json").write_text(json.dumps(result, indent=2))

    if score_csv:
        score_csv = Path(score_csv)
        pd.DataFrame(
            {"score": scores_eval, "y_true": y_true, "y_pred": y_pred}
        ).to_csv(score_csv, index=False)

    if summary:
        print(f"[+] Model saved to {outdir/'ocsvm.pkl'}")
        print(
            f"[+] OCSVM params — nu: {nu}  gamma: {gamma}  (resolved: {resolved_gamma})"
        )
        print(f"[+] Threshold: {thresh:.5f}  (target_fpr={target_fpr})")
        print(f"[+] Features used: {len(feature_cols)}")
        print(
            "[+] Train normals: {n_train} | Holdout normals: {n_hold} | Anomalies: {n_anom}".format(
                n_train=len(df_train),
                n_hold=len(df_hold),
                n_anom=0 if df_anom is None else len(df_anom),
            )
        )
        print(
            f"[+] Eval samples: {len(y_true)} — "
            f"TP:{tp} FP:{fp} TN:{tn} FN:{fn}"
        )
        print(
            f"[+] Precision: {metrics['precision']:.3f}  "
            f"Recall: {metrics['recall']:.3f}  "
            f"F1: {metrics['f1']:.3f}"
        )

    return result


def main():
    args = parse_args()
    train_ocsvm_pipeline(
        normal=args.normal,
        anomaly=args.anomaly,
        outdir=args.outdir,
        train_frac=args.train_frac,
        nu=args.nu,
        gamma=args.gamma,
        target_fpr=args.target_fpr,
        score_csv=args.score_csv,
        summary=args.summary,
    )


if __name__ == "__main__":
    main()
