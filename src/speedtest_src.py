from __future__ import annotations
import numpy as np, pandas as pd
from pathlib import Path
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import RobustScaler
from sklearn.pipeline import Pipeline
from sklearn.ensemble import IsolationForest

def load_features(path: str | Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    return df

ID_COLS = [
    "flow_id","src_ip","dst_ip","src_port","dst_port","protocol",
    "first_seen","last_seen"
]

def select_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Keep numeric columns that are NOT identifiers."""
    X = df.select_dtypes(include=[np.number]).copy()

    # treat ports as identifiers for now (comment out to include them)
    for col in ("src_port", "dst_port"):
        if col in X.columns:
            X.drop(columns=[col], inplace=True)

    # drop common ID/timing cols if they slipped in as numeric
    X.drop(columns=[c for c in ID_COLS if c in X.columns],
           errors="ignore", inplace=True)

    X = X.fillna(0.0)
    return X

def metrics_from_cm(tp, fp, tn, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {"precision": prec, "recall": rec, "f1": f1}

def fit_iforest(X_train: pd.DataFrame, contamination: float) -> IsolationForest:
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)
    return model

##############################
#### inserted isolation forest
##############################
def train_iforest(
    normal: str | Path,
    contamination: float = 0.05,
    train_frac: float = 0.8,
    random_state: int = 42,
):
    """
    Train IsolationForest on NORMAL flows only.

    Returns:
      model, feature_cols, X_holdout, y_holdout
    where X_holdout is the normal holdout feature matrix (for threshold calibration).
    """
    df_norm = load_features(normal)
    if df_norm.empty:
        raise ValueError("Normal dataset is empty; cannot train.")

    df_norm = df_norm.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    n_train = max(1, min(int(len(df_norm) * train_frac), len(df_norm) - 1))

    df_train = df_norm.iloc[:n_train].copy()
    df_hold  = df_norm.iloc[n_train:].copy()

    X_train = select_feature_matrix(df_train)
    X_hold  = select_feature_matrix(df_hold)

    model = fit_iforest(X_train, contamination=contamination)
    feature_cols = list(X_train.columns)

    return model, feature_cols, X_hold


def evaluate_iforest(
    model,
    X_norm_hold: pd.DataFrame,
    anomaly: str | Path | None = None,
    target_fpr: float | None = None,
):
    """
    Evaluate IsolationForest on:
      - normal holdout feature matrix (X_norm_hold)
      - optional anomaly flows from CSV path

    Returns:
      result dict including metrics, confusion counts, threshold
    """
    eval_frames = [X_norm_hold]
    y_true = [0] * len(X_norm_hold)

    n_anom = 0
    if anomaly:
        df_anom = load_features(anomaly)
        if not df_anom.empty:
            X_anom = select_feature_matrix(df_anom)
            eval_frames.append(X_anom)
            y_true.extend([1] * len(X_anom))
            n_anom = len(X_anom)

    X_eval = pd.concat(eval_frames, axis=0, ignore_index=True)
    y_true = np.asarray(y_true, dtype=int)

    # Scores: >0 normal, <0 anomalous
    scores_norm = model.decision_function(X_norm_hold)
    scores_eval = model.decision_function(X_eval)

    if target_fpr is not None and 0.0 < target_fpr < 0.5 and len(scores_norm) > 0:
        thresh = float(np.quantile(scores_norm, target_fpr))
    else:
        thresh = 0.0

    y_pred = (scores_eval < thresh).astype(int)

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    return {
        "target_fpr": None if target_fpr is None else float(target_fpr),
        "threshold": float(thresh),
        "counts": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "n_eval": int(len(y_true)),
            "n_holdout_normals": int(len(X_norm_hold)),
            "n_anomalies": int(n_anom),
        },
        "metrics": metrics_from_cm(tp, fp, tn, fn),
        # handy for notebook plots/diagnostics:
        "scores_eval": scores_eval,
        "y_true": y_true,
        "y_pred": y_pred,
    }


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

###################
#### inserted OCSVM
###################

def train_ocsvm(
    normal: str | Path,
    train_frac: float = 0.8,
    nu: float = 0.05,
    gamma: float | str = "scale",
    random_state: int = 42,
):
    """
    Train One-Class SVM on NORMAL flows only.

    Returns:
      model, meta, X_holdout

    meta includes nu, gamma_input, gamma_resolved (rounded if float).
    X_holdout is the normal holdout feature matrix (for threshold calibration).
    """
    df_norm = load_features(normal)
    if df_norm.empty:
        raise ValueError("Normal dataset is empty; cannot train.")

    df_norm = df_norm.sample(frac=1.0, random_state=random_state).reset_index(drop=True)
    n_train = max(1, min(int(len(df_norm) * train_frac), len(df_norm) - 1))

    df_train = df_norm.iloc[:n_train].copy()
    df_hold  = df_norm.iloc[n_train:].copy()

    X_train = select_feature_matrix(df_train)
    X_hold  = select_feature_matrix(df_hold)

    model = fit_ocsvm(X_train, nu=nu, gamma=gamma)

    # resolved gamma from fitted sklearn OneClassSVM inside Pipeline
    ocsvm = model.named_steps["ocsvm"]
    resolved_gamma = getattr(ocsvm, "_gamma", ocsvm.get_params().get("gamma", gamma))
    if isinstance(resolved_gamma, float):
        resolved_gamma = round(resolved_gamma, 5)

    meta = {
        "nu": float(nu),
        "gamma_input": gamma,
        "gamma_resolved": float(resolved_gamma) if isinstance(resolved_gamma, float) else str(resolved_gamma),
        "train_frac": float(train_frac),
        "n_train_normals": int(len(df_train)),
        "n_holdout_normals": int(len(df_hold)),
    }

    return model, meta, X_hold


def evaluate_ocsvm(
    model,
    X_norm_hold: pd.DataFrame,
    anomaly: str | Path | None = None,
    target_fpr: float | None = None,
):
    """
    Evaluate One-Class SVM on:
      - normal holdout feature matrix (X_norm_hold)
      - optional anomaly flows from CSV path

    Returns:
      result dict including metrics, confusion counts, threshold, and scores.
    """
    eval_frames = [X_norm_hold]
    y_true = [0] * len(X_norm_hold)

    n_anom = 0
    if anomaly:
        df_anom = load_features(anomaly)
        if not df_anom.empty:
            X_anom = select_feature_matrix(df_anom)
            eval_frames.append(X_anom)
            y_true.extend([1] * len(X_anom))
            n_anom = len(X_anom)

    X_eval = pd.concat(eval_frames, axis=0, ignore_index=True)
    y_true = np.asarray(y_true, dtype=int)

    # Scores: >0 normal, <0 anomalous
    scores_norm = model.decision_function(X_norm_hold)
    scores_eval = model.decision_function(X_eval)

    if target_fpr is not None and 0.0 < target_fpr < 0.5 and len(scores_norm) > 0:
        thresh = float(np.quantile(scores_norm, target_fpr))
    else:
        thresh = 0.0  # default SVM convention

    y_pred = (scores_eval < thresh).astype(int)

    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    return {
        "target_fpr": None if target_fpr is None else float(target_fpr),
        "threshold": float(thresh),
        "counts": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "n_eval": int(len(y_true)),
            "n_holdout_normals": int(len(X_norm_hold)),
            "n_anomalies": int(n_anom),
        },
        "metrics": metrics_from_cm(tp, fp, tn, fn),
        # handy for notebook plots/diagnostics:
        "scores_eval": scores_eval,
        "y_true": y_true,
        "y_pred": y_pred,
    }

speedtest_train = "/tests/speedtest/data/features/normal_flows.csv"
speedtest_eval = "/tests/speedtest/data/features/scan_flows.csv"

