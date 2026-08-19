from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


FEATURE_COLUMNS = [
    "requests_per_min",
    "interarrival_cv",
    "endpoint_entropy",
    "login_fail_rate",
    "accounts_per_ip",
    "ips_per_account",
    "ua_rotation_rate",
    "cookie_reuse_rate",
    "header_consistency",
    "tls_consistency",
    "navigation_entropy",
    "status_4xx_rate",
    "session_minutes",
    "automation_score",
]


def baseline_rule_score(df: pd.DataFrame) -> pd.Series:
    """Legacy-style score dominated by request velocity and simple automation signals."""
    rpm = np.clip(df["requests_per_min"] / 45.0, 0, 1)
    low_timing_variance = 1 - df["interarrival_cv"]
    automation = df["automation_score"]
    return (0.55 * rpm + 0.25 * low_timing_variance + 0.20 * automation).clip(0, 1)


def improved_rule_score(df: pd.DataFrame) -> pd.Series:
    """Context-aware score adding account targeting, auth abuse and fingerprint consistency."""
    rpm = np.clip(df["requests_per_min"] / 45.0, 0, 1)
    account_targeting = np.clip((df["accounts_per_ip"] - 1) / 6.0, 0, 1)
    distributed_targeting = np.clip((df["ips_per_account"] - 1) / 4.0, 0, 1)
    fingerprint_risk = 1 - (0.5 * df["header_consistency"] + 0.5 * df["tls_consistency"])
    auth_abuse = 0.55 * df["login_fail_rate"] + 0.45 * df["status_4xx_rate"]
    identity_reuse = df["cookie_reuse_rate"]
    automation = df["automation_score"]

    score = (
        0.15 * rpm
        + 0.18 * account_targeting
        + 0.14 * distributed_targeting
        + 0.18 * auth_abuse
        + 0.12 * fingerprint_risk
        + 0.10 * identity_reuse
        + 0.13 * automation
    )
    return score.clip(0, 1)


def detection_report(y_true: pd.Series | np.ndarray, scores: pd.Series | np.ndarray, threshold: float) -> dict[str, float | int]:
    y = np.asarray(y_true, dtype=int)
    pred = (np.asarray(scores, dtype=float) >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else 0.0,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def tune_threshold(
    y_true: pd.Series | np.ndarray,
    scores: pd.Series | np.ndarray,
    *,
    max_false_positive_rate: float = 0.05,
) -> dict[str, float | int]:
    """Pick the F1-optimal threshold subject to an FP-rate guardrail."""
    candidates = np.linspace(0.10, 0.90, 161)
    reports = []
    for threshold in candidates:
        report = detection_report(y_true, scores, float(threshold))
        if report["false_positive_rate"] <= max_false_positive_rate:
            reports.append({"threshold": float(threshold), **report})
    if not reports:
        reports = [{"threshold": float(t), **detection_report(y_true, scores, float(t))} for t in candidates]
    return max(reports, key=lambda row: (row["f1"], row["recall"], -row["false_positive_rate"]))


def train_xgboost(df: pd.DataFrame, seed: int = 42) -> dict[str, object]:
    X = df[FEATURE_COLUMNS]
    y = df["is_malicious"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.28, random_state=seed, stratify=y
    )
    model = XGBClassifier(
        n_estimators=120,
        max_depth=4,
        learning_rate=0.06,
        subsample=0.85,
        colsample_bytree=0.85,
        eval_metric="logloss",
        random_state=seed,
        n_jobs=2,
    )
    model.fit(X_train, y_train)
    probabilities = model.predict_proba(X_test)[:, 1]
    tuned = tune_threshold(y_test, probabilities, max_false_positive_rate=0.05)
    importances = (
        pd.DataFrame({"feature": FEATURE_COLUMNS, "importance": model.feature_importances_})
        .sort_values("importance", ascending=False)
        .reset_index(drop=True)
    )
    return {
        "model": model,
        "threshold": tuned["threshold"],
        "metrics": tuned,
        "feature_importance": importances,
        "test_index": X_test.index,
        "scores": probabilities,
    }


def isolation_forest_scores(df: pd.DataFrame, seed: int = 42) -> pd.Series:
    X = StandardScaler().fit_transform(df[FEATURE_COLUMNS])
    model = IsolationForest(
        n_estimators=150,
        contamination=0.25,
        random_state=seed,
        n_jobs=2,
    )
    raw = -model.fit(X).score_samples(X)
    normalized = (raw - raw.min()) / max(raw.max() - raw.min(), 1e-9)
    return pd.Series(normalized, index=df.index, name="anomaly_score")


def cluster_malicious_sessions(df: pd.DataFrame) -> pd.Series:
    """Cluster suspicious sessions to surface recurring campaign patterns."""
    suspicious = df[df["is_malicious"] == 1].copy()
    X = StandardScaler().fit_transform(suspicious[FEATURE_COLUMNS])
    labels = DBSCAN(eps=1.8, min_samples=8).fit_predict(X)
    result = pd.Series(-99, index=df.index, dtype=int, name="attack_cluster")
    result.loc[suspicious.index] = labels
    return result
