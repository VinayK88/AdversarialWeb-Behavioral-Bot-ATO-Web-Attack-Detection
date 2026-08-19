from __future__ import annotations

import pandas as pd

from .detection import baseline_rule_score, detection_report, improved_rule_score, tune_threshold


def credential_stuffing_case(df: pd.DataFrame) -> dict[str, object]:
    """Build a reproducible FP/FN investigation that mirrors a product escalation."""
    baseline_scores = baseline_rule_score(df)
    improved_scores = improved_rule_score(df)

    baseline_threshold = 0.42
    baseline = detection_report(df["is_malicious"], baseline_scores, baseline_threshold)
    improved = tune_threshold(df["is_malicious"], improved_scores, max_false_positive_rate=0.05)

    cs = df[df["attack_type"] == "credential_stuffing"]
    baseline_cs_recall = float((baseline_scores.loc[cs.index] >= baseline_threshold).mean())
    improved_cs_recall = float((improved_scores.loc[cs.index] >= improved["threshold"]).mean())

    missed = cs[baseline_scores.loc[cs.index] < baseline_threshold]
    evidence = {
        "median_requests_per_min": float(cs["requests_per_min"].median()),
        "median_login_fail_rate": float(cs["login_fail_rate"].median()),
        "median_accounts_per_ip": float(cs["accounts_per_ip"].median()),
        "median_ips_per_account": float(cs["ips_per_account"].median()),
        "median_ua_rotation_rate": float(cs["ua_rotation_rate"].median()),
        "missed_by_baseline": int(len(missed)),
    }

    return {
        "title": "Distributed credential stuffing bypasses velocity-heavy detection",
        "observed": (
            "A credential-stuffing campaign distributes attempts across source IPs, "
            "keeping per-IP request velocity moderate while repeatedly targeting accounts."
        ),
        "root_cause": (
            "The baseline score overweights requests-per-minute and underweights account targeting, "
            "login-failure behavior, distributed source patterns, and fingerprint inconsistency."
        ),
        "fix": (
            "Reduce velocity dependence and add account-targeting, distributed-targeting, auth-abuse, "
            "cookie-reuse, header/TLS consistency, and automation features."
        ),
        "baseline_threshold": baseline_threshold,
        "improved_threshold": float(improved["threshold"]),
        "baseline_metrics": baseline,
        "improved_metrics": improved,
        "credential_stuffing_recall_before": baseline_cs_recall,
        "credential_stuffing_recall_after": improved_cs_recall,
        "evidence": evidence,
    }


def recurring_pattern_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Summarize historical attack families for research-ticket generation."""
    grouped = (
        df.groupby("attack_type", as_index=False)
        .agg(
            sessions=("session_id", "count"),
            rpm=("requests_per_min", "median"),
            login_fail=("login_fail_rate", "median"),
            accounts_per_ip=("accounts_per_ip", "median"),
            ips_per_account=("ips_per_account", "median"),
            ua_rotation=("ua_rotation_rate", "median"),
            automation=("automation_score", "median"),
        )
        .sort_values("sessions", ascending=False)
    )
    return grouped[grouped["attack_type"] != "benign"].reset_index(drop=True)
