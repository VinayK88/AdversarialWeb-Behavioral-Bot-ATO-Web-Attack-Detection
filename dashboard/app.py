from __future__ import annotations

import pandas as pd
import streamlit as st

from adversarialweb.data import generate_sessions
from adversarialweb.detection import (
    baseline_rule_score,
    cluster_malicious_sessions,
    improved_rule_score,
    isolation_forest_scores,
    train_xgboost,
    tune_threshold,
)
from adversarialweb.investigation import credential_stuffing_case, recurring_pattern_summary


st.set_page_config(
    page_title="AdversarialWeb | Bot & ATO Detection",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
<style>
.block-container {max-width: 1500px; padding-top: 1.6rem;}
[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.22); border-radius: 14px; padding: 12px 14px;}
.hero {padding: 20px 22px; border: 1px solid rgba(128,128,128,.20); border-radius: 18px; margin-bottom: 16px;}
.kicker {font-size:.78rem; text-transform:uppercase; letter-spacing:.12em; opacity:.72; font-weight:700;}
.title {font-size:2.15rem; font-weight:800; margin:.2rem 0;}
.sub {max-width:980px; opacity:.78; line-height:1.5;}
</style>
<div class="hero">
<div class="kicker">Adversarial Traffic Intelligence</div>
<div class="title">AdversarialWeb</div>
<div class="sub">Behavioral bot, scraping, credential-stuffing and account-takeover detection with explicit false-positive / false-negative investigation, threshold tuning, clustering, and targeted detection improvements.</div>
</div>
""",
    unsafe_allow_html=True,
)

@st.cache_data
def load_data() -> pd.DataFrame:
    df = generate_sessions()
    df["baseline_score"] = baseline_rule_score(df)
    df["improved_score"] = improved_rule_score(df)
    df["anomaly_score"] = isolation_forest_scores(df)
    df["attack_cluster"] = cluster_malicious_sessions(df)
    return df


@st.cache_resource
def xgb_result() -> dict[str, object]:
    return train_xgboost(generate_sessions())


df = load_data()
case = credential_stuffing_case(df)
xgb = xgb_result()
improved = case["improved_metrics"]
baseline = case["baseline_metrics"]

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Detection recall", f"{improved['recall']:.1%}", f"{improved['recall']-baseline['recall']:+.1%}")
m2.metric("False-positive rate", f"{improved['false_positive_rate']:.1%}", f"{improved['false_positive_rate']-baseline['false_positive_rate']:+.1%}")
m3.metric("Credential-stuffing recall", f"{case['credential_stuffing_recall_after']:.1%}", f"{case['credential_stuffing_recall_after']-case['credential_stuffing_recall_before']:+.1%}")
m4.metric("XGBoost F1", f"{xgb['metrics']['f1']:.1%}")
m5.metric("Malicious sessions", f"{int(df['is_malicious'].sum()):,}")

overview, investigation, patterns, models = st.tabs(
    ["Traffic overview", "Detection gap investigation", "Attack-pattern miner", "Model diagnostics"]
)

with overview:
    left, right = st.columns(2)
    with left:
        st.subheader("Traffic by behavior")
        counts = df["attack_type"].value_counts().to_frame("sessions")
        st.bar_chart(counts)
    with right:
        st.subheader("Risk-score distribution")
        risk = (
            df.assign(score_band=pd.cut(df["improved_score"], bins=[0, .2, .35, .5, .65, 1.0], include_lowest=True))
            .groupby(["score_band", "is_malicious"], observed=True)
            .size()
            .unstack(fill_value=0)
        )
        risk.columns = ["Benign", "Malicious"]
        st.bar_chart(risk)

    st.subheader("Session explorer")
    selected = st.multiselect(
        "Attack type",
        sorted(df["attack_type"].unique()),
        default=sorted(df["attack_type"].unique()),
    )
    view = df[df["attack_type"].isin(selected)].copy()
    st.dataframe(
        view[
            [
                "session_id", "attack_type", "country", "asn", "http_version", "method",
                "endpoint_family", "requests_per_min", "login_fail_rate", "accounts_per_ip",
                "ips_per_account", "ua_rotation_rate", "cookie_reuse_rate",
                "header_consistency", "tls_consistency", "baseline_score",
                "improved_score", "anomaly_score",
            ]
        ].head(800),
        use_container_width=True,
        hide_index=True,
    )

with investigation:
    st.subheader("Detection gap investigation")
    st.error(case["title"])
    a, b, c = st.columns(3)
    a.metric("CS recall before", f"{case['credential_stuffing_recall_before']:.1%}")
    b.metric("CS recall after", f"{case['credential_stuffing_recall_after']:.1%}")
    c.metric("Baseline misses", f"{case['evidence']['missed_by_baseline']}")

    st.markdown("#### Observed")
    st.write(case["observed"])
    st.markdown("#### Root cause")
    st.write(case["root_cause"])
    st.markdown("#### Targeted fix")
    st.write(case["fix"])

    comparison = pd.DataFrame(
        {
            "Baseline": [
                baseline["precision"], baseline["recall"],
                1 - baseline["false_positive_rate"], 1 - baseline["false_negative_rate"],
            ],
            "Improved": [
                improved["precision"], improved["recall"],
                1 - improved["false_positive_rate"], 1 - improved["false_negative_rate"],
            ],
        },
        index=["Precision", "Recall", "Specificity", "Detection coverage"],
    )
    st.bar_chart(comparison)

    st.markdown("#### Investigation evidence")
    evidence_df = pd.DataFrame(
        [{"signal": k.replace("_", " "), "value": v} for k, v in case["evidence"].items()]
    )
    st.dataframe(evidence_df, use_container_width=True, hide_index=True)

    st.info(
        "This workflow mirrors an adversarial-response escalation: reproduce the miss, isolate the failure mode, "
        "change rule/feature logic, re-tune under an FP guardrail, and verify the targeted threat family improves."
    )

with patterns:
    st.subheader("Attack-pattern miner")
    st.caption("Historical cases are clustered and summarized to surface recurring campaigns and detection gaps.")
    cluster_view = (
        df[df["attack_cluster"] >= 0]
        .groupby(["attack_cluster", "attack_type"], as_index=False)
        .agg(
            sessions=("session_id", "count"),
            median_rpm=("requests_per_min", "median"),
            login_fail=("login_fail_rate", "median"),
            account_targeting=("accounts_per_ip", "median"),
            ua_rotation=("ua_rotation_rate", "median"),
        )
        .sort_values("sessions", ascending=False)
    )
    st.dataframe(cluster_view, use_container_width=True, hide_index=True)
    st.markdown("#### Historical attack-family signatures")
    st.dataframe(recurring_pattern_summary(df), use_container_width=True, hide_index=True)

with models:
    st.subheader("Model diagnostics")
    st.markdown("#### XGBoost feature importance")
    st.bar_chart(xgb["feature_importance"].head(10).set_index("feature"))

    st.markdown("#### Threshold trade-off")
    rows = []
    scores = improved_rule_score(df)
    for threshold in [0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60]:
        pred = scores >= threshold
        benign = df["is_malicious"] == 0
        malicious = ~benign
        fp_rate = float(pred[benign].mean())
        recall = float(pred[malicious].mean())
        rows.append({"threshold": threshold, "recall": recall, "false_positive_rate": fp_rate})
    tradeoff = pd.DataFrame(rows).set_index("threshold")
    st.line_chart(tradeoff)

    tuned = tune_threshold(df["is_malicious"], scores, max_false_positive_rate=0.05)
    st.success(
        f"Selected threshold: {tuned['threshold']:.3f} · recall {tuned['recall']:.1%} · "
        f"FPR {tuned['false_positive_rate']:.1%} · F1 {tuned['f1']:.1%}"
    )

st.caption("All traffic, identities, attack labels, and outcomes are synthetic. The repository demonstrates methodology and software implementation, not Akamai proprietary data or production efficacy.")
