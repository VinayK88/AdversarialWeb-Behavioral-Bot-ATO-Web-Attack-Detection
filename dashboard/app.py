from __future__ import annotations

import pandas as pd
import streamlit as st

from adversarialweb.data import generate_sessions
from adversarialweb.detection import (
    baseline_rule_score,
    cluster_malicious_sessions,
    detection_report,
    improved_rule_score,
    isolation_forest_scores,
    train_xgboost,
    tune_threshold,
)
from adversarialweb.investigation import credential_stuffing_case, recurring_pattern_summary


st.set_page_config(
    page_title="AdversarialWeb | Security Operations Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
.block-container {max-width: 1540px; padding-top: 1.25rem; padding-bottom: 3rem;}
[data-testid="stSidebar"] {border-right: 1px solid rgba(148,163,184,.14);}
[data-testid="stMetric"] {
    background: linear-gradient(145deg, rgba(15,23,42,.96), rgba(17,24,39,.96));
    border: 1px solid rgba(148,163,184,.18);
    padding: 14px 16px;
    border-radius: 16px;
}
[data-testid="stMetricLabel"] {font-size: .78rem; color: #94a3b8;}
[data-testid="stMetricValue"] {font-size: 1.72rem;}
[data-testid="stTabs"] button {font-weight: 650;}
.aw-hero {
    border: 1px solid rgba(56,189,248,.20);
    border-radius: 20px;
    padding: 24px 26px;
    margin-bottom: 16px;
    background: linear-gradient(115deg, rgba(14,165,233,.10), rgba(99,102,241,.08), rgba(15,23,42,.18));
}
.aw-kicker {font-size:.76rem; text-transform:uppercase; letter-spacing:.14em; color:#38bdf8; font-weight:800;}
.aw-title {font-size:2.25rem; font-weight:850; margin:.25rem 0 .3rem 0;}
.aw-sub {color:#aeb9cc; font-size:1rem; max-width:980px; line-height:1.55;}
.aw-pills {margin-top:14px; display:flex; gap:8px; flex-wrap:wrap;}
.aw-pill {display:inline-block; padding:5px 10px; border:1px solid rgba(148,163,184,.20); border-radius:999px; font-size:.73rem; color:#cbd5e1; background:rgba(15,23,42,.72);}
.aw-callout {border-left:3px solid #38bdf8; padding:10px 14px; background:rgba(14,165,233,.07); border-radius:0 12px 12px 0; margin:8px 0 14px 0;}
.aw-label {font-size:.72rem; text-transform:uppercase; letter-spacing:.1em; color:#64748b; font-weight:800; margin-bottom:3px;}
.aw-value {font-size:.98rem; color:#dbeafe; line-height:1.5;}
</style>
<div class="aw-hero">
  <div class="aw-kicker">Adversarial Traffic Intelligence</div>
  <div class="aw-title">AdversarialWeb</div>
  <div class="aw-sub">Behavioral bot, scraping, credential-stuffing, and account-takeover detection with explicit FP/FN investigation, threshold tuning, anomaly scoring, campaign clustering, and targeted detection improvements.</div>
  <div class="aw-pills">
    <span class="aw-pill">Rules + thresholds</span>
    <span class="aw-pill">XGBoost</span>
    <span class="aw-pill">Isolation Forest</span>
    <span class="aw-pill">DBSCAN</span>
    <span class="aw-pill">FP guardrails</span>
  </div>
</div>
""",
    unsafe_allow_html=True,
)


@st.cache_data
def load_data() -> pd.DataFrame:
    data = generate_sessions()
    data["baseline_score"] = baseline_rule_score(data)
    data["improved_score"] = improved_rule_score(data)
    data["anomaly_score"] = isolation_forest_scores(data)
    data["attack_cluster"] = cluster_malicious_sessions(data)
    return data


@st.cache_resource
def xgb_result() -> dict[str, object]:
    return train_xgboost(generate_sessions())


def pct_delta(new: float, old: float) -> str:
    return f"{new - old:+.1%}"


df = load_data()
case = credential_stuffing_case(df)
xgb = xgb_result()
baseline = case["baseline_metrics"]

with st.sidebar:
    st.markdown("### Investigation controls")
    st.caption("Filter the analyst view without changing the underlying benchmark labels.")

    attack_options = sorted(df["attack_type"].unique().tolist())
    selected_attacks = st.multiselect("Traffic behavior", attack_options, default=attack_options)

    country_options = sorted(df["country"].unique().tolist())
    selected_countries = st.multiselect("Country", country_options, default=country_options)

    min_risk = st.slider("Minimum improved risk score", 0.0, 1.0, 0.0, 0.05)
    fp_guardrail = st.slider("False-positive guardrail", 0.01, 0.10, 0.05, 0.01)

    st.divider()
    st.markdown("### Benchmark")
    st.caption(f"{len(df):,} deterministic synthetic sessions")
    st.caption(f"{int(df['is_malicious'].sum()):,} malicious · {int((df['is_malicious'] == 0).sum()):,} benign")
    st.caption("No external or proprietary traffic is used.")

scores = improved_rule_score(df)
tuned = tune_threshold(df["is_malicious"], scores, max_false_positive_rate=fp_guardrail)
improved = detection_report(df["is_malicious"], scores, float(tuned["threshold"]))
df["improved_prediction"] = (df["improved_score"] >= float(tuned["threshold"])).astype(int)
df["detection_outcome"] = "TN"
df.loc[(df["is_malicious"] == 1) & (df["improved_prediction"] == 1), "detection_outcome"] = "TP"
df.loc[(df["is_malicious"] == 0) & (df["improved_prediction"] == 1), "detection_outcome"] = "FP"
df.loc[(df["is_malicious"] == 1) & (df["improved_prediction"] == 0), "detection_outcome"] = "FN"

filtered = df[
    df["attack_type"].isin(selected_attacks)
    & df["country"].isin(selected_countries)
    & (df["improved_score"] >= min_risk)
].copy()

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Detection recall", f"{improved['recall']:.1%}", pct_delta(improved["recall"], baseline["recall"]))
m2.metric("Precision", f"{improved['precision']:.1%}", pct_delta(improved["precision"], baseline["precision"]))
m3.metric("False-positive rate", f"{improved['false_positive_rate']:.1%}", pct_delta(improved["false_positive_rate"], baseline["false_positive_rate"]))
m4.metric(
    "Credential-stuffing recall",
    f"{case['credential_stuffing_recall_after']:.1%}",
    pct_delta(case["credential_stuffing_recall_after"], case["credential_stuffing_recall_before"]),
)
m5.metric("XGBoost F1", f"{xgb['metrics']['f1']:.1%}")
m6.metric("Selected threshold", f"{tuned['threshold']:.3f}", f"FPR ≤ {fp_guardrail:.0%}")

st.caption(
    f"Filtered analyst view: {len(filtered):,} sessions · "
    f"{int(filtered['is_malicious'].sum()):,} malicious · "
    f"{int((filtered['detection_outcome'] == 'FN').sum()):,} false negatives · "
    f"{int((filtered['detection_outcome'] == 'FP').sum()):,} false positives"
)

executive, investigation, campaigns, models = st.tabs(
    ["Executive overview", "Investigation lab", "Campaign explorer", "Model lab"]
)

with executive:
    st.markdown("### Security posture at a glance")
    left, right = st.columns([1.0, 1.0])

    with left:
        st.markdown("#### Traffic composition")
        traffic = filtered["attack_type"].value_counts().rename_axis("behavior").to_frame("sessions")
        st.bar_chart(traffic)

    with right:
        st.markdown("#### Risk-score distribution")
        risk = (
            filtered.assign(
                score_band=pd.cut(
                    filtered["improved_score"],
                    bins=[0, .2, .35, .5, .65, .8, 1.0],
                    include_lowest=True,
                )
            )
            .groupby(["score_band", "is_malicious"], observed=True)
            .size()
            .unstack(fill_value=0)
        )
        if 0 not in risk.columns:
            risk[0] = 0
        if 1 not in risk.columns:
            risk[1] = 0
        risk = risk[[0, 1]]
        risk.columns = ["Benign", "Malicious"]
        st.bar_chart(risk)

    st.markdown("### Detection operating point")
    quality_table = pd.DataFrame(
        [
            {
                "Detector": "Velocity-heavy baseline",
                "Precision": baseline["precision"],
                "Recall": baseline["recall"],
                "F1": baseline["f1"],
                "FPR": baseline["false_positive_rate"],
                "FNR": baseline["false_negative_rate"],
            },
            {
                "Detector": "Context-aware rules",
                "Precision": improved["precision"],
                "Recall": improved["recall"],
                "F1": improved["f1"],
                "FPR": improved["false_positive_rate"],
                "FNR": improved["false_negative_rate"],
            },
            {
                "Detector": "XGBoost benchmark",
                "Precision": xgb["metrics"]["precision"],
                "Recall": xgb["metrics"]["recall"],
                "F1": xgb["metrics"]["f1"],
                "FPR": xgb["metrics"]["false_positive_rate"],
                "FNR": xgb["metrics"]["false_negative_rate"],
            },
        ]
    )
    st.dataframe(
        quality_table,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Precision": st.column_config.NumberColumn(format="%.1%%"),
            "Recall": st.column_config.NumberColumn(format="%.1%%"),
            "F1": st.column_config.NumberColumn(format="%.1%%"),
            "FPR": st.column_config.NumberColumn(format="%.1%%"),
            "FNR": st.column_config.NumberColumn(format="%.1%%"),
        },
    )

    st.markdown("### High-risk analyst queue")
    queue = filtered.sort_values(["improved_score", "anomaly_score"], ascending=False).head(75)
    st.dataframe(
        queue[
            [
                "session_id", "attack_type", "country", "asn", "endpoint_family",
                "requests_per_min", "login_fail_rate", "accounts_per_ip", "ips_per_account",
                "header_consistency", "tls_consistency", "improved_score", "anomaly_score",
                "attack_cluster", "detection_outcome",
            ]
        ],
        use_container_width=True,
        hide_index=True,
        column_config={
            "improved_score": st.column_config.ProgressColumn("Risk", min_value=0.0, max_value=1.0, format="%.2f"),
            "anomaly_score": st.column_config.ProgressColumn("Anomaly", min_value=0.0, max_value=1.0, format="%.2f"),
        },
    )

with investigation:
    st.markdown("### Detection gap investigation")
    st.markdown(
        f"""
<div class="aw-callout">
  <div class="aw-label">Case study</div>
  <div class="aw-value"><strong>{case['title']}</strong></div>
</div>
""",
        unsafe_allow_html=True,
    )

    a, b, c, d = st.columns(4)
    a.metric("Threat recall before", f"{case['credential_stuffing_recall_before']:.1%}")
    b.metric("Threat recall after", f"{case['credential_stuffing_recall_after']:.1%}")
    c.metric("Baseline misses", f"{case['evidence']['missed_by_baseline']}")
    d.metric("Improved threshold", f"{case['improved_threshold']:.3f}")

    n1, n2, n3 = st.columns(3)
    with n1:
        st.markdown("**Observed behavior**")
        st.info(case["observed"])
    with n2:
        st.markdown("**Root cause**")
        st.warning(case["root_cause"])
    with n3:
        st.markdown("**Targeted fix**")
        st.success(case["fix"])

    left, right = st.columns([1.15, 0.85])
    with left:
        st.markdown("#### Before vs after quality")
        comparison = pd.DataFrame(
            {
                "Baseline": [
                    baseline["precision"],
                    baseline["recall"],
                    1 - baseline["false_positive_rate"],
                    1 - baseline["false_negative_rate"],
                ],
                "Improved": [
                    improved["precision"],
                    improved["recall"],
                    1 - improved["false_positive_rate"],
                    1 - improved["false_negative_rate"],
                ],
            },
            index=["Precision", "Recall", "Specificity", "Detection coverage"],
        )
        st.bar_chart(comparison)

    with right:
        st.markdown("#### Confusion matrix")
        confusion = pd.DataFrame(
            {
                "Predicted benign": [improved["tn"], improved["fn"]],
                "Predicted malicious": [improved["fp"], improved["tp"]],
            },
            index=["Actual benign", "Actual malicious"],
        )
        st.dataframe(confusion, use_container_width=True)
        st.caption(
            f"At threshold {tuned['threshold']:.3f}: {improved['fp']} false positives and {improved['fn']} false negatives."
        )

    st.markdown("#### Investigation evidence")
    evidence_df = pd.DataFrame(
        [
            {"Signal": key.replace("_", " ").title(), "Observed value": value}
            for key, value in case["evidence"].items()
        ]
    )
    st.dataframe(evidence_df, use_container_width=True, hide_index=True)

    with st.expander("Research ticket / escalation summary", expanded=True):
        st.code(
            f"""TITLE
{case['title']}

OBSERVED
{case['observed']}

ROOT CAUSE
{case['root_cause']}

TARGETED CHANGE
{case['fix']}

VALIDATION
Credential-stuffing recall: {case['credential_stuffing_recall_before']:.1%} → {case['credential_stuffing_recall_after']:.1%}
Overall recall: {baseline['recall']:.1%} → {improved['recall']:.1%}
False-positive rate: {baseline['false_positive_rate']:.1%} → {improved['false_positive_rate']:.1%}
""",
            language="text",
        )

with campaigns:
    st.markdown("### Campaign explorer")
    st.caption("Use density-based clustering and historical signatures to identify repeated malicious behavior and emerging detection gaps.")

    clustered = df[df["attack_cluster"] >= 0].copy()
    cluster_view = (
        clustered.groupby(["attack_cluster", "attack_type"], as_index=False)
        .agg(
            sessions=("session_id", "count"),
            median_rpm=("requests_per_min", "median"),
            login_fail=("login_fail_rate", "median"),
            account_targeting=("accounts_per_ip", "median"),
            ua_rotation=("ua_rotation_rate", "median"),
            risk=("improved_score", "median"),
        )
        .sort_values(["sessions", "risk"], ascending=False)
    )

    c1, c2 = st.columns([1.1, 0.9])
    with c1:
        st.markdown("#### Cluster summary")
        st.dataframe(cluster_view, use_container_width=True, hide_index=True)
    with c2:
        st.markdown("#### Malicious traffic by country")
        country_counts = (
            df[df["is_malicious"] == 1]["country"]
            .value_counts()
            .head(12)
            .rename_axis("country")
            .to_frame("sessions")
        )
        st.bar_chart(country_counts)

    st.markdown("#### Historical attack-family signatures")
    st.dataframe(recurring_pattern_summary(df), use_container_width=True, hide_index=True)

    if not cluster_view.empty:
        cluster_ids = sorted(cluster_view["attack_cluster"].unique().tolist())
        selected_cluster = st.selectbox("Inspect cluster", cluster_ids)
        drill = df[df["attack_cluster"] == selected_cluster].sort_values("improved_score", ascending=False)
        st.dataframe(
            drill[
                [
                    "session_id", "attack_type", "country", "asn", "requests_per_min",
                    "login_fail_rate", "accounts_per_ip", "ips_per_account", "ua_rotation_rate",
                    "cookie_reuse_rate", "improved_score", "anomaly_score",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )

with models:
    st.markdown("### Model & threshold lab")

    left, right = st.columns([1.05, 0.95])
    with left:
        st.markdown("#### XGBoost feature importance")
        st.bar_chart(xgb["feature_importance"].head(12).set_index("feature"))
    with right:
        st.markdown("#### Model benchmark")
        st.metric("XGBoost precision", f"{xgb['metrics']['precision']:.1%}")
        st.metric("XGBoost recall", f"{xgb['metrics']['recall']:.1%}")
        st.metric("XGBoost F1", f"{xgb['metrics']['f1']:.1%}")
        st.metric("XGBoost FPR", f"{xgb['metrics']['false_positive_rate']:.1%}")

    st.markdown("#### Threshold trade-off")
    rows = []
    for threshold in [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65]:
        report = detection_report(df["is_malicious"], scores, threshold)
        rows.append(
            {
                "threshold": threshold,
                "recall": report["recall"],
                "precision": report["precision"],
                "false_positive_rate": report["false_positive_rate"],
            }
        )
    tradeoff = pd.DataFrame(rows).set_index("threshold")
    st.line_chart(tradeoff)

    st.success(
        f"Selected context-aware operating point: threshold {tuned['threshold']:.3f} · "
        f"precision {improved['precision']:.1%} · recall {improved['recall']:.1%} · "
        f"FPR {improved['false_positive_rate']:.1%}."
    )

    st.markdown("#### Isolation Forest anomaly profile")
    anomaly = (
        df.assign(
            anomaly_band=pd.cut(df["anomaly_score"], bins=[0, .2, .4, .6, .8, 1.0], include_lowest=True)
        )
        .groupby(["anomaly_band", "is_malicious"], observed=True)
        .size()
        .unstack(fill_value=0)
    )
    if 0 not in anomaly.columns:
        anomaly[0] = 0
    if 1 not in anomaly.columns:
        anomaly[1] = 0
    anomaly = anomaly[[0, 1]]
    anomaly.columns = ["Benign", "Malicious"]
    st.bar_chart(anomaly)

st.divider()
st.caption(
    "All traffic, identities, attack labels, fingerprints, and outcomes are synthetic. "
    "This dashboard demonstrates methodology and software implementation, not real-world production efficacy."
)
