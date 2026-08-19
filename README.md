<div align="center">

# AdversarialWeb

### Behavioral Bot · Scraping · Credential Stuffing · Account Takeover Detection

**Investigate adversarial web traffic, explain detection gaps, and improve defenses without blindly increasing false positives.**

![Python](https://img.shields.io/badge/Python-3.10--3.12-3776AB?logo=python&logoColor=white)
![ML](https://img.shields.io/badge/ML-XGBoost%20%7C%20Isolation%20Forest%20%7C%20DBSCAN-6A5ACD)
![Dashboard](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B?logo=streamlit&logoColor=white)
![Data](https://img.shields.io/badge/Data-Synthetic%20Only-7B61FF)
[![CI](https://github.com/VinayK88/AdversarialWeb-Behavioral-Bot-ATO-Web-Attack-Detection/actions/workflows/ci.yml/badge.svg)](https://github.com/VinayK88/AdversarialWeb-Behavioral-Bot-ATO-Web-Attack-Detection/actions/workflows/ci.yml)

</div>

---

AdversarialWeb is a production-style security data-science project for **bot abuse, scraping, credential stuffing, and account takeover (ATO)**. It is designed around the work an adversarial-response or web-security data-science team actually performs:

**observe → detect → investigate FP/FN → isolate root cause → change rules/features/thresholds → re-evaluate → mine recurring attack patterns**

The project intentionally goes beyond “train a classifier.” It makes **false positives, false negatives, detection gaps, threshold trade-offs, root-cause analysis, and product-facing remediation** first-class outputs.

## What it demonstrates

- Large-scale-style web/session telemetry modeled with Python and pandas
- HTTP and TLS-adjacent behavioral signals
- Bot, scraping, credential-stuffing, and ATO behavior
- Rule/threshold tuning with explicit false-positive guardrails
- XGBoost supervised detection
- Isolation Forest anomaly detection
- DBSCAN campaign clustering
- FP/FN investigation and targeted detection improvements
- Historical attack-pattern mining
- Streamlit investigation dashboard
- Docker packaging and multi-version GitHub Actions CI
- Example SQL feature engineering for request/session telemetry

## Detection signals

The synthetic telemetry includes:

| Signal family | Examples |
|---|---|
| Request behavior | requests/min, inter-arrival variability, endpoint entropy, session duration |
| Authentication abuse | login-failure rate, 4xx rate, accounts per IP, IPs per account |
| Client identity | user-agent rotation, cookie reuse |
| HTTP/TLS consistency | header consistency, TLS fingerprint consistency, HTTP version |
| Navigation behavior | navigation entropy, endpoint family |
| Automation | composite automation score |

These signals are intentionally overlapping so benign power users and adversarial traffic are not perfectly separable.

## Architecture

```text
Synthetic request/session telemetry
        │
        ▼
Behavioral feature layer
        │
        ├──────── Rules + thresholds
        ├──────── XGBoost classifier
        ├──────── Isolation Forest anomaly model
        └──────── DBSCAN campaign clustering
        │
        ▼
Detection quality evaluation
precision · recall · FPR · FNR · F1
        │
        ▼
FP/FN investigation
        │
        ├─ reproduce miss
        ├─ isolate root cause
        ├─ change feature/rule logic
        ├─ re-tune threshold under FP guardrail
        └─ verify targeted improvement
        │
        ▼
Historical pattern mining + research ticket
        │
        ▼
Streamlit analyst / executive dashboard
```

## Flagship investigation: distributed credential stuffing

The included investigation reproduces a common failure mode: a campaign distributes authentication attempts across many source IPs, keeping **per-IP velocity moderate**.

### Baseline weakness

The baseline detector overweights:

```text
requests_per_minute
+ timing regularity
+ generic automation score
```

That creates a blind spot for low-and-slow, distributed account targeting.

### Root-cause fix

The improved detector adds:

```text
account_targeting
+ distributed_targeting
+ login_failure_behavior
+ 4xx behavior
+ cookie reuse
+ header consistency
+ TLS consistency
+ automation
```

It then re-tunes the threshold under a **≤5% false-positive-rate guardrail** and explicitly checks credential-stuffing recall before vs. after the fix.

This is the key project story: **the fix is not “use a bigger model”; it is identify why the detector missed the attack and make a targeted, measurable improvement.**

## Dashboard

Run:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dashboard]'
streamlit run dashboard/app.py
```

The dashboard contains four views:

1. **Traffic overview** — attack mix, risk-score distribution, and session explorer
2. **Detection gap investigation** — FP/FN metrics, root cause, targeted fix, and before/after results
3. **Attack-pattern miner** — DBSCAN clusters and recurring historical signatures
4. **Model diagnostics** — XGBoost feature importance and threshold trade-offs

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

adversarialweb
python -m unittest discover -s tests -v
```

## Docker

```bash
docker build -t adversarialweb .
docker run --rm -p 8501:8501 adversarialweb
```

Then open the Streamlit app on port `8501`.

## Repository map

```text
.
├── adversarialweb/
│   ├── data.py              synthetic HTTP/session telemetry
│   ├── detection.py         rules, threshold tuning, XGBoost, Isolation Forest, DBSCAN
│   ├── investigation.py     FP/FN root-cause workflow + historical pattern mining
│   └── cli.py               compact reproducible report
├── dashboard/
│   └── app.py               analyst + executive Streamlit dashboard
├── sql/
│   └── investigation_features.sql
├── tests/
│   └── test_core.py
├── .github/workflows/ci.yml
├── Dockerfile
└── pyproject.toml
```

## Security-research workflow

A research ticket produced from this type of investigation should capture:

```text
Observed behavior
↓
Threat / customer impact
↓
Current detector behavior
↓
False-positive / false-negative evidence
↓
Root cause
↓
Targeted rule / threshold / feature change
↓
Before-vs-after metrics
↓
Residual risk
↓
Follow-up research
```

That creates a clean bridge between customer escalations, security operations, professional services, and the core detection/data-science team.

## Production evolution

The strongest next steps would be:

- streaming request aggregation with Kafka/Flink/Spark Structured Streaming;
- real JA4/JA3-style TLS fingerprint pipelines;
- graph features linking IPs, accounts, cookies, devices, and sessions;
- online threshold calibration by customer/application segment;
- time-aware validation to avoid campaign leakage;
- cost-sensitive learning for asymmetric FP/FN impact;
- drift monitoring for bot behavior and attack-family prevalence;
- analyst feedback loops and active learning;
- shadow deployment and champion/challenger detection policies;
- low-latency feature serving for edge enforcement.

## Evaluation boundary

All IPs, identities, traffic events, labels, fingerprints, and outcomes in this repository are synthetic. The project demonstrates methodology, software architecture, evaluation, and investigation workflows only. It does **not** use Akamai data and does not claim production detection efficacy.

---

<div align="center">

**Good adversarial-response work is not just finding malicious traffic—it is explaining why the current system missed or misclassified it, fixing the failure mode, and proving the fix improves security without creating unacceptable customer friction.**

</div>
