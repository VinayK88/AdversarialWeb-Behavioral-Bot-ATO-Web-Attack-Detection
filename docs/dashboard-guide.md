# AdversarialWeb Dashboard Guide

The Streamlit dashboard is designed to support both high-level detection review and analyst-level investigation.

## Executive overview

Use this view to understand the current operating point of the context-aware detector.

- Review recall, precision, false-positive rate, and selected threshold.
- Compare the velocity-heavy baseline, context-aware rules, and XGBoost benchmark.
- Inspect traffic mix and risk-score distributions.
- Use the high-risk queue to find sessions that deserve analyst attention.

## Investigation lab

Use this view to reproduce and explain a detection gap.

The included case study demonstrates a distributed credential-stuffing campaign that bypasses a velocity-heavy detector. The workflow presents:

1. observed behavior;
2. root cause;
3. targeted feature/rule change;
4. before-vs-after detection quality;
5. confusion-matrix impact;
6. supporting evidence; and
7. a research-ticket summary suitable for escalation.

## Campaign explorer

Use this view to inspect recurring malicious behavior.

- DBSCAN groups suspicious sessions into behavioral clusters.
- Historical summaries show common signatures by threat family.
- Country and cluster drill-downs help identify repeated campaign structure.

## Model lab

Use this view to understand why a detector was selected and how its threshold affects production trade-offs.

- XGBoost feature importance highlights influential behavioral signals.
- Threshold curves show recall, precision, and false-positive-rate trade-offs.
- Isolation Forest distributions show where unusual traffic concentrates.
- The selected operating point is constrained by the configurable false-positive guardrail.

## Filters

The sidebar can filter the analyst view by traffic behavior, country, and minimum risk score. The false-positive guardrail controls threshold tuning for the context-aware rules.

All data shown by the dashboard is synthetic and deterministic so the project remains reproducible and safe to share publicly.
