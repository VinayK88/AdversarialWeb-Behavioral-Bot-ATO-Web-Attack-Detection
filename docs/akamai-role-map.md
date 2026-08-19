# Akamai Global Web Security Role Map

This document maps AdversarialWeb directly to the responsibilities of an adversarial-response / web-security data scientist.

| Role expectation | AdversarialWeb evidence |
|---|---|
| Investigate false positives and false negatives | `credential_stuffing_case()` reproduces a detection miss, quantifies before/after recall, and tracks FP/FN metrics. |
| Analyze traffic patterns and behavioral signals | Synthetic session telemetry includes request rate, inter-arrival variability, endpoint entropy, account targeting, user-agent rotation, cookie reuse, HTTP version, header consistency, and TLS fingerprint consistency. |
| Tune rules and thresholds | Baseline and improved rule scores are compared, then the improved detector is re-tuned under an explicit false-positive-rate guardrail. |
| Improve features | The targeted fix adds account-targeting, distributed-targeting, authentication-abuse, identity-reuse, and HTTP/TLS consistency signals. |
| Identify recurring attack patterns | DBSCAN clusters suspicious sessions and the historical pattern summary aggregates recurring attack-family signatures. |
| Develop detections for evolving threats | The project compares deterministic rules, XGBoost supervised detection, and Isolation Forest anomaly scoring. |
| Bot / scraping / ATO / credential-stuffing experience | The benchmark contains dedicated synthetic behaviors for all four threat families. |
| Python and SQL at scale | The Python package performs feature generation, detection, evaluation, clustering, and investigation; `sql/investigation_features.sql` demonstrates warehouse feature construction. |
| Communicate findings across teams | The dashboard includes an investigation narrative with observed behavior, root cause, targeted fix, evidence, and measurable impact suitable for security operations, account teams, professional services, and research. |
| Production engineering mindset | Docker packaging, CLI smoke tests, multi-version GitHub Actions CI, explicit synthetic-data boundary, and reproducible tests are included. |

## Interview story

A strong walkthrough is the distributed credential-stuffing case:

1. A velocity-heavy detector misses a distributed campaign because no single IP is unusually noisy.
2. The investigation shows repeated account targeting, elevated authentication failures, source distribution, and client-fingerprint inconsistency.
3. The fix reduces dependence on raw request velocity and introduces account, identity, authentication, and HTTP/TLS behavioral signals.
4. The threshold is re-tuned under a false-positive guardrail rather than maximizing recall without regard for customer friction.
5. The dashboard verifies before-vs-after performance and makes the residual trade-off visible.

The key message is that the project treats adversarial detection as an iterative investigation and product-quality problem, not only a classification problem.
