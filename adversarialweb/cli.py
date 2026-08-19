from __future__ import annotations

import json

from .data import generate_sessions
from .detection import improved_rule_score, tune_threshold
from .investigation import credential_stuffing_case


def main() -> None:
    df = generate_sessions()
    tuned = tune_threshold(df["is_malicious"], improved_rule_score(df))
    case = credential_stuffing_case(df)
    payload = {
        "dataset": {
            "sessions": len(df),
            "malicious_rate": round(float(df["is_malicious"].mean()), 4),
        },
        "improved_detector": {
            k: round(v, 4) if isinstance(v, float) else v
            for k, v in tuned.items()
        },
        "credential_stuffing_case": {
            "recall_before": round(case["credential_stuffing_recall_before"], 4),
            "recall_after": round(case["credential_stuffing_recall_after"], 4),
        },
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
