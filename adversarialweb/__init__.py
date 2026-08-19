"""AdversarialWeb: behavioral bot, ATO, scraping, and credential-stuffing detection."""

from .data import generate_sessions
from .detection import (
    FEATURE_COLUMNS,
    detection_report,
    improved_rule_score,
    baseline_rule_score,
    tune_threshold,
)

__all__ = [
    "generate_sessions",
    "FEATURE_COLUMNS",
    "detection_report",
    "baseline_rule_score",
    "improved_rule_score",
    "tune_threshold",
]
__version__ = "0.1.0"
