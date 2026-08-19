import unittest

from adversarialweb.data import generate_sessions
from adversarialweb.detection import (
    FEATURE_COLUMNS,
    cluster_malicious_sessions,
    improved_rule_score,
    isolation_forest_scores,
    train_xgboost,
    tune_threshold,
)
from adversarialweb.investigation import credential_stuffing_case


class AdversarialWebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.df = generate_sessions(n=1200, seed=42)

    def test_dataset_has_required_attack_classes_and_features(self):
        self.assertTrue({"benign", "scraping", "credential_stuffing", "ato", "bot"}.issubset(set(self.df["attack_type"])))
        self.assertTrue(set(FEATURE_COLUMNS).issubset(self.df.columns))
        self.assertGreater(self.df["is_malicious"].mean(), 0.20)
        self.assertLess(self.df["is_malicious"].mean(), 0.45)

    def test_improved_detector_respects_fp_guardrail(self):
        tuned = tune_threshold(self.df["is_malicious"], improved_rule_score(self.df), max_false_positive_rate=0.05)
        self.assertLessEqual(tuned["false_positive_rate"], 0.05 + 1e-9)
        self.assertGreater(tuned["recall"], 0.70)

    def test_credential_stuffing_fix_improves_targeted_recall(self):
        case = credential_stuffing_case(self.df)
        self.assertGreater(case["credential_stuffing_recall_after"], case["credential_stuffing_recall_before"])
        self.assertGreater(case["credential_stuffing_recall_after"], 0.75)

    def test_unsupervised_outputs_align_to_rows(self):
        anomaly = isolation_forest_scores(self.df)
        clusters = cluster_malicious_sessions(self.df)
        self.assertEqual(len(anomaly), len(self.df))
        self.assertEqual(len(clusters), len(self.df))
        self.assertTrue(anomaly.between(0, 1).all())

    def test_xgboost_baseline_is_useful(self):
        result = train_xgboost(self.df, seed=42)
        self.assertGreater(result["metrics"]["precision"], 0.80)
        self.assertGreater(result["metrics"]["recall"], 0.80)
        self.assertEqual(len(result["feature_importance"]), len(FEATURE_COLUMNS))


if __name__ == "__main__":
    unittest.main()
