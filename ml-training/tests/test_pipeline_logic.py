"""
test_pipeline_logic.py — Milestone 12

Formal pytest version of the synthetic-data logic tests done ad hoc while
building M2 (dedup), M4 (anomaly), M5 (family labels), and M7 (risk engine).
These test the pure logic functions with synthetic data -- they do NOT
require thrember, the real EMBER2024 dataset, or trained models, so they
run anywhere, including CI.

Run (from the ThreatLens/ directory, with the venv active):

    pytest ml-training/tests/test_pipeline_logic.py -v
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


# ---- M2: dedupe.py ----

def test_dedupe_keep_first_removes_exact_duplicates():
    from dedupe import dedupe_keep_first

    rng = np.random.default_rng(0)
    X = rng.random((10, 4)).astype(np.float32)
    y = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
    X[1] = X[0]
    X[2] = X[0]
    X[6] = X[5]

    X_d, y_d, report = dedupe_keep_first(X, y)

    assert report["rows_before"] == 10
    assert report["rows_after"] == 7
    assert report["rows_removed"] == 3
    assert X_d.shape[0] == 7
    assert y_d.tolist() == [0, 0, 0, 1, 1, 1, 1]


def test_dedupe_keep_first_no_duplicates_is_a_noop():
    from dedupe import dedupe_keep_first

    rng = np.random.default_rng(1)
    X = rng.random((20, 4)).astype(np.float32)
    y = np.zeros(20, dtype=int)

    _, _, report = dedupe_keep_first(X, y)
    assert report["rows_removed"] == 0


# ---- M4: train_anomaly.py ----

def test_anomaly_evaluation_separates_clear_outliers():
    from train_anomaly import evaluate_anomaly

    rng = np.random.default_rng(0)
    n = 200
    y = np.zeros(n, dtype=int)
    y[:20] = 1  # 20 "malicious" rows are the ones with high scores
    scores = np.concatenate([rng.uniform(3, 5, 20), rng.uniform(0, 1, n - 20)])

    report = evaluate_anomaly(y, scores, top_pct=0.10)
    assert report["roc_auc"] > 0.9  # scores clearly separate the two groups
    assert report["mean_anomaly_score_malicious"] > report["mean_anomaly_score_benign"]


# ---- M5: train_family.py ----

def test_build_family_labels_excludes_benign_and_buckets_rare():
    from train_family import build_family_labels

    rows = [{"label": 0, "family": ""} for _ in range(10)]
    for fam, count in [("Trojan", 8), ("Ransomware", 6)]:
        rows += [{"label": 1, "family": fam} for _ in range(count)]
    rows += [{"label": 1, "family": "RareFamily"} for _ in range(2)]

    meta_df = pd.DataFrame(rows)
    labels = build_family_labels(meta_df, top_families=["Trojan", "Ransomware"])

    assert sum(l is None for l in labels) == 10  # benign rows excluded
    assert sum(l == "Trojan" for l in labels if l is not None) == 8
    assert sum(l == "other" for l in labels if l is not None) == 2  # rare family bucketed


# ---- M7: risk_engine.py ----

def test_thresholds_are_monotonically_non_decreasing():
    from risk_engine import compute_thresholds

    rng = np.random.default_rng(0)
    n = 2000
    y = rng.integers(0, 2, size=n)
    proba = np.clip(y * 0.7 + rng.normal(0.15, 0.2, size=n), 0, 1)

    t = compute_thresholds(y, proba)
    ordered = [t["thr_recall99"], t["thr_f1_optimal"], t["thr_precision95"], t["thr_precision99"]]
    assert all(ordered[i] <= ordered[i + 1] for i in range(len(ordered) - 1))


def test_tier_classification_escalates_on_high_anomaly():
    from risk_engine import base_tier, escalate, classify_batch

    thresholds = {
        "thr_recall99": 0.2, "thr_f1_optimal": 0.5,
        "thr_precision95": 0.5, "thr_precision99": 0.9,
    }

    # A MODERATE-tier probability with a high anomaly score should escalate
    # to ELEVATED (one tier up), not jump straight to CRITICAL.
    tiers = classify_batch(
        proba=np.array([0.3]),
        anomaly_score=np.array([0.99]),
        thresholds=thresholds,
        anomaly_cutoff=0.5,
    )
    assert tiers[0] == "ELEVATED"


def test_escalate_caps_at_critical():
    from risk_engine import escalate
    assert escalate("CRITICAL") == "CRITICAL"
    assert escalate("HIGH") == "CRITICAL"