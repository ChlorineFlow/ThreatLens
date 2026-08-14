"""
risk_engine.py — Milestone 7

Combines Model 1 (malware detection probability) and Model 2 (anomaly
score) into a single interpretable threat level: LOW / MODERATE /
ELEVATED / HIGH / CRITICAL.

Thresholds are NOT arbitrary — each is anchored to an actual point on the
detector's precision-recall curve, computed from the deduplicated test set
(see compute_thresholds()):

    thr_recall99   - smallest probability where recall >= 99%
                     (below this, we're fairly confident it's benign)
    thr_f1_optimal - the probability that maximizes F1 (the standard
                     malicious/benign decision boundary)
    thr_precision95 - smallest probability where precision >= 95%
    thr_precision99 - smallest probability where precision >= 99%

A sample's BASE tier comes from where its probability falls among these.
Its tier is escalated by ONE level if its anomaly score is also in the
top ANOMALY_TOP_PCT of the test set's anomaly-score distribution (default
10%, matching M4's own precision-at-top-10% metric) AND it isn't already
CRITICAL — this is what makes the anomaly signal actually useful: it
matters most for samples the detector itself is less confident about.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\risk_engine.py --data-dir ml-training\\data --test-subset test_dedup
"""

import argparse
import sys
from pathlib import Path

import numpy as np


ANOMALY_TOP_PCT = 0.10

TIER_ORDER = ["LOW", "MODERATE", "ELEVATED", "HIGH", "CRITICAL"]


def load_test_data(data_dir: str, subset: str):
    import thrember
    X, y = thrember.read_vectorized_features(data_dir, subset=subset)
    return np.asarray(X), np.asarray(y)


def compute_thresholds(y_true: np.ndarray, proba: np.ndarray) -> dict:
    from sklearn.metrics import precision_recall_curve, f1_score

    precision, recall, thresholds = precision_recall_curve(y_true, proba)
    # precision_recall_curve returns precision/recall of length n+1, with
    # thresholds of length n (last precision/recall point has no threshold
    # -- it's the "classify everything as positive" endpoint). Align by
    # dropping that last point.
    precision, recall = precision[:-1], recall[:-1]

    def first_threshold_where(condition: np.ndarray, default: float) -> float:
        idx = np.where(condition)[0]
        return float(thresholds[idx[0]]) if len(idx) else default

    thr_recall99 = first_threshold_where(recall <= 0.99, default=0.01)
    thr_precision95 = first_threshold_where(precision >= 0.95, default=0.9)
    thr_precision99 = first_threshold_where(precision >= 0.99, default=0.99)

    # F1-optimal threshold: scan actual candidate thresholds, not an
    # assumed 0.5 -- the point is to justify this from evidence.
    f1_scores = [f1_score(y_true, (proba >= t).astype(int)) for t in thresholds]
    thr_f1_optimal = float(thresholds[int(np.argmax(f1_scores))])

    # Precision is not guaranteed to be perfectly monotonic in threshold on
    # finite/noisy data, so the four thresholds found independently above
    # can come out slightly out of order. Since tier severity MUST be
    # nested (CRITICAL >= HIGH >= ELEVATED >= MODERATE), enforce a
    # non-decreasing sequence by taking a running maximum -- this keeps
    # the most stringent (highest) value found for each tier boundary
    # rather than silently trusting an out-of-order raw result.
    ordered = [thr_recall99, thr_f1_optimal, thr_precision95, thr_precision99]
    for i in range(1, len(ordered)):
        ordered[i] = max(ordered[i], ordered[i - 1])
    thr_recall99, thr_f1_optimal, thr_precision95, thr_precision99 = ordered

    return {
        "thr_recall99": round(thr_recall99, 4),
        "thr_f1_optimal": round(thr_f1_optimal, 4),
        "thr_precision95": round(thr_precision95, 4),
        "thr_precision99": round(thr_precision99, 4),
    }


def base_tier(proba: float, thresholds: dict) -> str:
    if proba >= thresholds["thr_precision99"]:
        return "CRITICAL"
    if proba >= thresholds["thr_precision95"]:
        return "HIGH"
    if proba >= thresholds["thr_f1_optimal"]:
        return "ELEVATED"
    if proba >= thresholds["thr_recall99"]:
        return "MODERATE"
    return "LOW"


def escalate(tier: str) -> str:
    idx = TIER_ORDER.index(tier)
    return TIER_ORDER[min(idx + 1, len(TIER_ORDER) - 1)]


def classify_batch(proba: np.ndarray, anomaly_score: np.ndarray, thresholds: dict,
                    anomaly_cutoff: float) -> list:
    tiers = []
    for p, a in zip(proba, anomaly_score):
        tier = base_tier(p, thresholds)
        if a >= anomaly_cutoff and tier != "CRITICAL":
            tier = escalate(tier)
        tiers.append(tier)
    return tiers


def write_report(out_path: Path, thresholds: dict, anomaly_cutoff: float,
                  tiers: np.ndarray, y_true: np.ndarray) -> None:
    lines = ["# M7 Risk Engine Report\n"]
    lines.append("## Thresholds (derived from the test set's precision-recall curve)\n")
    for key, val in thresholds.items():
        lines.append(f"- {key}: {val}")
    lines.append(f"- anomaly_cutoff (top {int(ANOMALY_TOP_PCT*100)}% most anomalous): {round(anomaly_cutoff, 4)}\n")

    lines.append(
        "\nA sample's base tier comes from where its detection probability "
        "falls among the thresholds above. It is escalated by one tier if "
        "its anomaly score is also in the top "
        f"{int(ANOMALY_TOP_PCT*100)}% most anomalous, and it isn't already "
        "CRITICAL.\n"
    )

    lines.append("## Tier distribution vs. actual label\n")
    lines.append("| Tier | Total | Actually malicious | Actually benign | % malicious |")
    lines.append("|---|---|---|---|---|")
    for tier in TIER_ORDER:
        mask = tiers == tier
        total = int(mask.sum())
        mal = int((y_true[mask] == 1).sum()) if total else 0
        ben = total - mal
        pct = round(100 * mal / total, 2) if total else 0.0
        lines.append(f"| {tier} | {total} | {mal} | {ben} | {pct}% |")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="M7: risk engine combining detection + anomaly signals.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--test-subset", default="test_dedup")
    parser.add_argument("--models-dir", default="ml-training/models")
    parser.add_argument("--reports-dir", default="ml-training/reports")
    args = parser.parse_args()

    try:
        import joblib
    except ImportError as e:
        print(f"ERROR: missing dependency ({e}).", file=sys.stderr)
        return 1

    models_dir = Path(args.models_dir)
    detector_path = models_dir / "malware_detector.joblib"
    anomaly_path = models_dir / "anomaly_detector.joblib"
    for p in [detector_path, anomaly_path]:
        if not p.exists():
            print(f"ERROR: '{p}' not found. Run train_detector.py (M3) and "
                  f"train_anomaly.py (M4) first.", file=sys.stderr)
            return 1

    print("Loading models ...")
    detector = joblib.load(detector_path)
    anomaly_model = joblib.load(anomaly_path)

    print(f"Loading test subset '{args.test_subset}' ...")
    X_test, y_test = load_test_data(args.data_dir, args.test_subset)
    print(f"  X_test.shape={X_test.shape}")

    print("Scoring detection probability ...")
    proba = detector.predict_proba(X_test)[:, 1]

    print("Scoring anomaly (relative to benign baseline) ...")
    anomaly_score = -anomaly_model.score_samples(X_test)

    print("\nComputing thresholds from the precision-recall curve ...")
    thresholds = compute_thresholds(y_test, proba)
    for key, val in thresholds.items():
        print(f"  {key}: {val}")

    anomaly_cutoff = float(np.quantile(anomaly_score, 1 - ANOMALY_TOP_PCT))
    print(f"  anomaly_cutoff (top {int(ANOMALY_TOP_PCT*100)}%): {round(anomaly_cutoff, 4)}")

    print("\nClassifying risk tiers for the full test set ...")
    tiers = np.array(classify_batch(proba, anomaly_score, thresholds, anomaly_cutoff))

    print("\n--- Tier distribution ---")
    for tier in TIER_ORDER:
        mask = tiers == tier
        total = int(mask.sum())
        mal = int((y_test[mask] == 1).sum()) if total else 0
        pct = round(100 * mal / total, 2) if total else 0.0
        print(f"{tier:10s} total={total:6d}  actually malicious={mal:6d} ({pct}%)")

    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "m7_risk_engine_report.md"
    write_report(report_path, thresholds, anomaly_cutoff, tiers, y_test)
    print(f"\nReport written to: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())