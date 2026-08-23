"""
adversarial_robustness_test.py — Bonus: Adversarial Robustness Testing

Tests how easily the M3 malware detector's verdict can be flipped by small
perturbations to the FEATURE VECTOR. This is deliberately scoped as a
defensive robustness MEASUREMENT, not an evasion guide: it never touches
real executable bytes, never suggests how a feature-space perturbation
would be realized in an actual file, and reports aggregate statistics
rather than a per-sample "recipe." Translating any of these findings into
an actual modified executable requires domain-specific work this script
does not provide and is out of scope for a defensive research project.

Two experiments:
  1. Single-feature test: what fraction of correctly-detected malicious
     samples flip to BENIGN if only HeaderFileInfo[43] is changed to the
     value typically seen in benign samples? Directly tests M6's finding
     that this one feature dominates most predictions.
  2. Epsilon-ball robustness curve: for several perturbation magnitudes
     (scaled to each feature's training-set standard deviation), what
     fraction of samples flip under random Gaussian noise across ALL
     features? A standard robustness metric in adversarial ML research.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\adversarial_robustness_test.py --data-dir ml-training\\data
"""

import argparse
import sys
from pathlib import Path

import numpy as np


def load_data(data_dir: str, subset: str):
    import thrember
    X, y = thrember.read_vectorized_features(data_dir, subset=subset)
    return np.asarray(X), np.asarray(y)


def build_feature_names() -> list:
    import thrember
    ext = thrember.PEFeatureExtractor()
    names = []
    for block in ext.features:
        block_name = type(block).__name__
        for i in range(block.dim):
            names.append(f"{block_name}[{i}]")
    return names


def single_feature_flip_test(detector, X_mal: np.ndarray, feature_idx: int,
                              benign_value: float, threshold: float) -> dict:
    """For each malicious-classified sample, set one feature to a fixed
    value and check whether the prediction flips to benign."""
    X_perturbed = X_mal.copy()
    X_perturbed[:, feature_idx] = benign_value

    proba_before = detector.predict_proba(X_mal)[:, 1]
    proba_after = detector.predict_proba(X_perturbed)[:, 1]

    was_malicious = proba_before >= threshold
    now_benign = proba_after < threshold
    flipped = was_malicious & now_benign
    n_tested = int(was_malicious.sum())

    return {
        "samples_tested": n_tested,
        "flipped_to_benign": int(flipped.sum()),
        "flip_rate": round(float(flipped.sum() / n_tested), 4) if n_tested else 0.0,
        "mean_confidence_before": round(float(proba_before[was_malicious].mean()), 4) if n_tested else None,
        "mean_confidence_after": round(float(proba_after[was_malicious].mean()), 4) if n_tested else None,
    }


def epsilon_ball_robustness(detector, X_mal: np.ndarray, feature_stds: np.ndarray,
                             epsilons: list, threshold: float, n_trials: int = 5,
                             seed: int = 42) -> list:
    """For each epsilon, perturb ALL features with Gaussian noise scaled by
    epsilon * feature_std, repeated n_trials times, and report the fraction
    of samples that flip to benign at least once."""
    rng = np.random.default_rng(seed)
    proba_before = detector.predict_proba(X_mal)[:, 1]
    was_malicious = proba_before >= threshold
    X_subset = X_mal[was_malicious]
    n = X_subset.shape[0]

    results = []
    for eps in epsilons:
        flipped_any = np.zeros(n, dtype=bool)
        for _ in range(n_trials):
            noise = rng.normal(0, 1, size=X_subset.shape) * (eps * feature_stds)
            proba_after = detector.predict_proba(X_subset + noise)[:, 1]
            flipped_any |= (proba_after < threshold)
        results.append({
            "epsilon": eps,
            "samples_tested": n,
            "flip_rate": round(float(flipped_any.sum() / n), 4) if n else 0.0,
        })
    return results


def write_report(out_path: Path, single_feature_result: dict, robustness_curve: list,
                  feature_name: str) -> None:
    lines = ["# Adversarial Robustness Test Report\n"]
    lines.append(
        "This is a defensive robustness MEASUREMENT, not an evasion guide. "
        "Results describe the model's feature-space sensitivity only -- "
        "they do not describe how to modify a real executable.\n"
    )

    lines.append(f"## Single-feature test: `{feature_name}`\n")
    lines.append(
        f"Directly tests M6's SHAP finding that this one feature dominates "
        f"most predictions, by setting it alone to the typical benign value "
        f"and checking how often that flips the verdict.\n"
    )
    for key, val in single_feature_result.items():
        lines.append(f"- {key}: {val}")
    lines.append("")

    lines.append("## Epsilon-ball robustness curve (all features, random noise)\n")
    lines.append("| Epsilon | Samples tested | Flip rate |")
    lines.append("|---|---|---|")
    for r in robustness_curve:
        lines.append(f"| {r['epsilon']} | {r['samples_tested']} | {r['flip_rate']} |")
    lines.append(
        "\nHigher epsilon = larger random perturbation relative to each "
        "feature's natural variation in the training data. A flip rate "
        "that stays low even at moderate epsilon indicates a robust "
        "decision boundary; a flip rate that jumps quickly indicates "
        "fragility.\n"
    )

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Adversarial robustness testing for the M3 detector.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--train-subset", default="train_dedup")
    parser.add_argument("--test-subset", default="test_dedup")
    parser.add_argument("--models-dir", default="ml-training/models")
    parser.add_argument("--reports-dir", default="ml-training/reports")
    parser.add_argument("--target-feature", default="HeaderFileInfo[43]",
                         help="The feature to test in isolation (default matches M6's finding).")
    args = parser.parse_args()

    try:
        import joblib
        import json
    except ImportError as e:
        print(f"ERROR: missing dependency ({e}).", file=sys.stderr)
        return 1

    models_dir = Path(args.models_dir)
    detector_path = models_dir / "malware_detector.joblib"
    thresholds_path = models_dir / "risk_thresholds.json"
    if not detector_path.exists() or not thresholds_path.exists():
        print(f"ERROR: run M3 (train_detector.py) and M7 (risk_engine.py) first.", file=sys.stderr)
        return 1

    print("Loading model and thresholds ...")
    detector = joblib.load(detector_path)
    thresholds = json.loads(thresholds_path.read_text(encoding="utf-8"))
    threshold = thresholds["thr_f1_optimal"]

    print("Building feature names ...")
    feature_names = build_feature_names()
    if args.target_feature not in feature_names:
        print(f"ERROR: feature '{args.target_feature}' not found.", file=sys.stderr)
        return 1
    target_idx = feature_names.index(args.target_feature)

    print(f"Loading train subset '{args.train_subset}' (for feature stats) ...")
    X_train, y_train = load_data(args.data_dir, args.train_subset)
    feature_stds = X_train.std(axis=0)
    feature_stds[feature_stds == 0] = 1e-6  # avoid zero-noise on constant features

    # Typical benign value for the target feature (median of benign rows).
    benign_value = float(np.median(X_train[y_train == 0, target_idx]))
    print(f"Typical benign value for '{args.target_feature}': {benign_value}")

    print(f"Loading test subset '{args.test_subset}' ...")
    X_test, y_test = load_data(args.data_dir, args.test_subset)
    X_mal = X_test[y_test == 1]
    print(f"  {X_mal.shape[0]} actually-malicious test samples available")

    print(f"\n--- Experiment 1: single-feature test on '{args.target_feature}' ---")
    single_result = single_feature_flip_test(detector, X_mal, target_idx, benign_value, threshold)
    for key, val in single_result.items():
        print(f"{key}: {val}")

    print("\n--- Experiment 2: epsilon-ball robustness curve ---")
    epsilons = [0.1, 0.25, 0.5, 1.0, 2.0]
    curve = epsilon_ball_robustness(detector, X_mal, feature_stds, epsilons, threshold)
    for r in curve:
        print(f"epsilon={r['epsilon']:.2f}  flip_rate={r['flip_rate']}")

    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "adversarial_robustness_report.md"
    write_report(report_path, single_result, curve, args.target_feature)
    print(f"\nReport written to: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())