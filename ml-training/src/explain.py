"""
explain.py — Milestone 6

Explains individual predictions from the M3 malware detector (XGBoost)
using SHAP, with analyst-readable feature names instead of raw indices.

Feature naming: PEFeatureExtractor's 2,568 dimensions are the concatenation
of several named sub-extractors (GeneralFileInfo, ByteHistogram, SectionInfo,
ImportsInfo, etc.), each contributing a fixed block of dimensions — see the
printed block list below, read directly from thrember at runtime rather than
hardcoded, so this stays correct even if thrember's internals change. There
is no single further human name for every individual float inside a block
(e.g. "ByteHistogram[142]" is accurate — it IS one specific byte-value bin —
but SectionInfo's internal dimension meanings aren't individually named by
thrember). This is a real, non-invented naming scheme built from the actual
feature extractor structure — not decorative labels.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\explain.py --data-dir ml-training\\data ^
        --test-subset test_dedup --n-samples 10 --top-k 10
"""

import argparse
import sys
from pathlib import Path

import numpy as np


def build_feature_names() -> list:
    """Builds the full 2,568-length feature name list dynamically from
    thrember's own PEFeatureExtractor structure, e.g.
    ['GeneralFileInfo[0]', ..., 'GeneralFileInfo[6]', 'ByteHistogram[0]', ...]."""
    import thrember
    ext = thrember.PEFeatureExtractor()
    names = []
    for block in ext.features:
        block_name = type(block).__name__
        for i in range(block.dim):
            names.append(f"{block_name}[{i}]")
    assert len(names) == ext.dim, f"name count {len(names)} != extractor dim {ext.dim}"
    return names


def load_test_data(data_dir: str, subset: str):
    import thrember
    X, y = thrember.read_vectorized_features(data_dir, subset=subset)
    return np.asarray(X), np.asarray(y)


def pick_example_indices(y_pred: np.ndarray, y_true: np.ndarray, n_samples: int) -> dict:
    """Picks a representative mix of examples to explain: correct malicious
    detections, correct benign, false positives, and false negatives —
    rather than just the first N rows, which would likely all be the
    same (easy, obviously-correct) case."""
    tp = np.where((y_pred == 1) & (y_true == 1))[0]
    tn = np.where((y_pred == 0) & (y_true == 0))[0]
    fp = np.where((y_pred == 1) & (y_true == 0))[0]
    fn = np.where((y_pred == 0) & (y_true == 1))[0]

    per_bucket = max(1, n_samples // 4)
    picks = {}
    for name, idxs in [("true_positive", tp), ("true_negative", tn),
                        ("false_positive", fp), ("false_negative", fn)]:
        picks[name] = idxs[:per_bucket].tolist()
    return picks


def explain_indices(model, X: np.ndarray, feature_names: list, indices: list, top_k: int):
    import shap
    explainer = shap.TreeExplainer(model)
    X_subset = X[indices]
    shap_values = explainer.shap_values(X_subset)

    explanations = []
    for row_i, orig_idx in enumerate(indices):
        row_shap = shap_values[row_i]
        row_x = X_subset[row_i]
        order = np.argsort(-np.abs(row_shap))[:top_k]
        contributions = [
            {
                "feature": feature_names[j],
                "value": round(float(row_x[j]), 4),
                "shap_value": round(float(row_shap[j]), 4),
                "direction": "toward malicious" if row_shap[j] > 0 else "toward benign",
            }
            for j in order
        ]
        explanations.append({"row_index": int(orig_idx), "top_contributions": contributions})
    return explanations


def write_report(out_path: Path, bucket_explanations: dict) -> None:
    lines = ["# M6 Explainability Report (SHAP)\n"]
    lines.append(
        "Each example below shows the top contributing features for one "
        "prediction, in the model's own terms — feature name, its actual "
        "value for this sample, its SHAP value (impact), and which "
        "direction it pushed the prediction.\n"
    )

    label_text = {
        "true_positive": "Correctly detected malicious",
        "true_negative": "Correctly detected benign",
        "false_positive": "False positive (benign flagged as malicious)",
        "false_negative": "False negative (malicious missed)",
    }

    for bucket, examples in bucket_explanations.items():
        lines.append(f"## {label_text.get(bucket, bucket)}\n")
        if not examples:
            lines.append("_No examples of this type in the sampled set._\n")
            continue
        for ex in examples:
            lines.append(f"### Test row {ex['row_index']}\n")
            for c in ex["top_contributions"]:
                lines.append(
                    f"- **{c['feature']}** = {c['value']}  "
                    f"(SHAP {c['shap_value']:+.4f}, {c['direction']})"
                )
            lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="M6: SHAP explainability for the malware detector.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--test-subset", default="test_dedup")
    parser.add_argument("--models-dir", default="ml-training/models")
    parser.add_argument("--reports-dir", default="ml-training/reports")
    parser.add_argument("--n-samples", type=int, default=12,
                         help="Total examples to explain, split across TP/TN/FP/FN buckets.")
    parser.add_argument("--top-k", type=int, default=10,
                         help="Top-K contributing features to report per example.")
    args = parser.parse_args()

    try:
        import thrember  # noqa: F401
        import joblib
    except ImportError as e:
        print(f"ERROR: missing dependency ({e}). Check requirements.txt is installed.", file=sys.stderr)
        return 1

    model_path = Path(args.models_dir) / "malware_detector.joblib"
    if not model_path.exists():
        print(f"ERROR: '{model_path}' not found. Run train_detector.py (M3) first.", file=sys.stderr)
        return 1

    print("Loading malware detection model ...")
    model = joblib.load(model_path)

    print("Building feature name list from thrember's extractor structure ...")
    feature_names = build_feature_names()
    print(f"  {len(feature_names)} feature names built (matches model's {model.n_features_in_} input dims: "
          f"{'OK' if len(feature_names) == model.n_features_in_ else 'MISMATCH'})")

    print(f"Loading test subset '{args.test_subset}' ...")
    X_test, y_test = load_test_data(args.data_dir, args.test_subset)
    print(f"  X_test.shape={X_test.shape}")

    print("Generating predictions to pick representative examples ...")
    y_pred = model.predict(X_test)

    picks = pick_example_indices(y_pred, y_test, args.n_samples)
    print("Examples picked per bucket:", {k: len(v) for k, v in picks.items()})

    bucket_explanations = {}
    for bucket, idxs in picks.items():
        if not idxs:
            bucket_explanations[bucket] = []
            continue
        print(f"Computing SHAP values for bucket '{bucket}' ({len(idxs)} example(s)) ...")
        bucket_explanations[bucket] = explain_indices(model, X_test, feature_names, idxs, args.top_k)

    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "m6_explainability_report.md"
    write_report(report_path, bucket_explanations)
    print(f"\nReport written to: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())