"""
analyze_file.py — Milestone 8

Safe static analysis of a single uploaded file. Ties together every prior
milestone into the actual user-facing pipeline described in the blueprint:

    Upload -> File validation -> Safe PE parsing -> Feature extraction
    -> Malware model -> Anomaly model -> Family model (if malicious)
    -> SHAP -> Risk engine -> Threat report

CRITICAL SAFETY PROPERTY: this script NEVER executes the analyzed file.
Feature extraction is pure static parsing (thrember's PEFeatureExtractor,
built on `pefile`, reading bytes only), wrapped in a try/except for
malformed files. There is no subprocess call, no os.system, no dynamic
execution of any kind, anywhere in this file. Treat the input file as
fully untrusted: only ever read its bytes, never run it.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\analyze_file.py --file path\\to\\sample.exe

Deliberately conservative validation limits (adjust with flags if needed):
  --max-size-mb   default 100 MB — reject anything larger before reading
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np


TIER_ORDER = ["LOW", "MODERATE", "ELEVATED", "HIGH", "CRITICAL"]


def validate_file(path: Path, max_size_mb: float) -> bytes:
    """Reads the file's bytes after basic safety checks. Never touches
    anything beyond reading -- no execution, no shell calls."""
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"'{path}' does not exist or is not a file.")

    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb > max_size_mb:
        raise ValueError(
            f"File is {size_mb:.1f} MB, exceeds the {max_size_mb} MB limit. "
            f"Refusing to process (adjust --max-size-mb if this is expected)."
        )

    with path.open("rb") as f:
        return f.read()


def extract_features(bytez: bytes):
    """Pure static feature extraction. Internally: pefile.PE(data=bytez)
    parses the PE structure in memory only -- it does not execute
    anything. Malformed/non-PE files are handled gracefully by thrember
    (raw_features catches PEFormatError), not treated as a crash."""
    import thrember
    extractor = thrember.PEFeatureExtractor()
    vector = extractor.feature_vector(bytez)
    return vector.reshape(1, -1), extractor.dim


def load_models(models_dir: Path):
    import joblib

    detector_path = models_dir / "malware_detector.joblib"
    anomaly_path = models_dir / "anomaly_detector.joblib"
    family_path = models_dir / "family_classifier.joblib"
    family_le_path = models_dir / "family_label_encoder.joblib"
    thresholds_path = models_dir / "risk_thresholds.json"

    for required in [detector_path, anomaly_path, thresholds_path]:
        if not required.exists():
            print(f"ERROR: '{required}' not found. Run the M3/M4/M7 training "
                  f"scripts first.", file=sys.stderr)
            sys.exit(1)

    detector = joblib.load(detector_path)
    anomaly_model = joblib.load(anomaly_path)
    thresholds = json.loads(thresholds_path.read_text(encoding="utf-8"))

    family_model, family_le = None, None
    if family_path.exists() and family_le_path.exists():
        family_model = joblib.load(family_path)
        family_le = joblib.load(family_le_path)

    return detector, anomaly_model, family_model, family_le, thresholds


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


def build_feature_names() -> list:
    import thrember
    ext = thrember.PEFeatureExtractor()
    names = []
    for block in ext.features:
        block_name = type(block).__name__
        for i in range(block.dim):
            names.append(f"{block_name}[{i}]")
    return names


def top_shap_contributions(detector, X: np.ndarray, feature_names: list, top_k: int = 5):
    import shap
    explainer = shap.TreeExplainer(detector)
    shap_values = explainer.shap_values(X)
    row_shap = shap_values[0]
    order = np.argsort(-np.abs(row_shap))[:top_k]
    return [
        {
            "feature": feature_names[j],
            "value": round(float(X[0, j]), 4),
            "shap_value": round(float(row_shap[j]), 4),
            "direction": "toward malicious" if row_shap[j] > 0 else "toward benign",
        }
        for j in order
    ]


def analyze(file_path: str, models_dir: str, max_size_mb: float, top_k: int) -> dict:
    path = Path(file_path)
    bytez = validate_file(path, max_size_mb)
    sha256 = hashlib.sha256(bytez).hexdigest()

    X, expected_dim = extract_features(bytez)

    detector, anomaly_model, family_model, family_le, thresholds = load_models(Path(models_dir))

    if X.shape[1] != detector.n_features_in_:
        raise ValueError(
            f"Extracted {X.shape[1]} features but the model expects "
            f"{detector.n_features_in_}. This file's feature schema doesn't "
            f"match the training data -- refusing to produce a potentially "
            f"meaningless prediction."
        )

    proba = float(detector.predict_proba(X)[0, 1])
    anomaly_score = float(-anomaly_model.score_samples(X)[0])

    tier = base_tier(proba, thresholds)
    if anomaly_score >= thresholds["anomaly_cutoff"] and tier != "CRITICAL":
        tier = escalate(tier)

    family_pred = None
    if family_model is not None and proba >= thresholds["thr_f1_optimal"]:
        family_idx = family_model.predict(X)[0]
        family_pred = str(family_le.inverse_transform([family_idx])[0])

    feature_names = build_feature_names()
    contributions = top_shap_contributions(detector, X, feature_names, top_k=top_k)

    return {
        "file_name": path.name,
        "sha256": sha256,
        "file_size_bytes": len(bytez),
        "classification": "MALICIOUS" if proba >= thresholds["thr_f1_optimal"] else "BENIGN",
        "malicious_probability": round(proba, 4),
        "anomaly_score": round(anomaly_score, 4),
        "threat_level": tier,
        "predicted_family": family_pred,
        "top_contributing_features": contributions,
    }


def print_report(result: dict) -> None:
    print("\n" + "=" * 60)
    print("THREAT ASSESSMENT")
    print("=" * 60)
    print(f"File:               {result['file_name']}")
    print(f"SHA-256:            {result['sha256']}")
    print(f"Size:               {result['file_size_bytes']} bytes")
    print("-" * 60)
    print(f"Classification:     {result['classification']}")
    print(f"Confidence:         {result['malicious_probability']*100:.2f}%")
    print(f"Threat Level:       {result['threat_level']}")
    print(f"Anomaly Score:      {result['anomaly_score']}")
    if result["predicted_family"]:
        print(f"Likely Family:      {result['predicted_family']}")
    print("-" * 60)
    print("Top Contributing Features:")
    for c in result["top_contributing_features"]:
        print(f"  {c['feature']:28s} = {c['value']:<14} "
              f"SHAP {c['shap_value']:+.4f} ({c['direction']})")
    print("=" * 60)
    print(
        "This is a probabilistic assessment from static analysis only. It "
        "is not a substitute for professional malware analysis and should "
        "not be the sole basis for a security decision."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="M8: safe static analysis of a single file.")
    parser.add_argument("--file", required=True, help="Path to the file to analyze.")
    parser.add_argument("--models-dir", default="ml-training/models")
    parser.add_argument("--max-size-mb", type=float, default=100.0)
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args()

    try:
        result = analyze(args.file, args.models_dir, args.max_size_mb, args.top_k)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print_report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())