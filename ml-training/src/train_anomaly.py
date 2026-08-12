"""
train_anomaly.py — Milestone 4

Trains an Isolation Forest anomaly detector on BENIGN-ONLY training data —
i.e. it learns what "normal" (non-malicious) software looks like, structurally.
Every test-set sample (benign or malicious) is then scored against that
learned baseline: higher score = more different from what the model
considers normal.

This is deliberately a different signal from train_detector.py's supervised
classifier: that model learns "malicious vs benign" directly from labels.
This one never sees a malicious label during training — it only ever learns
"benign", and flags deviation from it. That's what makes combining the two
signals later (Milestone 7 risk engine, and the M2/blueprint Section 10
research question) meaningful rather than redundant.

One-Class SVM is deliberately not trained here — it doesn't scale to
hundreds of thousands of rows x 2,568 features (effectively O(n^2)), which
the original project blueprint already flagged as the likely outcome. If
Isolation Forest's separation turns out weak, an Autoencoder is the planned
next candidate — not One-Class SVM.

Language note: results are reported as "how different from the learned
benign distribution", never as "zero-day detection" — see blueprint
Section 16.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\train_anomaly.py --data-dir ml-training\\data ^
        --train-subset train_dedup --test-subset test_dedup
"""

import argparse
import sys
from pathlib import Path

import numpy as np


def load_subset(data_dir: str, subset: str):
    try:
        import thrember
    except ImportError:
        print("ERROR: thrember is not installed. See README.md 'Setup' step.", file=sys.stderr)
        sys.exit(1)

    x_path = Path(data_dir) / f"X_{subset}.dat"
    y_path = Path(data_dir) / f"y_{subset}.dat"
    if not x_path.exists() or not y_path.exists():
        print(f"ERROR: '{x_path}' or '{y_path}' not found. Run dedupe.py first.", file=sys.stderr)
        sys.exit(1)

    X, y = thrember.read_vectorized_features(data_dir, subset=subset)
    return np.asarray(X), np.asarray(y)


def train_isolation_forest(X_train_benign: np.ndarray):
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_benign)
    return model, None


def train_autoencoder(X_train_benign: np.ndarray):
    """A lightweight autoencoder built from sklearn's MLPRegressor (input
    and target are the same data), rather than pulling in TensorFlow/PyTorch
    for a single model — no clear justification for that extra dependency
    weight here. Trained only on benign data, same as Isolation Forest: it
    learns to reconstruct 'normal', and reconstruction error becomes the
    anomaly score for any sample later."""
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_train_benign)

    # Undercomplete bottleneck (256 -> 64 -> 256): forces the network to
    # compress benign structure into 64 dimensions and reconstruct from
    # that, rather than just memorizing an identity mapping.
    model = MLPRegressor(
        hidden_layer_sizes=(256, 64, 256),
        max_iter=200,
        early_stopping=True,
        random_state=42,
    )
    model.fit(X_scaled, X_scaled)
    return model, scaler


def reconstruction_error(model, scaler, X: np.ndarray) -> np.ndarray:
    X_scaled = scaler.transform(X)
    X_pred = model.predict(X_scaled)
    return np.mean((X_pred - X_scaled) ** 2, axis=1)


def anomaly_scores(model, X: np.ndarray) -> np.ndarray:
    """IsolationForest.score_samples returns HIGHER = more normal (inlier).
    We negate it so higher = more anomalous, which is the more intuitive
    direction for reporting to an analyst."""
    return -model.score_samples(X)


def evaluate_anomaly(y_true: np.ndarray, scores: np.ndarray, top_pct: float = 0.10) -> dict:
    from sklearn.metrics import roc_auc_score, average_precision_score

    roc_auc = roc_auc_score(y_true, scores)
    pr_auc = average_precision_score(y_true, scores)

    # "If an analyst only had time to review the top N% most anomalous
    # samples, what fraction would actually be malicious?" — a directly
    # analyst-relevant metric, distinct from ROC/PR-AUC.
    n = len(scores)
    k = max(1, int(top_pct * n))
    top_idx = np.argsort(scores)[-k:]
    precision_at_top = float(y_true[top_idx].mean())

    mean_score_benign = float(scores[y_true == 0].mean())
    mean_score_malicious = float(scores[y_true == 1].mean())

    return {
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        f"precision_at_top_{int(top_pct*100)}pct": round(precision_at_top, 4),
        "mean_anomaly_score_benign": round(mean_score_benign, 4),
        "mean_anomaly_score_malicious": round(mean_score_malicious, 4),
    }


def write_report(out_path: Path, report: dict, n_train_benign: int, n_test: int) -> None:
    lines = ["# M4 Anomaly Detection Report\n"]
    lines.append(
        "Isolation Forest, trained on benign-only feature vectors "
        f"(n={n_train_benign}), scored against the full test set (n={n_test}).\n"
    )
    lines.append(
        "Language note: scores describe distance from the learned benign "
        "distribution — this is NOT zero-day detection, and is not "
        "presented as such.\n"
    )
    lines.append("## Results\n")
    for key, val in report.items():
        lines.append(f"- {key}: {val}")
    lines.append("")
    lines.append(
        "`roc_auc` / `pr_auc` treat 'malicious' as the positive class: "
        "how well anomaly score alone separates malicious from benign, "
        "despite never having seen a malicious label during training.\n"
    )
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Train and evaluate the M4 anomaly detector.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--train-subset", default="train_dedup")
    parser.add_argument("--test-subset", default="test_dedup")
    parser.add_argument("--model", choices=["isolation_forest", "autoencoder"], default="isolation_forest")
    parser.add_argument("--models-dir", default="ml-training/models")
    parser.add_argument("--reports-dir", default="ml-training/reports")
    parser.add_argument("--top-pct", type=float, default=0.10,
                         help="Fraction of most-anomalous test samples for the precision-at-top metric.")
    args = parser.parse_args()

    print(f"Loading train subset '{args.train_subset}' ...")
    X_train, y_train = load_subset(args.data_dir, args.train_subset)
    X_train_benign = X_train[y_train == 0]
    print(f"  X_train.shape={X_train.shape}  benign-only rows used for fitting: {X_train_benign.shape[0]}")

    print(f"Loading test subset '{args.test_subset}' ...")
    X_test, y_test = load_subset(args.data_dir, args.test_subset)
    print(f"  X_test.shape={X_test.shape}")

    print(f"\nTraining {args.model} on benign-only data ...")
    if args.model == "isolation_forest":
        model, scaler = train_isolation_forest(X_train_benign)
        print("Scoring test set ...")
        scores = anomaly_scores(model, X_test)
    else:
        model, scaler = train_autoencoder(X_train_benign)
        print("Scoring test set (reconstruction error) ...")
        scores = reconstruction_error(model, scaler, X_test)

    report = evaluate_anomaly(y_test, scores, top_pct=args.top_pct)
    print(f"\n--- Anomaly detection results ({args.model}) ---")
    for key, val in report.items():
        print(f"{key}: {val}")

    models_dir = Path(args.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    import joblib
    joblib.dump(model, models_dir / f"anomaly_detector_{args.model}.joblib")
    if scaler is not None:
        joblib.dump(scaler, models_dir / f"anomaly_scaler_{args.model}.joblib")
    print(f"\nSaved model to: {models_dir / f'anomaly_detector_{args.model}.joblib'}")

    report_path = reports_dir / f"m4_anomaly_report_{args.model}.md"
    write_report(report_path, report, X_train_benign.shape[0], X_test.shape[0])
    print(f"Report written to: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())