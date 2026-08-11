"""
train_detector.py — Milestone 3

Trains and compares three candidate algorithms for the malware detection
task (Model 1 from the blueprint): Logistic Regression, Random Forest, and
XGBoost. Selects and saves the best-performing model, with justification.

Deliberately does NOT use accuracy as the deciding metric — with malware
detection, false negatives (missed malware) and false positives (flagged
benign software) have very different real-world costs, so this reports
precision, recall, F1, ROC-AUC, PR-AUC, and the confusion matrix for each
candidate, and picks the best model based on PR-AUC (more informative than
ROC-AUC when classes are imbalanced, and meaningful even here where classes
happen to be balanced).

Expects DEDUPLICATED data (see dedupe.py) as input — training or evaluating
on the raw, duplicate-laden splits would risk misleadingly inflated metrics.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\train_detector.py --data-dir ml-training\\data ^
        --train-subset train_dedup --test-subset test_dedup
"""

import argparse
import sys
import time
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
        print(
            f"ERROR: '{x_path}' or '{y_path}' not found. Run dedupe.py on this "
            f"split first if you haven't already.",
            file=sys.stderr,
        )
        sys.exit(1)

    X, y = thrember.read_vectorized_features(data_dir, subset=subset)
    return np.asarray(X), np.asarray(y)


def evaluate(name: str, y_true: np.ndarray, y_pred: np.ndarray, y_proba: np.ndarray) -> dict:
    from sklearn.metrics import (
        precision_score, recall_score, f1_score,
        roc_auc_score, average_precision_score,
        confusion_matrix,
    )

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    return {
        "model": name,
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "f1": round(f1_score(y_true, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_true, y_proba), 4),
        "pr_auc": round(average_precision_score(y_true, y_proba), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def train_logistic_regression(X_train, y_train, X_test):
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    # Logistic Regression needs scaled features (unlike tree-based models);
    # fit the scaler on train only, apply to both, to avoid leaking test
    # distribution info into preprocessing.
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    y_proba = clf.predict_proba(X_test_scaled)[:, 1]
    return clf, scaler, y_pred, y_proba


def train_random_forest(X_train, y_train, X_test):
    from sklearn.ensemble import RandomForestClassifier

    clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    return clf, y_pred, y_proba


def train_xgboost(X_train, y_train, X_test):
    from xgboost import XGBClassifier

    clf = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        n_jobs=-1,
        eval_metric="logloss",
        random_state=42,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    return clf, y_pred, y_proba


def write_report(out_path: Path, results: list, best_model_name: str) -> None:
    lines = ["# M3 Model Comparison Report\n"]
    lines.append(
        "Selection metric: **PR-AUC** (more informative than ROC-AUC for "
        "operational decisions, and reported alongside precision/recall/F1/"
        "ROC-AUC/confusion-matrix/FPR/FNR — accuracy is deliberately not "
        "used as the deciding metric).\n"
    )

    for r in results:
        lines.append(f"## {r['model']}\n")
        lines.append(f"- Precision: {r['precision']}")
        lines.append(f"- Recall: {r['recall']}")
        lines.append(f"- F1: {r['f1']}")
        lines.append(f"- ROC-AUC: {r['roc_auc']}")
        lines.append(f"- PR-AUC: {r['pr_auc']}")
        lines.append(f"- False positive rate: {r['false_positive_rate']}")
        lines.append(f"- False negative rate: {r['false_negative_rate']}")
        cm = r["confusion_matrix"]
        lines.append(
            f"- Confusion matrix: TN={cm['tn']} FP={cm['fp']} FN={cm['fn']} TP={cm['tp']}"
        )
        lines.append("")

    lines.append(f"## Selected model: **{best_model_name}**\n")
    lines.append(
        "Selected as the model with the highest PR-AUC on the deduplicated "
        "test set among the three candidates evaluated above.\n"
    )

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Train and compare LR/RF/XGBoost for malware detection (M3)."
    )
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--train-subset", default="train_dedup",
                         help="Subset name for training data (default: train_dedup).")
    parser.add_argument("--test-subset", default="test_dedup",
                         help="Subset name for evaluation data (default: test_dedup).")
    parser.add_argument("--models-dir", default="ml-training/models")
    parser.add_argument("--reports-dir", default="ml-training/reports")
    args = parser.parse_args()

    print(f"Loading train subset '{args.train_subset}' ...")
    X_train, y_train = load_subset(args.data_dir, args.train_subset)
    print(f"  X_train.shape={X_train.shape}")

    print(f"Loading test subset '{args.test_subset}' ...")
    X_test, y_test = load_subset(args.data_dir, args.test_subset)
    print(f"  X_test.shape={X_test.shape}")

    models_dir = Path(args.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    results = []
    trained = {}

    print("\nTraining Logistic Regression ...")
    t0 = time.time()
    lr_clf, lr_scaler, y_pred, y_proba = train_logistic_regression(X_train, y_train, X_test)
    print(f"  done in {time.time() - t0:.1f}s")
    results.append(evaluate("LogisticRegression", y_test, y_pred, y_proba))
    trained["LogisticRegression"] = (lr_clf, lr_scaler)

    print("\nTraining Random Forest ...")
    t0 = time.time()
    rf_clf, y_pred, y_proba = train_random_forest(X_train, y_train, X_test)
    print(f"  done in {time.time() - t0:.1f}s")
    results.append(evaluate("RandomForest", y_test, y_pred, y_proba))
    trained["RandomForest"] = (rf_clf, None)

    print("\nTraining XGBoost ...")
    t0 = time.time()
    xgb_clf, y_pred, y_proba = train_xgboost(X_train, y_train, X_test)
    print(f"  done in {time.time() - t0:.1f}s")
    results.append(evaluate("XGBoost", y_test, y_pred, y_proba))
    trained["XGBoost"] = (xgb_clf, None)

    print("\n--- Comparison (sorted by PR-AUC) ---")
    results_sorted = sorted(results, key=lambda r: r["pr_auc"], reverse=True)
    for r in results_sorted:
        print(f"{r['model']:20s} PR-AUC={r['pr_auc']}  ROC-AUC={r['roc_auc']}  "
              f"F1={r['f1']}  FPR={r['false_positive_rate']}  FNR={r['false_negative_rate']}")

    best_name = results_sorted[0]["model"]
    best_clf, best_scaler = trained[best_name]
    print(f"\nBest model by PR-AUC: {best_name}")

    import joblib
    joblib.dump(best_clf, models_dir / "malware_detector.joblib")
    if best_scaler is not None:
        joblib.dump(best_scaler, models_dir / "preprocessor.joblib")
    print(f"Saved best model to: {models_dir / 'malware_detector.joblib'}")

    report_path = reports_dir / "m3_model_comparison.md"
    write_report(report_path, results_sorted, best_name)
    print(f"Report written to: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())