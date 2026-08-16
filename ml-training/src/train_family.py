"""
train_family.py — Milestone 5

Recovers actual malware family NAMES (not thrember's internal opaque
integer encoding) by reading raw metadata directly via
thrember.read_metadata(), then trains a multi-class classifier
(Random Forest) to predict family among the most frequent families in
the training data, with everything else consolidated into an explicit
"other" class — per the blueprint's own guidance: never force sparse
classes to stand alone with too few examples to learn from.

Why not just use the label_type="family" integers thrember produces
during create_vectorized_features()? That name -> integer mapping is
built internally and never saved anywhere thrember exposes, so there's
no way to translate "Family #16" back into a real name like "Trojan"
from that path alone. Reading metadata directly gives us the actual
family strings ClarAVy assigned, at the cost of an extra read pass over
the raw data.

Known thrember quirk (installed version): read_metadata()'s returned
challenge_metadf is actually built from test_records instead of
challenge_records — a bug in thrember itself. Irrelevant here since this
script only uses train and test metadata, not challenge.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\train_family.py --data-dir ml-training\\data --top-n 20
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd


def load_metadata(data_dir: str):
    import thrember
    train_metadf, test_metadf, _ = thrember.read_metadata(data_dir)
    return train_metadf.to_pandas(), test_metadf.to_pandas()


def load_features(data_dir: str, subset: str) -> np.ndarray:
    import thrember
    X, _ = thrember.read_vectorized_features(data_dir, subset=subset)
    return np.asarray(X)


def is_malicious_column(meta_df: pd.DataFrame) -> pd.Series:
    """Handles label being stored as int (0/1), bool, or string across
    possible thrember/EMBER2024 metadata formats."""
    return meta_df["label"].astype(str).isin(["1", "True", "malicious"])


def build_family_labels(meta_df: pd.DataFrame, top_families: list) -> np.ndarray:
    """Malicious rows get their family name if it's one of top_families,
    else 'other'. Benign / untagged rows get None — the caller drops these
    before training, since family classification is only meaningful for
    malicious samples."""
    fam = meta_df["family"].fillna("").astype(str)
    malicious = is_malicious_column(meta_df)
    tagged = malicious & (fam != "")

    labels = np.full(len(meta_df), None, dtype=object)
    kept = tagged & fam.isin(top_families)
    other = tagged & ~fam.isin(top_families)
    labels[kept.values] = fam[kept].values
    labels[other.values] = "other"
    return labels


def main() -> int:
    parser = argparse.ArgumentParser(description="Train the M5 malware family classifier.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--top-n", type=int, default=20,
                         help="Number of most frequent families kept as their own class; rest become 'other'.")
    parser.add_argument("--models-dir", default="ml-training/models")
    parser.add_argument("--reports-dir", default="ml-training/reports")
    args = parser.parse_args()

    try:
        import thrember  # noqa: F401
    except ImportError:
        print("ERROR: thrember is not installed. See README.md 'Setup' step.", file=sys.stderr)
        return 1

    print("Reading metadata (family names) ...")
    train_meta, test_meta = load_metadata(args.data_dir)
    print(f"  train_meta rows: {len(train_meta)}, test_meta rows: {len(test_meta)}")

    print("Loading feature vectors ...")
    X_train_full = load_features(args.data_dir, "train")
    X_test_full = load_features(args.data_dir, "test")
    print(f"  X_train_full.shape={X_train_full.shape}, X_test_full.shape={X_test_full.shape}")

    if len(train_meta) != X_train_full.shape[0] or len(test_meta) != X_test_full.shape[0]:
        print(
            "ERROR: metadata row count does not match feature row count — "
            "row alignment can't be trusted, aborting rather than risk "
            "mismatched labels.",
            file=sys.stderr,
        )
        return 1

    fam_counts = train_meta.loc[train_meta["family"].fillna("") != "", "family"].value_counts()
    top_families = fam_counts.head(args.top_n).index.tolist()
    print(f"\nTop {args.top_n} families by train frequency:")
    for fam, cnt in fam_counts.head(args.top_n).items():
        print(f"  {fam}: {cnt}")

    y_train_fam = build_family_labels(train_meta, top_families)
    y_test_fam = build_family_labels(test_meta, top_families)

    train_mask = y_train_fam != None  # noqa: E711 — vectorized comparison, not identity check
    test_mask = y_test_fam != None  # noqa: E711

    X_train = X_train_full[train_mask]
    y_train = y_train_fam[train_mask].astype(str)
    X_test = X_test_full[test_mask]
    y_test = y_test_fam[test_mask].astype(str)

    print(f"\nUsable malicious+family-tagged rows: train={X_train.shape[0]}, test={X_test.shape[0]}")
    print(f"Classes ({len(set(y_train))}): {sorted(set(y_train))}")

    from sklearn.preprocessing import LabelEncoder
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, f1_score

    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)

    # Defensive: drop any test rows whose class never appeared in train
    # (shouldn't happen since top_families is derived from train and
    # 'other' appears in both, but never trust an unseen label silently).
    known_mask = np.isin(y_test, le.classes_)
    X_test, y_test = X_test[known_mask], y_test[known_mask]
    y_test_enc = le.transform(y_test)

    print("\nTraining Random Forest family classifier ...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        min_samples_leaf=5,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train_enc)

    y_pred_enc = clf.predict(X_test)
    macro_f1 = f1_score(y_test_enc, y_pred_enc, average="macro")
    report_text = classification_report(
        y_test_enc, y_pred_enc, target_names=le.classes_, zero_division=0
    )

    print(f"\nMacro F1: {macro_f1:.4f}")
    print(report_text)

    models_dir = Path(args.models_dir)
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    import joblib
    joblib.dump(clf, models_dir / "family_classifier.joblib")
    joblib.dump(le, models_dir / "family_label_encoder.joblib")
    print(f"\nSaved model to: {models_dir / 'family_classifier.joblib'}")
    print(f"Saved label encoder to: {models_dir / 'family_label_encoder.joblib'}")

    report_path = reports_dir / "m5_family_report.md"
    lines = ["# M5 Family Classifier Report\n"]
    lines.append(
        f"Top-{args.top_n} families (by train frequency) kept as their own "
        f"class; everything else bucketed as 'other'. Family names are the "
        f"actual ClarAVy-assigned tags read from raw metadata, not invented.\n"
    )
    lines.append(f"Train rows used: {X_train.shape[0]}, test rows used: {X_test.shape[0]}\n")
    lines.append(f"Macro F1: {macro_f1:.4f}\n")
    lines.append("```\n" + report_text + "\n```\n")
    Path(report_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"Report written to: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())