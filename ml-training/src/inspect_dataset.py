"""
inspect_dataset.py — Milestone 1, Step 2

Loads a vectorized EMBER2024 split via `thrember` and produces the M1
"Dataset Understanding" report required before any modeling starts:

  - actual sample count and feature dimensionality
  - class balance (benign vs. malicious)
  - missing/NaN/infinite value counts, summarized per-feature
  - exact-duplicate feature-vector count within the split
  - optional cross-split duplicate check (early leakage signal)
  - basic per-feature statistics (mean/std/min/max) saved as CSV

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\inspect_dataset.py --data-dir ml-training\\data --split challenge

    # after also downloading a train split, check for train/test row overlap:
    python ml-training\\src\\inspect_dataset.py --data-dir ml-training\\data --split test ^
        --cross-check-dir ml-training\\data

Notes on memory:
EMBER2024 splits are loaded fully into memory by thrember.read_vectorized_features
(they are NOT memory-mapped). Win32 train (2,568 features x ~1.56M rows, float32)
is roughly 16 GB in RAM alone. Start with the challenge set or a test split, not
a full train split, unless you know your machine can hold it.
"""

import argparse
import hashlib
import sys
from pathlib import Path

import numpy as np
import pandas as pd


def vectorize_single_subset(data_dir: str, split: str) -> None:
    """Vectorize just ONE subset (train, test, or challenge), independent of
    whether the other two subsets' raw .jsonl files exist.

    thrember.create_vectorized_features() always tries to vectorize train,
    test, AND challenge in one call, and raises if any of the three has no
    raw .jsonl files present — which makes it unusable for a partial
    download (e.g. challenge-only). This replicates just the one subset's
    worth of work, using the same internal helpers thrember's own
    create_vectorized_features() calls for each subset.
    """
    from thrember import vectorize_subset, PEFeatureExtractor
    from thrember.model import gather_feature_paths

    data_path = Path(data_dir)
    x_path = data_path / f"X_{split}.dat"
    y_path = data_path / f"y_{split}.dat"

    if x_path.exists() and y_path.exists():
        return  # already vectorized, nothing to do

    feature_paths = gather_feature_paths(data_path, split)
    if not feature_paths:
        raise FileNotFoundError(
            f"No raw .jsonl files found for split='{split}' in '{data_dir}'. "
            f"Did you download this split with download_data.py first?"
        )

    print(f"Vectorizing '{split}' set from {len(feature_paths)} raw file(s) ...")
    extractor = PEFeatureExtractor()
    nrows = sum(1 for fp in feature_paths for _ in fp.open())
    vectorize_subset(x_path, y_path, feature_paths, extractor, nrows)


def load_split(data_dir: str, split: str):
    """Vectorizes (if needed) and loads one EMBER2024 split."""
    try:
        import thrember  # noqa: F401 — import check only
    except ImportError:
        print(
            "ERROR: thrember is not installed. See README.md 'Setup' step.",
            file=sys.stderr,
        )
        sys.exit(1)

    vectorize_single_subset(data_dir, split)

    import thrember
    X, y = thrember.read_vectorized_features(data_dir, subset=split)
    return np.asarray(X), np.asarray(y)


def class_balance_report(y: np.ndarray) -> dict:
    """EMBER-style labels: 1 = malicious, 0 = benign, -1 = unlabeled
    (unlabeled rows exist in some EMBER releases and must be reported,
    not silently dropped)."""
    total = len(y)
    counts = pd.Series(y).value_counts().sort_index()
    report = {"total_samples": total}
    for label_value, count in counts.items():
        pct = 100.0 * count / total if total else 0.0
        name = {1: "malicious", 0: "benign"}.get(label_value, f"label_{label_value}")
        report[name] = {"count": int(count), "pct": round(pct, 3)}
    return report


def missing_and_invalid_report(X: np.ndarray) -> dict:
    nan_mask = np.isnan(X)
    inf_mask = np.isinf(X)
    n_rows, n_features = X.shape

    rows_with_nan = int(np.any(nan_mask, axis=1).sum())
    rows_with_inf = int(np.any(inf_mask, axis=1).sum())
    features_with_nan = int(np.any(nan_mask, axis=0).sum())
    features_with_inf = int(np.any(inf_mask, axis=0).sum())

    return {
        "total_rows": n_rows,
        "total_features": n_features,
        "rows_with_nan": rows_with_nan,
        "rows_with_inf": rows_with_inf,
        "features_with_any_nan": features_with_nan,
        "features_with_any_inf": features_with_inf,
        "total_nan_cells": int(nan_mask.sum()),
        "total_inf_cells": int(inf_mask.sum()),
    }


def row_hashes(X: np.ndarray, chunk_size: int = 50_000) -> set:
    """Hash each row's raw bytes so we can find exact-duplicate feature
    vectors without holding an O(n^2) comparison in memory. Chunked to
    keep peak memory bounded on large splits."""
    hashes = set()
    n_rows = X.shape[0]
    for start in range(0, n_rows, chunk_size):
        chunk = X[start:start + chunk_size]
        for row in chunk:
            hashes.add(hashlib.blake2b(row.tobytes(), digest_size=16).digest())
    return hashes


def duplicate_report(X: np.ndarray, y: np.ndarray) -> dict:
    n_rows = X.shape[0]

    # Hash each row ONCE, remembering which row index it came from, so we
    # can also break duplicates down by class label without re-hashing.
    hash_to_first_row: dict = {}
    is_duplicate = np.zeros(n_rows, dtype=bool)
    for i in range(n_rows):
        h = hashlib.blake2b(X[i].tobytes(), digest_size=16).digest()
        if h in hash_to_first_row:
            is_duplicate[i] = True
        else:
            hash_to_first_row[h] = i

    n_unique = len(hash_to_first_row)
    overall = {
        "total_rows": n_rows,
        "unique_rows": n_unique,
        "exact_duplicate_rows": n_rows - n_unique,
        "duplicate_pct": round(100.0 * (n_rows - n_unique) / n_rows, 4) if n_rows else 0.0,
    }

    by_class = {}
    for label_value in np.unique(y):
        mask = (y == label_value)
        class_total = int(mask.sum())
        class_dupes = int(is_duplicate[mask].sum())
        name = {1: "malicious", 0: "benign"}.get(int(label_value), f"label_{label_value}")
        by_class[name] = {
            "total": class_total,
            "duplicate_rows": class_dupes,
            "duplicate_pct": round(100.0 * class_dupes / class_total, 4) if class_total else 0.0,
        }

    overall["by_class"] = by_class
    return overall


def cross_split_overlap(X_a: np.ndarray, X_b: np.ndarray) -> dict:
    """Cheap, early leakage signal: exact feature-vector overlap between
    two splits (e.g., train vs. test). This is NOT a substitute for the
    proper near-duplicate / family-aware / temporal leakage analysis
    planned for Milestone 2 — it only catches exact-match leakage."""
    hashes_a = row_hashes(X_a)
    hashes_b = row_hashes(X_b)
    overlap = hashes_a & hashes_b
    return {
        "rows_in_a": X_a.shape[0],
        "rows_in_b": X_b.shape[0],
        "exact_overlap_count": len(overlap),
    }


def feature_stats(X: np.ndarray) -> pd.DataFrame:
    return pd.DataFrame({
        "feature_index": np.arange(X.shape[1]),
        "mean": np.nanmean(X, axis=0),
        "std": np.nanstd(X, axis=0),
        "min": np.nanmin(X, axis=0),
        "max": np.nanmax(X, axis=0),
    })


def write_report(
    out_path: Path,
    split: str,
    class_report: dict,
    missing_report: dict,
    dup_report: dict,
    cross_report,
    stats_csv_path: Path,
) -> None:
    lines = []
    lines.append(f"# M1 Dataset Report — split: `{split}`\n")

    lines.append("## Class balance\n")
    lines.append(f"- Total samples: **{class_report['total_samples']}**")
    for key, val in class_report.items():
        if key == "total_samples":
            continue
        lines.append(f"- {key}: {val['count']} ({val['pct']}%)")
    lines.append("")

    lines.append("## Shape / missing & invalid values\n")
    for key, val in missing_report.items():
        lines.append(f"- {key}: {val}")
    lines.append("")

    lines.append("## Exact-duplicate feature vectors (within split)\n")
    for key, val in dup_report.items():
        if key == "by_class":
            continue
        lines.append(f"- {key}: {val}")
    lines.append("")
    lines.append("### Duplicate breakdown by class\n")
    for class_name, class_stats in dup_report.get("by_class", {}).items():
        lines.append(
            f"- {class_name}: {class_stats['duplicate_rows']} / {class_stats['total']} "
            f"duplicated ({class_stats['duplicate_pct']}%)"
        )
    lines.append("")

    if cross_report is not None:
        lines.append("## Cross-split exact overlap (early leakage signal)\n")
        for key, val in cross_report.items():
            lines.append(f"- {key}: {val}")
        lines.append(
            "\n_This only catches exact-match leakage. Near-duplicate, "
            "family-aware, and temporal leakage checks are planned for "
            "Milestone 2._\n"
        )

    lines.append(f"## Per-feature statistics\n")
    lines.append(f"Full per-feature mean/std/min/max saved to: `{stats_csv_path}`\n")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="M1 dataset understanding report.")
    parser.add_argument("--data-dir", required=True, help="Directory passed to thrember (where data was downloaded).")
    parser.add_argument("--split", required=True, choices=["train", "test", "challenge"])
    parser.add_argument(
        "--cross-check-dir",
        default=None,
        help="If set, also loads this directory's OPPOSITE split (train<->test) "
             "and reports exact feature-vector overlap with --split.",
    )
    parser.add_argument(
        "--reports-dir",
        default="ml-training/reports",
        help="Where to write the report (default: ml-training/reports).",
    )
    args = parser.parse_args()

    print(f"Loading split='{args.split}' from '{args.data_dir}' ...")
    X, y = load_split(args.data_dir, args.split)
    print(f"Loaded X.shape={X.shape}, y.shape={y.shape}")

    class_report = class_balance_report(y)
    missing_report = missing_and_invalid_report(X)
    dup_report = duplicate_report(X, y)

    cross_report = None
    if args.cross_check_dir:
        other_split = "test" if args.split == "train" else "train"
        print(f"Cross-checking against split='{other_split}' for exact overlap ...")
        X_other, _ = load_split(args.cross_check_dir, other_split)
        cross_report = cross_split_overlap(X, X_other)

    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    stats_df = feature_stats(X)
    stats_csv_path = reports_dir / f"m1_feature_stats_{args.split}.csv"
    stats_df.to_csv(stats_csv_path, index=False)

    report_path = reports_dir / f"m1_dataset_report_{args.split}.md"
    write_report(
        report_path, args.split, class_report, missing_report,
        dup_report, cross_report, stats_csv_path,
    )

    print(f"\nReport written to: {report_path}")
    print(f"Feature stats CSV written to: {stats_csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())