"""
dedupe.py — Milestone 2, Step 1

Removes exact-duplicate feature vectors from a vectorized EMBER2024 split
and writes the deduplicated result as new .dat files, alongside a
before/after report.

Why this exists: M1 found that the .NET test split is ~50% exact-duplicate
rows, split evenly across both classes — almost certainly from the same
file being resubmitted to VirusTotal across more than one of the 12 weeks
that make up a split. Training or evaluating on that as-is risks inflated,
misleading metrics (a model can "learn" by memorizing a duplicate that
leaked between train and test, rather than by learning real signal).

This script keeps the FIRST occurrence of each unique feature vector and
drops the rest — a conservative, simple policy. It does not yet do
near-duplicate or family-aware/temporal leakage removal — those are
separate, planned follow-ups once train data is involved (M2 continued).

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\dedupe.py --data-dir ml-training\\data --split test
"""

import argparse
import hashlib
import sys
from pathlib import Path

import numpy as np


def load_split(data_dir: str, split: str):
    try:
        import thrember
    except ImportError:
        print("ERROR: thrember is not installed. See README.md 'Setup' step.", file=sys.stderr)
        sys.exit(1)

    x_path = Path(data_dir) / f"X_{split}.dat"
    y_path = Path(data_dir) / f"y_{split}.dat"
    if not x_path.exists() or not y_path.exists():
        print(
            f"ERROR: '{x_path}' or '{y_path}' not found. Run inspect_dataset.py "
            f"on this split first (it vectorizes the raw data), then retry.",
            file=sys.stderr,
        )
        sys.exit(1)

    X, y = thrember.read_vectorized_features(data_dir, subset=split)
    return np.asarray(X), np.asarray(y)


def dedupe_keep_first(X: np.ndarray, y: np.ndarray):
    """Keeps the first occurrence of each unique feature vector (exact
    byte-match), drops every later occurrence. Returns the deduplicated
    arrays plus a small report dict."""
    n_rows = X.shape[0]
    seen_hashes: dict = {}
    keep_mask = np.zeros(n_rows, dtype=bool)

    for i in range(n_rows):
        h = hashlib.blake2b(X[i].tobytes(), digest_size=16).digest()
        if h not in seen_hashes:
            seen_hashes[h] = i
            keep_mask[i] = True

    X_dedup = X[keep_mask]
    y_dedup = y[keep_mask]

    report = {
        "rows_before": n_rows,
        "rows_after": int(keep_mask.sum()),
        "rows_removed": int(n_rows - keep_mask.sum()),
        "removed_pct": round(100.0 * (n_rows - keep_mask.sum()) / n_rows, 4) if n_rows else 0.0,
    }
    return X_dedup, y_dedup, report


def save_dedup(data_dir: str, split: str, X_dedup: np.ndarray, y_dedup: np.ndarray) -> None:
    """Writes deduplicated arrays as new .dat files, in the same raw binary
    layout thrember itself uses (float32 for X, int32 for y), so they can
    be read back the same way — just under a '_dedup' subset name."""
    data_path = Path(data_dir)
    X_dedup.astype(np.float32).tofile(data_path / f"X_{split}_dedup.dat")
    y_dedup.astype(np.int32).tofile(data_path / f"y_{split}_dedup.dat")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remove exact-duplicate feature vectors from a vectorized EMBER2024 split."
    )
    parser.add_argument("--data-dir", required=True, help="Directory containing the vectorized .dat files.")
    parser.add_argument("--split", required=True, choices=["train", "test", "challenge"])
    args = parser.parse_args()

    print(f"Loading split='{args.split}' from '{args.data_dir}' ...")
    X, y = load_split(args.data_dir, args.split)
    print(f"Loaded X.shape={X.shape}, y.shape={y.shape}")

    print("Deduplicating (keeping first occurrence of each unique feature vector) ...")
    X_dedup, y_dedup, report = dedupe_keep_first(X, y)

    print("\n--- Deduplication report ---")
    for key, val in report.items():
        print(f"{key}: {val}")

    save_dedup(args.data_dir, args.split, X_dedup, y_dedup)
    print(
        f"\nSaved deduplicated arrays to: "
        f"{Path(args.data_dir) / f'X_{args.split}_dedup.dat'} and "
        f"{Path(args.data_dir) / f'y_{args.split}_dedup.dat'}"
    )
    print(
        "\nTo load these later: "
        "thrember.read_vectorized_features(data_dir, subset='"
        f"{args.split}_dedup')"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())