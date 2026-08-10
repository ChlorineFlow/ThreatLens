"""
download_data.py — Milestone 1, Step 1

Thin, explicit CLI wrapper around `thrember.download_dataset`, so we never
download more of EMBER2024 than we intend to.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\download_data.py --file-type PE --split challenge
    python ml-training\\src\\download_data.py --file-type PE --split test

Why this file exists instead of calling thrember directly in a notebook:
the EMBER2024 splits range from ~24 MB (ELF test) to ~24 GB (Win32 train).
A one-line typo in a notebook cell can trigger an accidental multi-hour,
multi-GB download. This script forces you to pass --file-type and --split
explicitly and prints the documented size before downloading.
"""

import argparse
import sys
from typing import Optional

# Approximate sizes from the EMBER2024 README, used only to warn the user
# before a large download — not used for any computation.
KNOWN_SIZES_GB = {
    ("Win32", "train"): 23.7,
    ("Win32", "test"): 4.9,
    ("Win64", "train"): 12.9,
    ("Win64", "test"): 2.5,
    ("Dot_Net", "train"): 1.8,
    ("Dot_Net", "test"): 0.43,
    ("APK", "train"): 1.0,
    ("APK", "test"): 0.23,
    ("PDF", "train"): 0.20,
    ("PDF", "test"): 0.05,
    ("ELF", "train"): 0.10,
    ("ELF", "test"): 0.03,
    ("PE", "challenge"): 0.126,
}

# These are the exact strings thrember.download_dataset() accepts — confirmed
# from its own error message: "file_type must be in all, PE, Win32, Win64,
# Dot_Net, APK, ELF, PDF". "all" is omitted here deliberately so this script
# never accidentally triggers a full-dataset download.
VALID_FILE_TYPES = ["Win32", "Win64", "Dot_Net", "APK", "PDF", "ELF", "PE"]
VALID_SPLITS = ["train", "test", "challenge"]


def estimate_size_gb(file_type: str, split: str) -> Optional[float]:
    if split == "challenge":
        return KNOWN_SIZES_GB.get(("PE", "challenge"))
    if file_type == "PE":
        # PE is the combined Win32 + Win64 + .NET group.
        parts = [KNOWN_SIZES_GB.get((ft, split), 0) for ft in ("Win32", "Win64", "Dot_Net")]
        return sum(parts) if all(p is not None for p in parts) else None
    return KNOWN_SIZES_GB.get((file_type, split))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download a specific slice of EMBER2024 via thrember."
    )
    parser.add_argument(
        "--file-type",
        required=True,
        choices=VALID_FILE_TYPES,
        help="Which file-type group to download. PE = Win32+Win64+.NET combined.",
    )
    parser.add_argument(
        "--split",
        required=True,
        choices=VALID_SPLITS,
        help="train, test, or challenge. challenge ignores --file-type (it's PE-only).",
    )
    parser.add_argument(
        "--data-dir",
        default="ml-training/data",
        help="Destination directory (default: ml-training/data).",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt (useful for scripted/CI runs).",
    )
    args = parser.parse_args()

    try:
        import thrember
    except ImportError:
        print(
            "ERROR: thrember is not installed. See README.md 'Setup' step — "
            "it must be installed from source (git clone + pip install .), "
            "it is not on PyPI.",
            file=sys.stderr,
        )
        return 1

    est = estimate_size_gb(args.file_type, args.split)
    est_str = f"~{est:.2f} GB" if est is not None else "unknown size"
    print(f"About to download file_type={args.file_type} split={args.split} "
          f"({est_str}) into '{args.data_dir}'.")

    if not args.yes:
        confirm = input("Proceed? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return 0

    if args.split == "challenge":
        thrember.download_dataset(args.data_dir, split="challenge")
    else:
        thrember.download_dataset(
            args.data_dir, file_type=args.file_type, split=args.split
        )

    print("Download finished. Next step: vectorize + inspect with "
          "ml-training/src/inspect_dataset.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())