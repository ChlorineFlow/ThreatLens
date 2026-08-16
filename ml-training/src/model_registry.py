"""
model_registry.py — Milestone 13 (MLOps)

Lightweight, file-based model registry -- deliberately NOT MLflow/DVC.
Those bring real value at team scale with many collaborators and
long-running experiment histories; for this project's actual scale (one
developer, ~5 model artifacts, produced by scripts already tracked in
git), a JSON manifest recording what each artifact IS, when it was made,
against which git commit, and which report documents its metrics gives
the same practical reproducibility without the operational overhead of
running a tracking server. Add a heavier tool if/when the project's
scale actually needs one -- not preemptively (per the blueprint's own
"do not add tools merely for buzzwords" guidance).

Records, for each known model artifact:
  - file path, size, sha256 (integrity -- detects silent corruption or
    an accidental overwrite with a different model)
  - last-modified timestamp
  - the git commit HEAD at the time the registry was built (best-effort;
    requires being run inside the git repo)
  - the report file that documents this artifact's actual metrics

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\model_registry.py
"""

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MODELS_DIR = Path("ml-training/models")
REPORTS_DIR = Path("ml-training/reports")

# artifact filename (relative to MODELS_DIR) -> the report that documents it
KNOWN_ARTIFACTS = {
    "malware_detector.joblib": "m3_model_comparison.md",
    "anomaly_detector.joblib": "m4_anomaly_report_isolation_forest.md",
    "anomaly_detector_autoencoder.joblib": "m4_anomaly_report_autoencoder.md",
    "family_classifier.joblib": "m5_family_report.md",
    "family_label_encoder.joblib": "m5_family_report.md",
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def current_git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "unknown (not run inside a git repo, or git not available)"


def build_registry() -> dict:
    commit = current_git_commit()
    entries = []
    for filename, report_name in KNOWN_ARTIFACTS.items():
        path = MODELS_DIR / filename
        if not path.exists():
            continue
        report_path = REPORTS_DIR / report_name
        entries.append({
            "artifact": filename,
            "size_bytes": path.stat().st_size,
            "sha256": sha256_of(path),
            "last_modified": datetime.fromtimestamp(
                path.stat().st_mtime, tz=timezone.utc
            ).isoformat(),
            "documented_in": str(report_path) if report_path.exists() else None,
        })
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit_at_registry_build": commit,
        "artifacts": entries,
    }


def main() -> int:
    if not MODELS_DIR.exists():
        print(f"ERROR: '{MODELS_DIR}' not found. Train models first (M3-M5).", file=sys.stderr)
        return 1

    registry = build_registry()
    out_path = MODELS_DIR / "model_registry.json"
    out_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")

    print(f"Registered {len(registry['artifacts'])} artifact(s) at commit "
          f"{registry['git_commit_at_registry_build'][:12]}:")
    for e in registry["artifacts"]:
        print(f"  {e['artifact']:38s} {e['size_bytes']:>10} bytes  sha256={e['sha256'][:12]}...")
    print(f"\nWritten to: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())