"""
main.py — Milestone 9: FastAPI service

Exposes the ML pipeline (M3-M8) as a REST API. Storage is in-memory for
now (a plain dict) -- Milestone 10 replaces this with PostgreSQL. The
endpoints and their shape are designed so that swap is additive, not a
rewrite: ANALYSES becomes a database-backed repository, the route
handlers stay the same.

SECURITY NOTES (per blueprint Section 22 -- the upload endpoint is
itself attack surface):
  - Uploaded bytes are written to a RANDOMIZED temp path (tempfile.mkstemp),
    never to a path derived from the user-supplied filename -- no path
    traversal is possible from the original filename.
  - The temp file is always removed in a `finally` block, including on
    error -- no leftover files from failed/partial analyses.
  - File size is checked before writing to disk.
  - The uploaded file is NEVER executed -- analyze() (imported from M8's
    analyze_file.py) only ever reads bytes via thrember's static PE
    parser.
  - The original filename is kept ONLY as a display label in the
    response, never used to construct a filesystem path.

Run (from the ThreatLens/ directory, with the venv active):

    uvicorn backend.main:app --reload --port 8000

Then, e.g.: POST a file to http://127.0.0.1:8000/api/analyze
Interactive docs: http://127.0.0.1:8000/docs
"""

import os
import sys
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

# Reuse M8's already-tested analyze() function directly, rather than
# re-implementing the pipeline here.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml-training" / "src"))
from analyze_file import analyze  # noqa: E402

MODELS_DIR = str(Path(__file__).resolve().parent.parent / "ml-training" / "models")
MAX_SIZE_MB = 100.0
TOP_K = 5

app = FastAPI(
    title="ThreatLens API",
    description="Defensive malware intelligence platform -- static analysis only, "
                 "never executes uploaded files.",
    version="0.1.0",
)

# Permissive for local development; the M11 React dashboard will call this
# from a different port. Tighten allow_origins before any real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store: analysis_id -> result dict. Replaced by PostgreSQL in M10.
ANALYSES: dict = {}


@app.post("/api/analyze")
async def analyze_endpoint(file: UploadFile = File(...)):
    contents = await file.read()
    size_mb = len(contents) / (1024 * 1024)
    if size_mb > MAX_SIZE_MB:
        raise HTTPException(status_code=413, detail=f"File exceeds {MAX_SIZE_MB} MB limit.")

    # Randomized temp filename -- the original filename is never used to
    # build a filesystem path.
    fd, tmp_path = tempfile.mkstemp(suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(contents)
        result = analyze(tmp_path, MODELS_DIR, MAX_SIZE_MB, TOP_K)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        # Always clean up, including on error -- no leftover files.
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

    analysis_id = str(uuid.uuid4())
    result["analysis_id"] = analysis_id
    result["file_name"] = file.filename  # overwrite the internal temp filename with the real one
    ANALYSES[analysis_id] = result

    return result


@app.get("/api/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    result = ANALYSES.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return result


@app.get("/api/analysis/{analysis_id}/explanation")
def get_explanation(analysis_id: str):
    result = ANALYSES.get(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return {
        "analysis_id": analysis_id,
        "top_contributing_features": result.get("top_contributing_features", []),
    }


@app.get("/api/statistics")
def get_statistics():
    total = len(ANALYSES)
    malicious = sum(1 for r in ANALYSES.values() if r.get("classification") == "MALICIOUS")
    benign = total - malicious
    tier_counts: dict = {}
    for r in ANALYSES.values():
        tier = r.get("threat_level", "UNKNOWN")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    return {
        "total_analyses": total,
        "malicious": malicious,
        "benign": benign,
        "threat_level_distribution": tier_counts,
    }


@app.get("/api/models")
def get_models():
    import json

    thresholds_path = Path(MODELS_DIR) / "risk_thresholds.json"
    thresholds = json.loads(thresholds_path.read_text(encoding="utf-8")) if thresholds_path.exists() else None

    return {
        "malware_detector": "XGBoost (selected in M3 over Logistic Regression, Random Forest)",
        "anomaly_detector": "Isolation Forest (selected in M4 over Autoencoder)",
        "family_classifier": "Random Forest, 21 classes (20 named families + 'other')"
                              if (Path(MODELS_DIR) / "family_classifier.joblib").exists() else None,
        "risk_thresholds": thresholds,
        "training_scope": "EMBER2024 .NET file-type slice only -- see README for scope caveat "
                           "regarding Win32/Win64 generalization.",
    }


@app.get("/")
def root():
    return {
        "service": "ThreatLens API",
        "docs": "/docs",
        "note": "Defensive static analysis only. Uploaded files are never executed.",
    }