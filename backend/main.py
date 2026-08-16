"""
main.py — Milestone 9 (FastAPI) + Milestone 10 (PostgreSQL)

Exposes the ML pipeline (M3-M8) as a REST API, now backed by PostgreSQL
(see database.py, db_models.py) instead of the in-memory dict M9 started
with. Route shapes are unchanged from M9 -- only the storage layer swapped,
as planned.

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
  - Database credentials come from .env (gitignored), never hardcoded --
    see database.py.

Run (from the ThreatLens/ directory, with the venv active):

    uvicorn backend.main:app --reload --port 8000

Then, e.g.: POST a file to http://127.0.0.1:8000/api/analyze
Interactive docs: http://127.0.0.1:8000/docs
"""

import os
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
from database import Base, engine, get_db  # noqa: E402
from db_models import Analysis  # noqa: E402

# Reuse M8's already-tested analyze() function directly, rather than
# re-implementing the pipeline here.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ml-training" / "src"))
from analyze_file import analyze  # noqa: E402

MODELS_DIR = str(Path(__file__).resolve().parent.parent / "ml-training" / "models")
MAX_SIZE_MB = 100.0
TOP_K = 5


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Simple schema creation -- no migration tool (Alembic etc.) yet,
    # since the schema is still small and single-table. Add one if/when
    # the schema needs versioned migrations, not preemptively.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="ThreatLens API",
    description="Defensive malware intelligence platform -- static analysis only, "
                 "never executes uploaded files.",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/api/analyze")
async def analyze_endpoint(file: UploadFile = File(...), db: Session = Depends(get_db)):
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

    record = Analysis(
        file_name=file.filename,
        sha256=result["sha256"],
        file_size_bytes=result["file_size_bytes"],
        classification=result["classification"],
        malicious_probability=result["malicious_probability"],
        anomaly_score=result["anomaly_score"],
        threat_level=result["threat_level"],
        predicted_family=result.get("predicted_family"),
        top_contributing_features=result["top_contributing_features"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return record.to_dict()

@app.get("/api/analyses")
def list_analyses(limit: int = 50, db: Session = Depends(get_db)):
    records = (
        db.query(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .all()
    )
    return [r.to_dict() for r in records]

@app.get("/api/analysis/{analysis_id}")
def get_analysis(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return record.to_dict()


@app.get("/api/analysis/{analysis_id}/explanation")
def get_explanation(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return {
        "analysis_id": analysis_id,
        "top_contributing_features": record.top_contributing_features,
    }


@app.get("/api/statistics")
def get_statistics(db: Session = Depends(get_db)):
    total = db.query(Analysis).count()
    malicious = db.query(Analysis).filter(Analysis.classification == "MALICIOUS").count()
    benign = total - malicious

    tier_rows = (
        db.query(Analysis.threat_level, func.count(Analysis.id))
        .group_by(Analysis.threat_level)
        .all()
    )
    tier_counts = {tier: count for tier, count in tier_rows}

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