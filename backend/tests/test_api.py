"""
test_api.py — Milestone 12

Formal pytest version of the API tests done ad hoc during M9/M10 development.
Uses a temporary SQLite database (not the real PostgreSQL one) so tests never
touch real data, and monkeypatches analyze() so these tests don't require
thrember or the trained models to be present -- they test the API's own
logic (routing, storage, error handling, security-critical cleanup), not
the ML pipeline itself (that's covered separately, see ml-training/tests/).

Run (from the ThreatLens/ directory, with the venv active):

    pytest backend/tests/test_api.py -v
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "ml-training" / "src"))


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Fresh app + fresh temp SQLite DB for every test -- no shared state
    between tests, and never touches the real PostgreSQL database."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    # Reload modules fresh so they pick up the patched DATABASE_URL
    for mod in ["main", "database", "db_models"]:
        sys.modules.pop(mod, None)

    import main as backend_main
    from fastapi.testclient import TestClient

    with TestClient(backend_main.app) as c:
        yield c, backend_main


def test_root(client):
    c, _ = client
    r = c.get("/")
    assert r.status_code == 200
    assert r.json()["service"] == "ThreatLens API"


def test_statistics_empty(client):
    c, _ = client
    r = c.get("/api/statistics")
    assert r.status_code == 200
    body = r.json()
    assert body["total_analyses"] == 0
    assert body["malicious"] == 0
    assert body["benign"] == 0


def test_analysis_not_found(client):
    c, _ = client
    r = c.get("/api/analysis/does-not-exist")
    assert r.status_code == 404


def test_explanation_not_found(client):
    c, _ = client
    r = c.get("/api/analysis/does-not-exist/explanation")
    assert r.status_code == 404


def test_analyze_success_and_persistence(client):
    c, backend_main = client

    def fake_analyze(file_path, models_dir, max_size_mb, top_k):
        assert os.path.exists(file_path), "temp file must exist while analyze() runs"
        return {
            "file_name": "irrelevant.exe", "sha256": "abc123", "file_size_bytes": 999,
            "classification": "MALICIOUS", "malicious_probability": 0.87,
            "anomaly_score": 0.6, "threat_level": "HIGH",
            "predicted_family": "wacatac",
            "top_contributing_features": [
                {"feature": "X[0]", "value": 1.0, "shap_value": 0.5, "direction": "toward malicious"}
            ],
        }
    backend_main.analyze = fake_analyze

    r = c.post("/api/analyze", files={"file": ("sample.exe", b"fake bytes", "application/octet-stream")})
    assert r.status_code == 200
    body = r.json()
    assert body["file_name"] == "sample.exe"  # real filename, not the temp path
    assert body["classification"] == "MALICIOUS"
    assert "analysis_id" in body

    # Confirm it's actually retrievable afterward (real persistence, not
    # just the response echoing back what was just sent).
    r2 = c.get(f"/api/analysis/{body['analysis_id']}")
    assert r2.status_code == 200
    assert r2.json()["sha256"] == "abc123"

    r3 = c.get(f"/api/analysis/{body['analysis_id']}/explanation")
    assert r3.status_code == 200
    assert len(r3.json()["top_contributing_features"]) == 1


def test_analyze_cleans_up_temp_file_on_success(client):
    c, backend_main = client
    captured = {}

    def fake_analyze(file_path, models_dir, max_size_mb, top_k):
        captured["path"] = file_path
        return {
            "file_name": "a.exe", "sha256": "x", "file_size_bytes": 1,
            "classification": "BENIGN", "malicious_probability": 0.01,
            "anomaly_score": 0.1, "threat_level": "LOW",
            "predicted_family": None, "top_contributing_features": [],
        }
    backend_main.analyze = fake_analyze

    c.post("/api/analyze", files={"file": ("a.exe", b"bytes", "application/octet-stream")})
    assert not os.path.exists(captured["path"]), "temp file must be deleted after a successful analysis"


def test_analyze_cleans_up_temp_file_on_failure(client):
    """Security-critical: even when analyze() raises, no temp file should
    be left behind on disk."""
    c, backend_main = client
    captured = {}

    def failing_analyze(file_path, models_dir, max_size_mb, top_k):
        captured["path"] = file_path
        raise ValueError("simulated failure")
    backend_main.analyze = failing_analyze

    r = c.post("/api/analyze", files={"file": ("bad.exe", b"junk", "application/octet-stream")})
    assert r.status_code == 400
    assert not os.path.exists(captured["path"]), "temp file must be deleted even when analyze() raises"


def test_statistics_aggregation(client):
    c, backend_main = client

    def make_analyze(classification, tier, proba):
        def fn(file_path, models_dir, max_size_mb, top_k):
            return {
                "file_name": "x.exe", "sha256": "x", "file_size_bytes": 1,
                "classification": classification, "malicious_probability": proba,
                "anomaly_score": 0.1, "threat_level": tier,
                "predicted_family": None, "top_contributing_features": [],
            }
        return fn

    backend_main.analyze = make_analyze("MALICIOUS", "HIGH", 0.9)
    c.post("/api/analyze", files={"file": ("a.exe", b"x", "application/octet-stream")})
    backend_main.analyze = make_analyze("BENIGN", "LOW", 0.01)
    c.post("/api/analyze", files={"file": ("b.exe", b"x", "application/octet-stream")})
    backend_main.analyze = make_analyze("BENIGN", "LOW", 0.02)
    c.post("/api/analyze", files={"file": ("c.exe", b"x", "application/octet-stream")})

    r = c.get("/api/statistics")
    body = r.json()
    assert body["total_analyses"] == 3
    assert body["malicious"] == 1
    assert body["benign"] == 2
    assert body["threat_level_distribution"]["LOW"] == 2
    assert body["threat_level_distribution"]["HIGH"] == 1


def test_list_analyses_ordering(client):
    """/api/analyses should return most recent first."""
    c, backend_main = client

    def make_analyze(name):
        def fn(file_path, models_dir, max_size_mb, top_k):
            return {
                "file_name": name, "sha256": name, "file_size_bytes": 1,
                "classification": "BENIGN", "malicious_probability": 0.01,
                "anomaly_score": 0.1, "threat_level": "LOW",
                "predicted_family": None, "top_contributing_features": [],
            }
        return fn

    backend_main.analyze = make_analyze("first.exe")
    c.post("/api/analyze", files={"file": ("first.exe", b"x", "application/octet-stream")})
    backend_main.analyze = make_analyze("second.exe")
    c.post("/api/analyze", files={"file": ("second.exe", b"x", "application/octet-stream")})

    r = c.get("/api/analyses")
    names = [a["file_name"] for a in r.json()]
    assert names[0] == "second.exe"  # most recent first
    assert names[1] == "first.exe"


def test_analyze_error_returns_400_not_500(client):
    """A pipeline error (e.g. malformed file) should be a clean 400 with a
    message, not an unhandled 500 -- the API shouldn't crash on bad input."""
    c, backend_main = client

    def failing_analyze(file_path, models_dir, max_size_mb, top_k):
        raise ValueError("not a valid PE file")
    backend_main.analyze = failing_analyze

    r = c.post("/api/analyze", files={"file": ("bad.exe", b"not a real exe", "application/octet-stream")})
    assert r.status_code == 400
    assert "not a valid PE file" in r.json()["detail"]