# ThreatLens — AI-Powered Malware Intelligence & Threat Analysis Platform

> **Status:** Milestones 1–14 complete (M14 is the blueprint's optional advanced phase),
> plus M15 — adversarial robustness testing (bonus, beyond the original blueprint).
> Current scope: trained and validated on the EMBER2024 `.NET` file-type slice.
> Win32/Win64 generalization validation is planned as a follow-up (see **Known limitations** below).

An explainable machine-learning platform for static malware detection, anomaly
analysis, malware family attribution, and analyst-facing threat scoring — with
a FastAPI + PostgreSQL backend and a React analyst dashboard.

This is strictly a **defensive** cybersecurity project — malware detection,
anomaly detection, family classification, and explainability. It never
implements malware creation, evasion, or offensive tooling, and it never
executes an uploaded or downloaded file. See **Responsible use** below.

---

## Project structure

```
ThreatLens/
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example                 <- template; copy to .env with your real DB password
├── backend/
│   ├── main.py                  <- FastAPI service (M9, M10)
│   ├── database.py               <- SQLAlchemy engine/session (M10)
│   ├── db_models.py              <- Analysis ORM model (M10)
│   └── tests/
│       └── test_api.py           <- pytest suite for the API (M12)
├── frontend/                     <- React + Vite + Tailwind dashboard (M11)
│   └── src/
│       ├── App.jsx
│       └── components/
│           ├── ParticleBackground.jsx
│           └── ThemeToggle.jsx
└── ml-training/
    ├── data/                     <- downloaded/vectorized EMBER2024 files (gitignored)
    ├── models/                   <- trained model artifacts (gitignored)
    ├── reports/                  <- generated milestone reports (gitignored)
    ├── tests/
    │   └── test_pipeline_logic.py  <- pytest suite for core ML logic (M12)
    └── src/
        ├── download_data.py       <- M1: guarded CLI dataset downloader
        ├── inspect_dataset.py     <- M1: dataset-understanding report
        ├── dedupe.py              <- M2: exact-duplicate removal
        ├── train_detector.py      <- M3: malware detection model
        ├── train_anomaly.py       <- M4: anomaly detection model
        ├── train_family.py        <- M5: malware family classifier
        ├── explain.py             <- M6: SHAP explainability
        ├── risk_engine.py         <- M7: risk tier engine
        ├── analyze_file.py        <- M8: safe static file analyzer
        ├── model_registry.py      <- M13: lightweight MLOps provenance tracking
        └── build_threat_graph.py  <- M14: optional threat intelligence graph
```

`ml-training/data/`, `ml-training/models/`, `ml-training/reports/`, and `.env`
are gitignored — the dataset and model artifacts are multi-GB and fully
regenerable from these scripts, and `.env` holds real credentials that must
never reach a public repo.

---

## Setup (Windows, PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

git clone https://github.com/FutureComputing4AI/EMBER2024.git
cd EMBER2024
pip install .
cd ..
```

`thrember` (the EMBER2024 toolkit) is not on PyPI, so it's installed from
source as shown above.

**Known compatibility fixes required** (the installed `signify` release, 0.9.1+,
reorganized its internals in ways `thrember` wasn't written against):

1. In `.venv\Lib\site-packages\thrember\features.py`, line ~28: change
   `from signify.authenticode import SignedPEFile` to
   `from signify.authenticode.signed_file import SignedPEFile`.
2. In the same file's `AuthenticodeSignature.raw_features` method, change
   `signed_pe.iter_signed_datas()` to `signed_pe.iter_embedded_signatures()`.
3. In that method's exception chain, add `except AttributeError:` and
   `except TypeError:` (each followed by `raw_obj["parse_error"] = 1`) as a
   safety net for any further `signify` API drift — these are small, well-
   isolated features (8 of 2,568 dimensions), and graceful degradation beats
   chasing every point-release API change.

Verify with: `python -c "import thrember; print('thrember OK')"`

For the backend, copy `.env.example` to `.env` and fill in your real
PostgreSQL password — see **Milestone 10** below.

---

## Milestone 1 — Dataset Understanding

```powershell
python ml-training\src\download_data.py --file-type PE --split challenge
python ml-training\src\download_data.py --file-type Dot_Net --split test
python ml-training\src\download_data.py --file-type Dot_Net --split train
python ml-training\src\inspect_dataset.py --data-dir ml-training\data --split test
```

We built and validated the full pipeline on the smallest relevant file family
(`.NET`) first, before scaling up — same feature extractor and pipeline, far
less data to move while everything was still being debugged.

**Findings:** challenge set (6,315 samples, 2,568 features) is 100% malicious
as expected (evasive-sample set by design). `.NET` test set (120,000 samples)
has a real 50/50 benign/malicious balance. All counts and dimensionality
match EMBER2024's published documentation exactly. Zero missing/invalid
values across every split checked.

---

## Milestone 2 — Data Pipeline (Dedup + Leakage Check)

```powershell
python ml-training\src\dedupe.py --data-dir ml-training\data --split test
python ml-training\src\dedupe.py --data-dir ml-training\data --split train
```

**Key finding:** ~50% of rows in both the `.NET` train and test splits are
exact-duplicate feature vectors, evenly split across both classes — almost
certainly from the same file being resubmitted to VirusTotal across more
than one of the weeks that make up a split. After deduplication (260,000
train rows, 59,953 test rows), **train↔test exact overlap is 0%** — the
official temporal split boundary holds; only within-split duplication needed
correcting.

---

## Milestone 3 — Malware Detection Model

```powershell
python ml-training\src\train_detector.py --data-dir ml-training\data
```

Trained and compared Logistic Regression, Random Forest, and XGBoost on the
deduplicated split, evaluated on precision/recall/F1/ROC-AUC/PR-AUC/confusion
matrix/FPR/FNR — never bare accuracy.

| Model | PR-AUC | ROC-AUC | F1 | FPR | FNR |
|---|---|---|---|---|---|
| **XGBoost (selected)** | **0.9978** | **0.9977** | **0.9778** | 2.75% | 1.71% |
| Random Forest | 0.9949 | 0.9952 | 0.9685 | 3.90% | 2.44% |
| Logistic Regression | 0.9852 | 0.9865 | 0.9503 | 5.81% | 4.21% |

**Selected: XGBoost**, on PR-AUC, with the lowest false-negative rate of the
three (missed detections are typically costlier than false alarms).

---

## Milestone 4 — Anomaly Detection Model

```powershell
python ml-training\src\train_anomaly.py --data-dir ml-training\data --model isolation_forest
python ml-training\src\train_anomaly.py --data-dir ml-training\data --model autoencoder
```

Trained on **benign-only** data — it never sees a malicious label, only
learns what "normal" looks like, then scores any sample against that
baseline. One-Class SVM was skipped (doesn't scale to this row count).

| Model | ROC-AUC | PR-AUC | Precision @ top 10% |
|---|---|---|---|
| **Isolation Forest (selected)** | **0.7471** | **0.7563** | **0.8911** |
| Autoencoder (MLPRegressor, benign-reconstruction) | 0.7134 | 0.7167 | 0.8714 |

Weaker separation than the supervised detector is expected and correct — this
model is a complementary, differently-sourced signal, not a competitor to it.
The genuinely useful number: if an analyst reviewed only the top 10% most
anomalous samples, 89% would actually be malicious.

---

## Milestone 5 — Malware Family Classifier

```powershell
python ml-training\src\train_family.py --data-dir ml-training\data --top-n 20
```

Real family **names** (not opaque integer IDs) recovered via
`thrember.read_metadata()`, since `create_vectorized_features()`'s internal
name→integer mapping is never persisted. Top-20 families by frequency kept
as their own class; everything else bucketed as `other`.

**Result:** 21-class Random Forest, macro F1 **0.4496**, accuracy 0.54,
on 204,062 usable malicious+family-tagged train rows. Best-performing class:
`xworm` (F1 0.88). This is a realistic result for a heavily imbalanced
21-class problem (support ranges from 78 to 20,666 test samples) — not a
weak number in context.

Model artifact was originally 1.76 GB (`n_estimators=200`, unconstrained
depth) — impractical to load/serve. Retrained with `max_depth=25,
min_samples_leaf=5` → **535 MB**, macro F1 dropped from 0.4866 to 0.4496.
Accepted trade-off: ~3.3× smaller for a documented, modest accuracy cost.

---

## Milestone 6 — Explainability (SHAP)

```powershell
python ml-training\src\explain.py --data-dir ml-training\data
```

Feature names are built dynamically from `thrember`'s actual extractor
structure (e.g. `SectionInfo[12]`) — genuine, not decorative labels.
Explanations generated for a representative mix: true positives, true
negatives, false positives, and false negatives.

**Key finding:** one feature, `HeaderFileInfo[43]`, dominates nearly every
prediction — every false positive has it at `0.0`, every false negative has
it at `1.0`. This directly explains the model's error pattern, not just its
correct predictions — a genuinely useful interpretability result, and a
concrete, named limitation to discuss rather than a vague caveat.

---

## Milestone 7 — Risk Engine

```powershell
python ml-training\src\risk_engine.py --data-dir ml-training\data
```

Combines detection probability and anomaly score into LOW/MODERATE/ELEVATED/
HIGH/CRITICAL. Thresholds are anchored to actual points on the
precision-recall curve (recall≥99%, F1-optimal, precision≥95%,
precision≥99%), not arbitrary cutoffs — enforced to be monotonically
non-decreasing since raw precision isn't always perfectly monotonic on
finite data. A sample's tier escalates by one level if it's also in the top
10% most anomalous (matching M4's own cutoff), unless already CRITICAL.

**Result — tiers are cleanly monotonic in actual risk:**

| Tier | Actually malicious |
|---|---|
| LOW | 1.0% |
| MODERATE | 20.97% |
| ELEVATED | 41.67% |
| HIGH | 67.23% |
| CRITICAL | 98.91% |

95.6% of test samples land in the two confident extreme tiers (LOW or
CRITICAL) — most files get a confident, near-automatic verdict; only a
small fraction need closer analyst review.

---

## Milestone 8 — Safe Static File Analyzer

```powershell
python ml-training\src\analyze_file.py --file "C:\path\to\sample.exe"
```

Ties M3–M7 into the full described pipeline: Upload → validation → safe PE
parsing (`pefile`, via `thrember`) → feature extraction → detection model →
anomaly model → family model (if malicious) → SHAP → risk engine → threat
report. **The file is never executed** — only its bytes are read.

**Validated on two real files:**
- `InstallUtil.exe` (a genuine `.NET` executable): BENIGN, 0.17% confidence,
  LOW threat — correct.
- `notepad.exe` (a native Win32 executable, out of the `.NET`-only training
  domain): misclassified MALICIOUS — expected and documented (see **Known
  limitations**), not a pipeline defect.

---

## Milestone 9 — FastAPI Service

```powershell
uvicorn backend.main:app --reload --port 8000
```

Interactive docs at `http://127.0.0.1:8000/docs`. Endpoints: `POST
/api/analyze`, `GET /api/analyses`, `GET /api/analysis/{id}`, `GET
/api/analysis/{id}/explanation`, `GET /api/statistics`, `GET /api/models`.

**Upload security (blueprint Section 22):** uploaded bytes are written to a
randomized temp path (`tempfile.mkstemp`) — never a path derived from the
user-supplied filename — always cleaned up in a `finally` block including on
error, size-checked before processing, and never executed.

---

## Milestone 10 — PostgreSQL

```powershell
psql -U postgres -h localhost -c "CREATE DATABASE threatlens;"
```

Copy `.env.example` to `.env` and set your real `DATABASE_URL`. `.env` is
gitignored — credentials never reach the public repo. Replaces M9's
in-memory dict with real persistence (`backend/database.py`,
`backend/db_models.py`); route shapes were designed to make this swap
additive, not a rewrite. Verified two ways: via the API's own read-back, and
visually in pgAdmin.

---

## Milestone 11 — React Dashboard

```powershell
cd frontend
npm install
npm run dev
```

React + Vite + Tailwind v4. Cybersecurity-themed design (deliberately not
the generic "AI website" near-black + green look): deep navy / electric
blue + amber palette grounded in real SOC tooling conventions, IBM Plex
Mono/Sans typography, dark/light toggle, and an animated particle network
background — a visual echo of the project's own threat-intelligence-graph
concept (M14), not pure decoration. Pages: Dashboard (Recharts analytics —
donut for malicious/benign split, bar chart for threat tiers, confidence
trend line, family breakdown), Analyze Sample, History, Models.

Validated end-to-end through the actual UI, not just `/docs`.

---

## Milestone 12 — Testing

```powershell
pytest -v
```

17 tests, all passing: `backend/tests/test_api.py` (10 tests — routing,
error handling, statistics aggregation, and the **security-critical**
temp-file cleanup on both success and failure paths) and
`ml-training/tests/test_pipeline_logic.py` (7 tests — dedup, anomaly
evaluation, family label bucketing, risk threshold monotonicity, tier
escalation).

---

## Milestone 13 — MLOps

```powershell
python ml-training\src\model_registry.py
```

Deliberately **not** MLflow/DVC — at this project's actual scale (one
developer, ~5 model artifacts), a full tracking server adds operational
weight without proportional benefit. Instead: a JSON manifest recording,
per artifact, its size, sha256 (integrity check), last-modified time, git
commit at build time, and which report documents its metrics. Genuine
reproducibility without the overhead.

---

## Milestone 14 — Threat Intelligence Graph (optional)

```powershell
python ml-training\src\build_threat_graph.py --data-dir ml-training\data --n-samples 200
```

Built with NetworkX, per the blueprint's own guidance to start there rather
than a graph database or GNN without justification. Nodes: samples and
predicted families. Edges: `belongs_to` (sample→family) and
`shares_characteristics_with` (sample↔sample, when top-5 SHAP features
overlap by Jaccard similarity ≥ 0.4) — an operationalization of "shared
characteristics" grounded in M6's explainability work, not invented.

**Result (200 samples):** 14 distinct families found, 1 connected component,
3 communities detected via greedy modularity — the graph structure
genuinely reflects family groupings, verified against synthetic data with
known clusters before running on real samples. Outputs: `.graphml` (for
external tools), a static visualization, and a summary report.

---

## Milestone 15 — Adversarial Robustness Testing

```powershell
python ml-training\src\adversarial_robustness_test.py --data-dir ml-training\data
```

Directly follows up on the M6 SHAP finding that the detector leans heavily
on `HeaderFileInfo[43]`: rather than leaving that as an interpretability
observation, this milestone tests whether it's an actual, exploitable
evasion vector.

**Experiment 1 — single-feature perturbation.** For real malicious test
samples, `HeaderFileInfo[43]` was set to its typical benign value (leaving
every other feature untouched) and the sample rescored.

| Metric | Result |
|---|---|
| Samples tested | 29,425 |
| Flipped to BENIGN | 4,361 (**14.82%**) |
| Mean confidence before | 98.5% |
| Mean confidence after | 82.77% |

**Experiment 2 — epsilon-ball robustness curve.** Bounded perturbation
across the feature space, at increasing budgets:

| Epsilon | Flip rate |
|---|---|
| 0.10 | 4.64% |
| 0.25 | 6.61% |
| 0.50 | 7.86% |
| 1.00 | 10.48% |
| 2.00 | 19.92% |

**Finding:** the model's known reliance on one feature is a real, measurable
evasion vector — changing that single structural value, without altering a
file's actual malicious behavior, flips ~15% of confident malicious
predictions to benign. The epsilon-curve's smooth, monotonic increase
(more perturbation → more evasion, no anomalous jumps) is itself evidence
the test methodology is behaving correctly. This converts an
interpretability observation (M6) into a quantified, tested limitation —
exactly the kind of finding that should be disclosed rather than
discovered by someone else asking "is this robust?"

---

## Known limitations

- **Training scope is `.NET` only.** Deliberately chosen to validate the
  full 14-milestone pipeline quickly; not yet re-validated on Win32/Win64.
  `notepad.exe` (native, out-of-domain) is a confirmed misclassification —
  expected given the scope, and evidence the limitation is real and
  understood, not hidden. Win32/Win64 retraining uses the identical scripts
  (`--train-subset`/`--test-subset` are generic) and is the natural next
  step, deferred for time/compute cost (Win32 train alone is 23.7 GB).
- **`HeaderFileInfo[43]` dominates the detector's predictions** (M6) — and
  M15 confirmed this is a real, exploitable evasion vector: perturbing just
  this feature flips ~15% of confident malicious predictions to benign
  (see Milestone 15). A production system would need either adversarial
  training or feature-level hardening to address this.
- **No hyperparameter search was performed** — model configs (XGBoost's
  `max_depth=6`, Random Forest's `n_estimators`, etc.) are reasonable
  defaults, not the output of a tuning process.
- **No authentication on the API.** Appropriate for a local research tool;
  would be required before any real deployment.
- **Single temporal train/test split**, no cross-validation confidence
  intervals — standard practice for a "generalizes forward in time"
  evaluation, but worth naming explicitly.
- **Family classifier accuracy is realistic, not high**, on a genuinely hard
  21-class, long-tail-imbalanced problem — see Milestone 5 for the honest
  per-class breakdown.

---

## Core ML components

**1. Malware Detection Model** — XGBoost, selected over Logistic Regression
and Random Forest via a documented PR-AUC comparison (M3).

**2. Anomaly Detection Model** — Isolation Forest, trained on benign-only
data, selected over an Autoencoder (M4). A proxy for "worth a closer look,"
never presented as zero-day detection.

**3. Malware Family Classifier** — Random Forest, 21 classes from
EMBER2024's actual ClarAVy-assigned family tags — never invented categories
(M5).

## Planned system architecture

```
                  React Analyst Dashboard (M11)
                           │
                           ▼
                  FastAPI Backend (M9)
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
     ML Inference    PostgreSQL (M10)  File Analysis (M8)
             │
       ┌─────┼─────┐
       ▼     ▼     ▼
   Malware Anomaly Family
    Model    Model   Model
       │     │       │
       └─────┼───────┘
             ▼
       SHAP / XAI (M6)
             │
             ▼
      Risk Engine (M7)
             │
             ▼
      Threat Assessment
```

Optional layer: **Threat Intelligence Graph** (M14, NetworkX).

The platform performs **static analysis only**. Uploaded files are never
executed, at any stage.

## Technology stack

| Layer | Tools |
|---|---|
| ML | Python, NumPy, Pandas, scikit-learn, XGBoost, SHAP, NetworkX |
| Backend | FastAPI, SQLAlchemy, Pydantic |
| Database | PostgreSQL |
| Frontend | React, Vite, Tailwind CSS v4, Recharts |
| Testing | pytest |
| MLOps | File-based model registry (git + sha256 provenance) |

Every tool here has a specific, stated reason — nothing was added for
buzzword coverage.

## Security principles

- Never executes uploaded or downloaded files, at any stage
- Never requires disabling antivirus or Windows security features
- Treats every uploaded file as untrusted input: validated, size-limited,
  randomized-temp-filename, protected against path traversal
- Automatic temp-file cleanup after analysis, including on error — verified
  by an automated test (M12)
- No arbitrary command execution based on file contents or user input
- Real credentials (`DATABASE_URL`) never committed — `.env` is gitignored,
  `.env.example` is the committed template
- Dynamic analysis is out of scope; if pursued later, must run inside a
  properly isolated, disposable sandbox/VM — never on the host machine

---

## Responsible use

This project is for defensive security research. Results are probabilistic,
not certain. It is not a replacement for professional malware analysis and
should not be the sole basis for a security decision. Model predictions can
include false positives, false negatives, dataset bias, and generalization
error — see **Known limitations** above for the specific, named ones found
during this project's own evaluation. Unknown samples should never be
executed on personal or production systems — this platform performs static
analysis only and never executes any uploaded or downloaded file. The
project provides no functionality for malware creation, exploitation,
persistence, evasion, credential theft, unauthorized access, or offensive
cyber operations.