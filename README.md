# ThreatLens — AI-Powered Malware Intelligence & Threat Analysis Platform

> **Status:** Milestone 1 (Dataset Understanding) — Complete
> Milestone 2 (Data Pipeline: dedup + leakage check) — Complete
> Milestone 3 (Detection Model: LR/RF/XGBoost comparison) — Complete
> Next up: Milestone 4 — Anomaly Detection Model

An explainable machine-learning platform for static malware detection, anomaly
analysis, and analyst-facing threat scoring, built on the EMBER2024 dataset
with a FastAPI + React analyst dashboard (in progress).

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
└── ml-training/
    ├── data/                    <- downloaded/vectorized EMBER2024 files (gitignored)
    ├── reports/                 <- generated M1/M2 reports (gitignored)
    └── src/
        ├── download_data.py     <- guarded CLI wrapper around thrember's downloader
        ├── inspect_dataset.py   <- M1: dataset-understanding report generator
        └── dedupe.py            <- M2: exact-duplicate removal + before/after report
```

`ml-training/data/` and `ml-training/reports/` are gitignored on purpose — the
dataset is multi-GB and the reports/vectorized `.dat` files are fully
regenerable from the scripts, so neither belongs in version control.

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

**Known compatibility fix required:** the latest `signify` release (0.9.2+)
reorganized its internals and no longer re-exports `SignedPEFile` from
`signify.authenticode` directly, which breaks `thrember`'s import. Fix:

1. Pin `signify==0.9.1` (already listed in `requirements.txt`).
2. If the import still fails, edit
   `.venv\Lib\site-packages\thrember\features.py`, line ~28 — change
   `from signify.authenticode import SignedPEFile` to
   `from signify.authenticode.signed_file import SignedPEFile`.

Verify with: `python -c "import thrember; print('thrember OK')"`

---

## Milestone 1 — Dataset Understanding

### Download a slice of EMBER2024

```powershell
python ml-training\src\download_data.py --file-type PE --split challenge
python ml-training\src\download_data.py --file-type Dot_Net --split test
python ml-training\src\download_data.py --file-type Dot_Net --split train
```

`--file-type` accepts: `Win32`, `Win64`, `Dot_Net`, `APK`, `PDF`, `ELF`, or the
combined `PE` group. `--split` accepts `train`, `test`, or `challenge`. Sizes
range from ~24 MB (ELF test) to ~24 GB (Win32 train) — the script prints the
estimated size and asks for confirmation before downloading.

We're building and validating the full pipeline on the smallest relevant file
family (`.NET`) first, before scaling up to `Win32`/`Win64` for the final
trained models — same feature extractor and pipeline, far less data to move
while everything is still being debugged.

### Run the dataset report

```powershell
python ml-training\src\inspect_dataset.py --data-dir ml-training\data --split challenge
python ml-training\src\inspect_dataset.py --data-dir ml-training\data --split test
python ml-training\src\inspect_dataset.py --data-dir ml-training\data --split train
```

Each split gets its own report at `ml-training/reports/m1_dataset_report_<split>.md`,
plus a per-feature stats CSV. The report covers: sample/feature counts, class
distribution, missing/infinite values, exact-duplicate feature vectors, and
per-feature statistics.

### M1 findings

| Split | Rows | Features | Class balance | Missing/invalid | Exact duplicates |
|---|---|---|---|---|---|
| challenge (PE) | 6,315 | 2,568 | 100% malicious (expected — evasive-sample set) | none | 0% |
| .NET test | 120,000 | 2,568 | 50% / 50% | none | ~50.04% (evenly split across both classes) |
| .NET train | 520,000 | 2,568 | — | none | exactly 50.0% |

All sample counts and feature dimensionality match EMBER2024's published
documentation exactly.

---

## Milestone 2 — Data Pipeline (Dedup + Leakage Check)

The near-exactly-50% within-split duplication found in M1 (on both `.NET`
train and test) is too clean to be incidental — it strongly suggests each
underlying sample was captured twice, most likely from the same file being
resubmitted to VirusTotal in more than one of the weeks that make up a split.
Training or evaluating on this as-is risks inflated, misleading metrics.

### Deduplicate a split

```powershell
python ml-training\src\dedupe.py --data-dir ml-training\data --split test
python ml-training\src\dedupe.py --data-dir ml-training\data --split train
```

Keeps the first occurrence of each exact feature vector, drops the rest, and
writes `X_<split>_dedup.dat` / `y_<split>_dedup.dat`.

### M2 findings

| Check | Result |
|---|---|
| .NET test, before → after dedup | 120,000 → 59,953 rows (50.04% removed) |
| .NET train, before → after dedup | 520,000 → 260,000 rows (exactly 50.0% removed) |
| Post-dedup test class balance | 29,953 benign / 30,000 malicious |
| **Train ↔ test exact overlap (post-dedup)** | **0 rows — 0.0% of test** |

**Conclusion:** within-split duplication is real and must be corrected before
training or evaluation, but EMBER2024's official temporal train/test boundary
itself holds — there is no exact-match leakage between train and test once
each side is deduplicated internally. This validates using the official split
as the primary evaluation protocol, with deduplication as a mandatory
preprocessing step.

*(This checks exact-match duplication only. Near-duplicate, family-aware, and
temporal-boundary leakage are still open, deeper questions for later, once the
modeling milestones are underway.)*

---

## Roadmap

- [x] M1 — Dataset Understanding
- [x] M2 — Data Pipeline (dedup + leakage check)
- [x] M3 — Malware Detection Model (Logistic Regression / Random Forest / XGBoost)
- [ ] M4 — Anomaly Detection Model (Isolation Forest / Autoencoder)
- [ ] M5 — Malware Family Classifier
- [ ] M6 — Explainability (SHAP)
- [ ] M7 — Risk Engine
- [ ] M8 — Safe Static File Analyzer
- [ ] M9 — FastAPI Service
- [ ] M10 — PostgreSQL Integration
- [ ] M11 — React Dashboard
- [ ] M12 — Testing
- [ ] M13 — MLOps
- [ ] M14 — Threat Intelligence Graph (optional)

---

## Milestone 3 — Malware Detection Model

Trained and compared three candidates on the deduplicated `.NET` train/test
split (260,000 train rows / 59,953 test rows), evaluated with precision,
recall, F1, ROC-AUC, PR-AUC, confusion matrix, and false positive/negative
rate — never bare accuracy.

| Model | PR-AUC | ROC-AUC | F1 | FPR | FNR |
|---|---|---|---|---|---|
| **XGBoost (selected)** | **0.9978** | **0.9977** | **0.9778** | 2.75% | 1.71% |
| Random Forest | 0.9949 | 0.9952 | 0.9685 | 3.90% | 2.44% |
| Logistic Regression | 0.9852 | 0.9865 | 0.9503 | 5.81% | 4.21% |

**Selected model: XGBoost**, chosen on PR-AUC. Its false-negative rate
(1.71%) is the lowest of the three — the more operationally important of the
two error rates for malware detection, since a missed detection is typically
costlier than a false alarm.

**Scope caveat:** these results are from the `.NET` file family only, used
deliberately as the smallest relevant slice to build and debug the full
pipeline quickly. They are not assumed to transfer directly to `Win32`/`Win64`
— those are larger, more diverse, and the actual target for the final
deployed model. Re-running this same script against `Win32`/`Win64` data is
planned once the rest of the pipeline (M4–M7) is in place.

Run it yourself: `python ml-training\src\train_detector.py --data-dir ml-training\data`
Full report: `ml-training/reports/m3_model_comparison.md`

## Core ML components (planned)

**1. Malware Detection Model** — classifies a sample as benign or malicious.
Candidate algorithms: Logistic Regression, Random Forest, XGBoost. The final
deployed model will be chosen based on actual validation results, not assumed.

**2. Anomaly Detection Model** — flags samples whose characteristics are
significantly different from the learned data distribution. Candidate
approaches: Isolation Forest, One-Class SVM, Autoencoder. This is a proxy for
"worth a closer look," not a claim of zero-day detection.

**3. Malware Family Classifier** — if family labels are usable at sufficient
volume (EMBER2024's ClarAVy-assigned family tags), classifies malicious
samples into the families the dataset actually supports — never invented
categories.

### Explainable AI

Predictions won't just be a bare probability. SHAP will attribute each
prediction to the specific features that drove it, e.g.:

```
Malicious: 94%
Top contributing features:
  1. Feature A
  2. Feature B
  3. Feature C
```

---

## Planned system architecture

```
                  React Analyst Dashboard
                           │
                           ▼
                     FastAPI Backend
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
        ML Inference   PostgreSQL    File Analysis
             │
       ┌─────┼─────┐
       ▼     ▼     ▼
   Malware Anomaly Family
    Model    Model   Model
       │     │       │
       └─────┼───────┘
             ▼
          SHAP / XAI
             │
             ▼
        Risk Engine
             │
             ▼
      Threat Assessment
```

The platform performs **static analysis only**. Uploaded files are never
executed, at any stage.

## Planned technology stack

| Layer | Tools |
|---|---|
| ML | Python, NumPy, Pandas, scikit-learn, XGBoost, SHAP |
| Backend | FastAPI, Pydantic |
| Database | PostgreSQL |
| Frontend | React, Vite, Tailwind CSS |
| MLOps (where justified) | MLflow, DVC, Docker |

Additional tools/libraries are only introduced when there's a clear technical
reason — not for buzzword coverage.

## Security principles

- Never executes uploaded or downloaded files, at any stage
- Never requires disabling antivirus or Windows security features
- Treats every uploaded file as untrusted input: validated, size-limited,
  filename-sanitized, protected against path traversal
- Uses temporary storage with automatic cleanup after analysis
- No arbitrary command execution based on file contents or user input
- Dynamic analysis is out of scope for the initial system; if pursued later,
  it must run inside a properly isolated, disposable sandbox/VM — never on
  the host machine

---

## Responsible use

This project is for defensive security research. Results are probabilistic,
not certain. It is not a replacement for professional malware analysis and
should not be the sole basis for a security decision. Model predictions can
include false positives, false negatives, dataset bias, and generalization
error. Unknown samples should never be executed on personal or production
systems — this platform performs static analysis only and never executes any
uploaded or downloaded file. The project provides no functionality for
malware creation, exploitation, persistence, evasion, credential theft,
unauthorized access, or offensive cyber operations.