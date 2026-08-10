# ThreatLens — AI-Powered Malware Intelligence & Threat Analysis Platform

> **Status: Milestone 1 — Dataset Understanding — Complete**

An explainable machine-learning platform for static malware detection, anomaly analysis, and analyst-facing threat scoring, built on the **EMBER2024** dataset with a **FastAPI + React** analyst dashboard (in progress).

This is strictly a **defensive** cybersecurity project: malware detection, anomaly analysis, family classification, and explainability — never malware creation, evasion, or offensive tooling.

See **Responsible Use** below.

---

## Project Structure

```text
ThreatLens/
├── README.md
├── requirements.txt
├── .gitignore
└── ml-training/
    ├── data/                    # Downloaded EMBER2024 files (gitignored)
    ├── reports/                 # Generated M1 reports (gitignored)
    └── src/
        ├── download_data.py     # Guarded CLI wrapper around thrember downloader
        └── inspect_dataset.py   # Produces M1 dataset-understanding reports
```

> **Note:** `ml-training/data/` and `ml-training/reports/` are gitignored on purpose. The dataset is multi-GB and the reports are regenerable, so neither belongs in version control. Only `.gitkeep` placeholders are tracked for those folders.

---

## Setup — Windows / PowerShell

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the basic requirements:

```powershell
pip install -r requirements.txt
```

Clone and install the EMBER2024 toolkit:

```powershell
git clone https://github.com/FutureComputing4AI/EMBER2024.git
cd EMBER2024
pip install .
cd ..
```

`thrember` (the EMBER2024 toolkit) is not currently installed through PyPI, so it is installed from source as shown above.

### Known Compatibility Fix

The latest `signify` release (0.9.2+) moved `SignedPEFile` out of `signify.authenticode`'s top-level exports, which can break `thrember` imports.

If you encounter this issue, edit:

```text
.venv\Lib\site-packages\thrember\features.py
```

Change:

```python
from signify.authenticode import SignedPEFile
```

to:

```python
from signify.authenticode.signed_file import SignedPEFile
```

---

# Milestone 1 — Dataset Understanding

## Step 1 — Download an EMBER2024 Dataset Slice

Download the smaller challenge set first:

```powershell
python ml-training\src\download_data.py --file-type PE --split challenge
```

The `.NET` test split used for the initial dataset investigation can be downloaded with:

```powershell
python ml-training\src\download_data.py --file-type Dot_Net --split test
```

`--file-type` accepts:

```text
Win32
Win64
Dot_Net
APK
PDF
ELF
PE
```

`PE` represents the combined PE group.

`--split` accepts:

```text
train
test
challenge
```

> **Warning:** Check available disk space before requesting large training splits. Some EMBER2024 splits can be very large.

---

## Step 2 — Generate the Dataset Report

For the challenge split:

```powershell
python ml-training\src\inspect_dataset.py --data-dir ml-training\data --split challenge
```

For the test split:

```powershell
python ml-training\src\inspect_dataset.py --data-dir ml-training\data --split test
```

The inspection script generates:

```text
ml-training/reports/m1_dataset_report_<split>.md
```

and a per-feature statistics CSV.

The report analyzes:

* Dataset size
* Feature count
* Class distribution
* Missing values
* Infinite values
* Exact duplicate feature vectors
* Potential train/test overlap
* Per-feature statistics

---

# M1 Findings So Far

## Challenge Set

* **6,315 samples**
* **2,568 features**
* 100% malicious
* Zero missing/invalid values
* Zero exact duplicates

The 100% malicious distribution is expected because the challenge set is designed around difficult/evasive samples.

---

## .NET Test Set

* **120,000 samples**
* **2,568 features**
* Approximately 50/50 benign and malicious
* Zero missing/invalid values

### Key Leakage Finding

Approximately **50% of rows in the .NET test set are exact feature-vector duplicates**, with duplication occurring almost evenly across the benign and malicious classes.

This indicates substantial duplication in the test data and raises an important data-quality and evaluation concern.

The exact duplicate detection is confirmed by the dataset inspection pipeline.

The current hypothesis is that repeated observations may be related to the same underlying files appearing across different VirusTotal collection periods. This hypothesis should be verified against the EMBER2024 dataset construction/documentation before drawing a definitive conclusion.

### Impact on Future ML Training

This duplication must be investigated and handled during **Milestone 2 — Data Pipeline** before model training.

Otherwise, careless splitting could allow identical or near-identical samples to appear in both training and testing data, resulting in **data leakage and artificially inflated evaluation metrics**.

---

# Roadmap

```text
M1  Dataset Understanding       ✅ Complete
 ↓
M2  Data Pipeline              Deduplication + Splitting
 ↓
M3  Malware Detection Model
 ↓
M4  Anomaly Detection Model
 ↓
M5  Malware Family Classifier
 ↓
M6  Explainability             SHAP
 ↓
M7  Risk Engine
 ↓
M8  Safe Static File Analyzer
 ↓
M9  FastAPI Service
 ↓
M10 PostgreSQL
 ↓
M11 React Analyst Dashboard
 ↓
M12 Testing
 ↓
M13 MLOps
 ↓
M14 Threat Intelligence Graph  ⭐ Optional
```

---

# Core ML Components

ThreatLens is planned around three core ML components:

### 1. Malware Detection Model

Classifies a sample as:

```text
Benign
or
Malicious
```

Candidate algorithms include:

* Logistic Regression
* Random Forest
* XGBoost

The final deployed model will be selected based on actual validation results.

### 2. Anomaly Detection Model

Identifies samples whose characteristics are significantly different from the learned data distribution.

Candidate approaches include:

* Isolation Forest
* One-Class SVM
* Autoencoder

This component is intended for anomaly detection and **must not be presented as guaranteed zero-day detection**.

### 3. Malware Family Classifier

If suitable malware-family labels are available in the dataset, the system will classify malicious samples into supported families.

The exact family categories will be determined from the actual dataset labels rather than being invented.

---

# Explainable AI

ThreatLens will use explainable AI techniques such as **SHAP** to explain model predictions.

Instead of simply reporting:

```text
Malicious: 94%
```

the system should provide information such as:

```text
Top contributing features:

1. Feature A
2. Feature B
3. Feature C
4. Feature D
```

The explanations will be based on actual model features and predictions.

---

# Planned System Architecture

```text
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
          SHAP/XAI
             │
             ▼
        Risk Engine
             │
             ▼
      Threat Assessment
```

The platform will perform **static analysis only** in its initial implementation.

Uploaded files will not be executed.

---

# Planned Technology Stack

## Machine Learning

* Python
* NumPy
* Pandas
* Scikit-learn
* XGBoost
* SHAP

Additional libraries will only be introduced when technically justified.

## Backend

* FastAPI
* Pydantic

## Database

* PostgreSQL

## Frontend

* React
* Vite
* Tailwind CSS

## MLOps

Potential tools:

* MLflow
* DVC
* Docker

These will be introduced only where they provide meaningful value.

---

# Security Principles

ThreatLens is designed as a **defensive cybersecurity research project**.

The system will:

* Never execute uploaded malware
* Never require disabling antivirus
* Never require disabling Windows security features
* Never execute unknown binaries on the host machine
* Treat uploaded files as untrusted input
* Validate uploaded files
* Enforce file-size limits
* Sanitize filenames
* Protect against path traversal
* Use temporary storage where appropriate
* Remove temporary files after analysis
* Avoid arbitrary command execution

Dynamic malware execution is **not part of the initial system**.

If dynamic analysis is investigated in the future, it must use a properly isolated and disposable sandbox/virtual machine environment.

---

# Responsible Use

This project is intended strictly for **defensive cybersecurity research and education**.

ThreatLens provides probabilistic assessments and is not a replacement for professional malware analysis.

Model predictions may contain:

* False positives
* False negatives
* Dataset bias
* Generalization errors

The system should not be used as the sole basis for real-world security decisions.

Unknown or suspicious samples should **never be executed on personal or production systems**.

The initial ThreatLens platform performs static analysis and does not execute uploaded files.

The project does not provide functionality for malware creation, exploitation, persistence, evasion, credential theft, unauthorized access, or offensive cyber operations.

---

# Current Status

**Milestone 1 — Dataset Understanding: COMPLETE ✅**

Next:

**Milestone 2 — Data Pipeline**

Focus areas:

* Duplicate investigation
* Deduplication strategy
* Data leakage analysis
* Train/validation/test splitting
* Random split
* Temporal split where applicable
* Family-aware evaluation where applicable
* Reproducible preprocessing
* Dataset validation
