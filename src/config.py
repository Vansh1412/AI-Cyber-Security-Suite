"""
src/config.py
─────────────
Centralised, cross-platform path configuration.

No hardcoded Windows paths — every constant is derived from the location
of this file so the project works identically on Windows, macOS, and Linux.
"""

from pathlib import Path

# ── Root ──────────────────────────────────────────────────────────────────────
ROOT_DIR: Path = Path(__file__).resolve().parent.parent

# ── Datasets ──────────────────────────────────────────────────────────────────
DATASET_DIR: Path = ROOT_DIR / "datasets"

RAW_DIR: Path = DATASET_DIR / "raw"
PHISHING_DIR: Path = RAW_DIR / "phishing"
LEGITIMATE_DIR: Path = RAW_DIR / "legitimate"

PROCESSED_DIR: Path = DATASET_DIR / "processed"

# ── Outputs ───────────────────────────────────────────────────────────────────
REPORT_DIR: Path = ROOT_DIR / "reports"
LOG_DIR: Path = ROOT_DIR / "logs"

# ── Auto-create output directories on import ──────────────────────────────────
REPORT_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# ── Feature Store ──────────────────────────────────────────────────────────────
FEATURE_STORE_DIR: Path = ROOT_DIR / "ml" / "feature_store"
FEATURE_STORE_DIR.mkdir(parents=True, exist_ok=True)

FEATURES_V1: Path = FEATURE_STORE_DIR / "features_v1.parquet"

# ── Multi-scale training subsets ──────────────────────────────────────────────
FEATURES_100K:  Path = FEATURE_STORE_DIR / "features_train_100k.parquet"
FEATURES_500K:  Path = FEATURE_STORE_DIR / "features_train_500k.parquet"

# ── Train / Val / Test splits ──────────────────────────────────────────────────
SPLITS_DIR: Path = FEATURE_STORE_DIR / "splits"
SPLITS_DIR.mkdir(parents=True, exist_ok=True)
TRAIN_PATH: Path = SPLITS_DIR / "train.parquet"
VAL_PATH:   Path = SPLITS_DIR / "val.parquet"
TEST_PATH:  Path = SPLITS_DIR / "test.parquet"
MANIFEST:   Path = SPLITS_DIR / "manifest.json"

# ── Model store ────────────────────────────────────────────────────────────────
MODEL_DIR: Path = ROOT_DIR / "ml" / "models" / "store"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ── Feature schema (for API inference) ────────────────────────────────────────
FEATURE_SCHEMA: Path = FEATURE_STORE_DIR / "feature_schema_v1.json"
SELECTED_FEATURES: Path = FEATURE_STORE_DIR / "selected_features.json"

# ── MLflow tracking ────────────────────────────────────────────────────────────
MLFLOW_DIR: Path = ROOT_DIR / "ml" / "experiments"
MLFLOW_DIR.mkdir(parents=True, exist_ok=True)
MLFLOW_TRACKING_URI: str = f"sqlite:///{MLFLOW_DIR.as_posix()}/mlflow.db"

# ── Configs ────────────────────────────────────────────────────────────────────
CONFIGS_DIR: Path = ROOT_DIR / "configs"
TRAINING_CONFIG: Path = CONFIGS_DIR / "training.yaml"

# ── Merged output file ────────────────────────────────────────────────────────
MERGED_DATASET: Path = PROCESSED_DIR / "merged_dataset.csv"

# ── Canonical column schema ───────────────────────────────────────────────────
# Every cleaned CSV will conform to these three columns.
SCHEMA_COLUMNS: list[str] = ["url", "label", "source"]

# ── URL column aliases ─────────────────────────────────────────────────────────
# Column names that various datasets use for the URL field.
URL_COLUMN_ALIASES: list[str] = [
    "url", "URL", "domain", "Domain", "website", "Website",
    "address", "Address", "link", "Link", "hostname", "Hostname",
]

# ── Label column aliases ───────────────────────────────────────────────────────
LABEL_COLUMN_ALIASES: list[str] = [
    "label", "Label", "type", "Type", "class", "Class",
    "status", "Status", "tag", "Tag", "result", "Result",
]
