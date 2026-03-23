"""
Training Pipeline for CloudTwin AI Anomaly Detection

Usage:
    python -m ai_engine.ml.trainer

Workflow:
    1. Load CSV data from ai_engine/data-sets/
    2. Preprocess and engineer features
    3. Train Isolation Forest, One-Class SVM, and Autoencoder
    4. Evaluate with Precision, Recall, F1-score, ROC-AUC
    5. Save trained models to ai_engine/saved_models/
    6. Generate evaluation report (JSON)
"""

import json
import sys
import time
from pathlib import Path
from typing import List, Dict, Optional

import numpy as np

# Ensure project root is on path
_PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from ai_engine.ml.preprocessor import (
    CloudLogPreprocessor,
    load_dataset,
    load_csv,
    split_data,
    FEATURE_NAMES,
)
from ai_engine.ml.models import (
    IsolationForestDetector,
    OneClassSVMDetector,
    AutoencoderDetector,
    EnsembleDetector,
    _ensure_dir,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DATA_DIR = Path(__file__).parent.parent / "data-sets"
SAVED_MODELS_DIR = Path(__file__).parent.parent / "saved_models"
EVAL_REPORT_PATH = SAVED_MODELS_DIR / "evaluation_report.json"


# ---------------------------------------------------------------------------
# Synthetic data generator (fallback when no real data available)
# ---------------------------------------------------------------------------

def generate_synthetic_data(n_normal: int = 2000, n_anomaly: int = 200,
                            n_features: int = 10, seed: int = 42) -> tuple:
    """
    Generate synthetic cloud log data for training when no CSV data is available.
    Returns (X, y) where y: 1=normal, -1=anomaly.
    """
    rng = np.random.RandomState(seed)

    # Normal traffic: clustered around origin with moderate variance
    X_normal = rng.randn(n_normal, n_features) * 0.5

    # Anomalous traffic: scattered, higher variance, shifted
    X_anomaly = rng.randn(n_anomaly, n_features) * 2.0 + rng.choice([-3, 3], size=(n_anomaly, n_features))

    X = np.vstack([X_normal, X_anomaly])
    y = np.array([1] * n_normal + [-1] * n_anomaly)

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ---------------------------------------------------------------------------
# Training pipeline
# ---------------------------------------------------------------------------

def run_training_pipeline(data_dir: Optional[Path] = None,
                          model_dir: Optional[Path] = None,
                          use_synthetic_if_empty: bool = True) -> Dict:
    """
    Full training pipeline.

    Returns evaluation report dict.
    """
    data_dir = data_dir or DATA_DIR
    model_dir = model_dir or SAVED_MODELS_DIR
    _ensure_dir(model_dir)

    report: Dict = {
        "training_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "data_source": None,
        "total_samples": 0,
        "feature_names": list(FEATURE_NAMES),
        "split": {"train": 0.70, "val": 0.15, "test": 0.15},
        "models": {},
        "ensemble": {},
    }

    # ------------------------------------------------------------------
    # 1. Load data
    # ------------------------------------------------------------------
    print("=" * 60)
    print("CloudTwin AI - Anomaly Detection Training Pipeline")
    print("=" * 60)

    logs = load_dataset(data_dir)

    if logs:
        print(f"\n[1/5] Loaded {len(logs)} log entries from {data_dir}")
        report["data_source"] = str(data_dir)

        # Preprocess
        preprocessor = CloudLogPreprocessor()
        X, feature_names = preprocessor.fit_transform(logs)

        # If we have a label column, extract it; otherwise treat all as normal
        y = np.ones(X.shape[0])
        for log in logs:
            label = log.get("label") or log.get("is_anomaly") or log.get("anomaly")
            if label is not None:
                break
        else:
            label = None

        if label is not None:
            y = np.array([
                -1 if str(l.get("label", l.get("is_anomaly", l.get("anomaly", "0")))).lower()
                in ("1", "true", "yes", "anomaly", "-1") else 1
                for l in logs
            ])

        # Save preprocessor params
        import joblib
        joblib.dump(preprocessor, model_dir / "preprocessor.joblib")

    elif use_synthetic_if_empty:
        print(f"\n[1/5] No CSV data found in {data_dir}. Using synthetic data.")
        report["data_source"] = "synthetic"
        X, y = generate_synthetic_data()
    else:
        raise FileNotFoundError(f"No CSV data found in {data_dir}")

    report["total_samples"] = int(X.shape[0])
    print(f"      Features: {X.shape[1]}, Samples: {X.shape[0]}")
    print(f"      Normal: {int(np.sum(y == 1))}, Anomaly: {int(np.sum(y == -1))}")

    # ------------------------------------------------------------------
    # 2. Split data
    # ------------------------------------------------------------------
    print(f"\n[2/5] Splitting data (70/15/15)...")
    splits = split_data(X, y)
    X_train, X_val, X_test = splits["X_train"], splits["X_val"], splits["X_test"]
    y_train, y_val, y_test = splits["y_train"], splits["y_val"], splits["y_test"]

    print(f"      Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Test: {X_test.shape[0]}")

    # For unsupervised training, use only normal samples
    normal_mask = y_train == 1
    X_train_normal = X_train[normal_mask]
    print(f"      Training on {X_train_normal.shape[0]} normal samples (unsupervised)")

    # ------------------------------------------------------------------
    # 3. Train models
    # ------------------------------------------------------------------
    print(f"\n[3/5] Training models...")

    ensemble = EnsembleDetector(model_dir=model_dir)

    t0 = time.time()
    ensemble.train(X_train_normal)
    train_time = time.time() - t0
    print(f"      Training completed in {train_time:.2f}s")

    # ------------------------------------------------------------------
    # 4. Evaluate
    # ------------------------------------------------------------------
    print(f"\n[4/5] Evaluating models...")
    evaluation = ensemble.evaluate(X_test, y_test)

    report["models"] = {}
    for name, metrics in evaluation["individual"].items():
        report["models"][name] = {
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1_score": metrics["f1_score"],
            "roc_auc": metrics["roc_auc"],
        }
        print(f"\n      {name}:")
        print(f"        Precision: {metrics['precision']:.4f}")
        print(f"        Recall:    {metrics['recall']:.4f}")
        print(f"        F1-Score:  {metrics['f1_score']:.4f}")
        print(f"        ROC-AUC:   {metrics['roc_auc']:.4f}" if metrics['roc_auc'] else "        ROC-AUC:   N/A")

    report["ensemble"] = {
        "precision": evaluation["ensemble"]["precision"],
        "recall": evaluation["ensemble"]["recall"],
        "f1_score": evaluation["ensemble"]["f1_score"],
        "roc_auc": evaluation["ensemble"].get("roc_auc"),
    }
    print(f"\n      Ensemble (majority vote):")
    print(f"        Precision: {evaluation['ensemble']['precision']:.4f}")
    print(f"        Recall:    {evaluation['ensemble']['recall']:.4f}")
    print(f"        F1-Score:  {evaluation['ensemble']['f1_score']:.4f}")
    if evaluation["ensemble"].get("roc_auc"):
        print(f"        ROC-AUC:   {evaluation['ensemble']['roc_auc']:.4f}")

    report["training_time_seconds"] = round(train_time, 2)

    # ------------------------------------------------------------------
    # 5. Save models and report
    # ------------------------------------------------------------------
    print(f"\n[5/5] Saving models to {model_dir}...")
    ensemble.save()

    with open(EVAL_REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)
    print(f"      Evaluation report saved to {EVAL_REPORT_PATH}")

    print("\n" + "=" * 60)
    print("Training pipeline completed successfully!")
    print("=" * 60)

    return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_training_pipeline()
