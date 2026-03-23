"""
Production Inference Engine for CloudTwin AI

Loads the pre-trained models (from the Kaggle UNSW-NB15 training notebook)
and runs anomaly detection on new network traffic data.

Expected saved artifacts (in ai_engine/saved_models/):
  - isolation_forest.joblib
  - one_class_svm.joblib
  - autoencoder.keras
  - autoencoder_threshold.json
  - scaler.joblib
  - feature_names.json
"""

import json
import csv
import io
from pathlib import Path
from typing import List, Dict, Optional, Tuple

import numpy as np
import joblib

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SAVED_MODELS_DIR = Path(__file__).parent.parent / "saved_models"

# ---------------------------------------------------------------------------
# UNSW-NB15 feature columns (must match training notebook)
# ---------------------------------------------------------------------------
NUMERIC_FEATURES = [
    "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
    "sload", "dload", "spkts", "dpkts", "sinpkt", "dinpkt",
    "sjit", "djit", "tcprtt", "ct_srv_src", "ct_dst_ltm",
]

CATEGORICAL_FEATURES = {
    "proto": ["icmp", "tcp", "udp"],
    "service": ["-", "dns", "ftp", "http", "https", "ssh"],
    "state": ["CON", "FIN", "INT", "REQ", "RST"],
}


class AnomalyInferenceEngine:
    """
    Production inference engine that mirrors the Kaggle notebook's pipeline.

    Usage:
        engine = AnomalyInferenceEngine()
        engine.load_models()
        results = engine.predict_from_csv(csv_text)
    """

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = Path(model_dir) if model_dir else SAVED_MODELS_DIR
        self.if_model = None
        self.svm_model = None
        self.ae_model = None
        self.ae_threshold = None
        self.scaler = None
        self.feature_names = None
        self._loaded = False

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def load_models(self) -> "AnomalyInferenceEngine":
        """Load all saved model artifacts."""
        model_dir = self.model_dir

        # Isolation Forest
        if_path = model_dir / "isolation_forest.joblib"
        if not if_path.exists():
            raise FileNotFoundError(f"Isolation Forest model not found: {if_path}")
        self.if_model = joblib.load(if_path)

        # One-Class SVM
        svm_path = model_dir / "one_class_svm.joblib"
        if not svm_path.exists():
            raise FileNotFoundError(f"One-Class SVM model not found: {svm_path}")
        self.svm_model = joblib.load(svm_path)

        # Autoencoder (Keras)
        ae_path = model_dir / "autoencoder.keras"
        if not ae_path.exists():
            raise FileNotFoundError(f"Autoencoder model not found: {ae_path}")
        import tensorflow as tf
        tf.get_logger().setLevel("ERROR")
        self.ae_model = tf.keras.models.load_model(str(ae_path))

        # Autoencoder threshold
        threshold_path = model_dir / "autoencoder_threshold.json"
        if not threshold_path.exists():
            raise FileNotFoundError(f"Autoencoder threshold not found: {threshold_path}")
        with open(threshold_path) as f:
            self.ae_threshold = json.load(f)["threshold"]

        # Scaler
        scaler_path = model_dir / "scaler.joblib"
        if not scaler_path.exists():
            raise FileNotFoundError(f"Scaler not found: {scaler_path}")
        self.scaler = joblib.load(scaler_path)

        # Feature names
        fn_path = model_dir / "feature_names.json"
        if not fn_path.exists():
            raise FileNotFoundError(f"Feature names not found: {fn_path}")
        with open(fn_path) as f:
            self.feature_names = json.load(f)

        self._loaded = True
        return self

    def is_loaded(self) -> bool:
        return self._loaded

    def models_exist(self) -> bool:
        """Check if all required model files exist on disk."""
        required = [
            "isolation_forest.joblib",
            "one_class_svm.joblib",
            "autoencoder.keras",
            "autoencoder_threshold.json",
            "scaler.joblib",
            "feature_names.json",
        ]
        return all((self.model_dir / f).exists() for f in required)

    # ------------------------------------------------------------------
    # Preprocessing (mirrors notebook's preprocess() function)
    # ------------------------------------------------------------------

    def preprocess(self, df) -> np.ndarray:
        """
        Preprocess a DataFrame to match the training pipeline exactly.

        Steps (matching notebook):
          1. Fill missing numeric with median, categorical with mode
          2. One-hot encode proto, service, state
          3. Replace inf with 0
          4. Drop label/attack_cat/id columns
          5. Scale with the saved StandardScaler
          6. Align columns to match training feature order
        """
        import pandas as pd

        df = df.copy()

        # 1. Handle missing values
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
        cat_cols = df.select_dtypes(include=["object"]).columns
        for col in cat_cols:
            if col not in ["label", "attack_cat"]:
                mode = df[col].mode()
                df[col] = df[col].fillna(mode[0] if not mode.empty else "unknown")

        # 2. One-hot encode
        encode_cols = [c for c in ["proto", "service", "state"] if c in df.columns]
        if encode_cols:
            df = pd.get_dummies(df, columns=encode_cols, drop_first=False)

        # 3. Replace inf
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # 4. Drop non-feature columns
        drop_cols = [c for c in ["label", "attack_cat", "id"] if c in df.columns]
        if drop_cols:
            df = df.drop(columns=drop_cols)

        # 5. Align columns to training feature order
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0  # missing one-hot columns get 0
        df = df[self.feature_names]

        X = df.values.astype(np.float64)

        # 6. Scale
        X = self.scaler.transform(X)

        return X

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, X: np.ndarray) -> Dict:
        """
        Run ensemble prediction on preprocessed feature matrix.

        Returns dict with per-sample results and aggregate stats.
        """
        if not self._loaded:
            raise RuntimeError("Models not loaded. Call load_models() first.")

        n = X.shape[0]

        # Isolation Forest: -1 = anomaly, 1 = normal
        if_pred = self.if_model.predict(X)
        if_anomaly = (if_pred == -1).astype(int)

        # One-Class SVM: -1 = anomaly, 1 = normal
        svm_pred = self.svm_model.predict(X)
        svm_anomaly = (svm_pred == -1).astype(int)

        # Autoencoder: reconstruction error > threshold = anomaly
        ae_recon = self.ae_model.predict(X, verbose=0)
        ae_errors = np.mean(np.square(X - ae_recon), axis=1)
        ae_anomaly = (ae_errors > self.ae_threshold).astype(int)

        # Ensemble: majority vote (>= 2 of 3)
        votes = np.stack([if_anomaly, svm_anomaly, ae_anomaly], axis=1)
        ensemble_anomaly = (np.sum(votes, axis=1) >= 2).astype(int)

        # Anomaly scores (for ranking)
        if_scores = -self.if_model.decision_function(X)  # higher = more anomalous
        svm_scores = -self.svm_model.decision_function(X)
        ae_scores = ae_errors

        # Normalize scores to [0, 1] for each model
        def normalize(s):
            s_min, s_max = s.min(), s.max()
            if s_max - s_min == 0:
                return np.zeros_like(s)
            return (s - s_min) / (s_max - s_min)

        combined_score = (normalize(if_scores) + normalize(svm_scores) + normalize(ae_scores)) / 3

        # Risk levels based on combined score
        risk_levels = []
        for score in combined_score:
            if score > 0.8:
                risk_levels.append("Critical")
            elif score > 0.6:
                risk_levels.append("High")
            elif score > 0.4:
                risk_levels.append("Medium")
            else:
                risk_levels.append("Low")

        anomaly_count = int(ensemble_anomaly.sum())

        return {
            "ensemble_predictions": ensemble_anomaly,
            "individual_predictions": {
                "isolation_forest": if_anomaly,
                "one_class_svm": svm_anomaly,
                "autoencoder": ae_anomaly,
            },
            "anomaly_scores": combined_score,
            "risk_levels": risk_levels,
            "model_agreement": votes,
            "total_samples": n,
            "anomaly_count": anomaly_count,
            "anomaly_percentage": round(anomaly_count / n * 100, 2) if n > 0 else 0,
        }

    # ------------------------------------------------------------------
    # High-level API (CSV in, results out)
    # ------------------------------------------------------------------

    def predict_from_csv(self, csv_text: str) -> Dict:
        """
        End-to-end prediction from raw CSV text.

        Args:
            csv_text: CSV content as string (with header row)

        Returns:
            Dict with predictions, scores, anomalous entries, and stats.
        """
        import pandas as pd

        df = pd.read_csv(io.StringIO(csv_text))
        if df.empty:
            raise ValueError("Empty CSV data")

        # Keep original data for response
        original_records = df.to_dict(orient="records")

        # Has labels? (for evaluation mode)
        has_labels = "label" in df.columns
        true_labels = df["label"].values.astype(int) if has_labels else None
        attack_cats = df["attack_cat"].values if "attack_cat" in df.columns else None

        # Preprocess and predict
        X = self.preprocess(df)
        results = self.predict(X)

        # Build anomalous entries list
        anomalous_entries = []
        for i in range(len(original_records)):
            if results["ensemble_predictions"][i] == 1:
                entry = {
                    "index": i,
                    "risk_level": results["risk_levels"][i],
                    "anomaly_score": round(float(results["anomaly_scores"][i]), 4),
                    "model_agreement": {
                        "isolation_forest": bool(results["individual_predictions"]["isolation_forest"][i]),
                        "one_class_svm": bool(results["individual_predictions"]["one_class_svm"][i]),
                        "autoencoder": bool(results["individual_predictions"]["autoencoder"][i]),
                    },
                    "log_entry": original_records[i],
                }
                if attack_cats is not None:
                    entry["attack_category"] = str(attack_cats[i])
                anomalous_entries.append(entry)

        # Sort by score descending
        anomalous_entries.sort(key=lambda x: x["anomaly_score"], reverse=True)

        response = {
            "status": "completed",
            "total_logs": results["total_samples"],
            "anomalies_detected": results["anomaly_count"],
            "anomaly_percentage": results["anomaly_percentage"],
            "risk_level": (
                "Critical" if results["anomaly_percentage"] > 20
                else "High" if results["anomaly_percentage"] > 10
                else "Medium" if results["anomaly_count"] > 0
                else "Normal"
            ),
            "models_used": ["Isolation Forest", "One-Class SVM", "Autoencoder (Keras)"],
            "anomalous_entries": anomalous_entries[:100],  # Top 100
        }

        # If labels available, add evaluation metrics
        if has_labels:
            from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
            ensemble_pred = results["ensemble_predictions"]
            response["evaluation"] = {
                "precision": round(float(precision_score(true_labels, ensemble_pred, zero_division=0)), 4),
                "recall": round(float(recall_score(true_labels, ensemble_pred, zero_division=0)), 4),
                "f1_score": round(float(f1_score(true_labels, ensemble_pred, zero_division=0)), 4),
            }
            try:
                response["evaluation"]["roc_auc"] = round(
                    float(roc_auc_score(true_labels, results["anomaly_scores"])), 4
                )
            except Exception:
                pass

        return response


# ---------------------------------------------------------------------------
# Module-level singleton for the API layer
# ---------------------------------------------------------------------------
_engine: Optional[AnomalyInferenceEngine] = None


def get_engine(model_dir: Optional[Path] = None) -> AnomalyInferenceEngine:
    """Get or create the singleton inference engine."""
    global _engine
    if _engine is None or not _engine.is_loaded():
        _engine = AnomalyInferenceEngine(model_dir=model_dir)
        _engine.load_models()
    return _engine
