"""
ML Model Implementations for CloudTwin AI Anomaly Detection

Models:
  - IsolationForestDetector  (sklearn)
  - OneClassSVMDetector      (sklearn)
  - AutoencoderDetector      (sklearn MLPRegressor as lightweight autoencoder)
  - EnsembleDetector         (hybrid voting across all three)

For production inference with Kaggle-trained UNSW-NB15 models,
use ai_engine.ml.inference.AnomalyInferenceEngine instead.
"""

import os
import json
from pathlib import Path
from typing import Optional, List, Dict

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neural_network import MLPRegressor
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
)


# Paths

_SAVED_MODELS_DIR = Path(__file__).parent.parent / "saved_models"


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path



# Base class


class BaseDetector:
    """Abstract base for anomaly detectors."""

    name: str = "base"

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = Path(model_dir) if model_dir else _SAVED_MODELS_DIR
        self.model = None
        self.is_trained = False

    #  public API 

    def train(self, X_train: np.ndarray, **kwargs) -> "BaseDetector":
        raise NotImplementedError

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Return array of 1 (normal) / -1 (anomaly)."""
        raise NotImplementedError

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Return continuous anomaly scores (lower = more anomalous)."""
        raise NotImplementedError

    def evaluate(self, X_test: np.ndarray, y_true: np.ndarray) -> Dict:
        """Evaluate detector against labelled data.
        y_true: 1 = normal, -1 = anomaly (same convention as sklearn).
        """
        y_pred = self.predict(X_test)
        # Convert labels to binary for sklearn metrics: anomaly=1, normal=0
        y_true_bin = (y_true == -1).astype(int)
        y_pred_bin = (y_pred == -1).astype(int)

        metrics = {
            "precision": float(precision_score(y_true_bin, y_pred_bin, zero_division=0)),
            "recall": float(recall_score(y_true_bin, y_pred_bin, zero_division=0)),
            "f1_score": float(f1_score(y_true_bin, y_pred_bin, zero_division=0)),
        }
        try:
            scores = self.score_samples(X_test)
            metrics["roc_auc"] = float(roc_auc_score(y_true_bin, -scores))
        except Exception:
            metrics["roc_auc"] = None

        metrics["classification_report"] = classification_report(
            y_true_bin, y_pred_bin, target_names=["Normal", "Anomaly"], output_dict=True,
            zero_division=0,
        )
        return metrics

    # persistence 

    def save(self, path: Optional[Path] = None) -> Path:
        path = path or (_ensure_dir(self.model_dir) / f"{self.name}_model.joblib")
        joblib.dump(self.model, path)
        return path

    def load(self, path: Optional[Path] = None) -> "BaseDetector":
        path = path or (self.model_dir / f"{self.name}_model.joblib")
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        self.model = joblib.load(path)
        self.is_trained = True
        return self

    def model_path(self) -> Path:
        return self.model_dir / f"{self.name}_model.joblib"

    def model_exists(self) -> bool:
        return self.model_path().exists()


# Isolation Forest


class IsolationForestDetector(BaseDetector):
    """Anomaly detection via Isolation Forest."""

    name = "isolation_forest"

    def __init__(self, contamination: float = 0.1, n_estimators: int = 200,
                 random_state: int = 42, **kwargs):
        super().__init__(**kwargs)
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

    def train(self, X_train: np.ndarray, **kwargs) -> "IsolationForestDetector":
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_train)
        self.is_trained = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.model.score_samples(X)



# One-Class SVM


class OneClassSVMDetector(BaseDetector):
    """Anomaly detection via One-Class SVM with RBF kernel."""

    name = "one_class_svm"

    def __init__(self, kernel: str = "rbf", gamma: str = "scale",
                 nu: float = 0.1, **kwargs):
        super().__init__(**kwargs)
        self.kernel = kernel
        self.gamma = gamma
        self.nu = nu

    def train(self, X_train: np.ndarray, **kwargs) -> "OneClassSVMDetector":
        self.model = OneClassSVM(
            kernel=self.kernel,
            gamma=self.gamma,
            nu=self.nu,
        )
        self.model.fit(X_train)
        self.is_trained = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return self.model.score_samples(X)



# Autoencoder 


class AutoencoderDetector(BaseDetector):
    """
    Autoencoder-style anomaly detector using sklearn MLPRegressor.

    The MLP is trained to reconstruct its own input (identity mapping via a
    bottleneck).  High reconstruction error signals an anomaly.
    """

    name = "autoencoder"

    def __init__(self, hidden_layers: tuple = (64, 32, 16, 32, 64),
                 max_iter: int = 500, threshold_percentile: float = 95.0,
                 random_state: int = 42, **kwargs):
        super().__init__(**kwargs)
        self.hidden_layers = hidden_layers
        self.max_iter = max_iter
        self.threshold_percentile = threshold_percentile
        self.random_state = random_state
        self.threshold_: Optional[float] = None

    def train(self, X_train: np.ndarray, **kwargs) -> "AutoencoderDetector":
        self.model = MLPRegressor(
            hidden_layer_sizes=self.hidden_layers,
            activation="relu",
            solver="adam",
            max_iter=self.max_iter,
            random_state=self.random_state,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=20,
        )
        # Train to reconstruct input
        self.model.fit(X_train, X_train)

        # Compute reconstruction error threshold from training data
        recon = self.model.predict(X_train)
        errors = np.mean((X_train - recon) ** 2, axis=1)
        self.threshold_ = float(np.percentile(errors, self.threshold_percentile))
        self.is_trained = True
        return self

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        recon = self.model.predict(X)
        return np.mean((X - recon) ** 2, axis=1)

    def predict(self, X: np.ndarray) -> np.ndarray:
        errors = self._reconstruction_errors(X)
        predictions = np.where(errors > self.threshold_, -1, 1)
        return predictions

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        # Return negative error so lower = more anomalous (consistent convention)
        return -self._reconstruction_errors(X)

    def save(self, path: Optional[Path] = None) -> Path:
        path = path or (_ensure_dir(self.model_dir) / f"{self.name}_model.joblib")
        joblib.dump({"model": self.model, "threshold": self.threshold_}, path)
        return path

    def load(self, path: Optional[Path] = None) -> "AutoencoderDetector":
        path = path or (self.model_dir / f"{self.name}_model.joblib")
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        data = joblib.load(path)
        self.model = data["model"]
        self.threshold_ = data["threshold"]
        self.is_trained = True
        return self



# Ensemble Detector


class EnsembleDetector:
    """
    Hybrid anomaly detector combining Isolation Forest, One-Class SVM,
    and Autoencoder via majority voting.
    """

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = Path(model_dir) if model_dir else _SAVED_MODELS_DIR
        self.detectors: List[BaseDetector] = [
            IsolationForestDetector(model_dir=self.model_dir),
            OneClassSVMDetector(model_dir=self.model_dir),
            AutoencoderDetector(model_dir=self.model_dir),
        ]
        self.anomaly_scores: Optional[np.ndarray] = None

    def train(self, X_train: np.ndarray, **kwargs) -> "EnsembleDetector":
        for det in self.detectors:
            print(f"  Training {det.name}...")
            det.train(X_train, **kwargs)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Majority-vote prediction across all models."""
        votes = np.zeros((X.shape[0], len(self.detectors)), dtype=int)
        scores = np.zeros((X.shape[0], len(self.detectors)), dtype=float)

        for i, det in enumerate(self.detectors):
            votes[:, i] = det.predict(X)
            try:
                scores[:, i] = det.score_samples(X)
            except Exception:
                pass

        # Majority vote: anomaly if >= 2 of 3 say anomaly
        anomaly_votes = np.sum(votes == -1, axis=1)
        predictions = np.where(anomaly_votes >= 2, -1, 1)

        # Store average anomaly scores for API response
        self.anomaly_scores = np.mean(scores, axis=1)

        return predictions

    def evaluate(self, X_test: np.ndarray, y_true: np.ndarray) -> Dict:
        """Evaluate ensemble and each individual model."""
        results = {"ensemble": {}, "individual": {}}

        # Ensemble evaluation
        y_pred = self.predict(X_test)
        y_true_bin = (y_true == -1).astype(int)
        y_pred_bin = (y_pred == -1).astype(int)

        results["ensemble"] = {
            "precision": float(precision_score(y_true_bin, y_pred_bin, zero_division=0)),
            "recall": float(recall_score(y_true_bin, y_pred_bin, zero_division=0)),
            "f1_score": float(f1_score(y_true_bin, y_pred_bin, zero_division=0)),
        }
        try:
            results["ensemble"]["roc_auc"] = float(
                roc_auc_score(y_true_bin, -self.anomaly_scores)
            )
        except Exception:
            results["ensemble"]["roc_auc"] = None

        # Individual evaluations
        for det in self.detectors:
            results["individual"][det.name] = det.evaluate(X_test, y_true)

        return results

    def save(self) -> None:
        _ensure_dir(self.model_dir)
        for det in self.detectors:
            det.save()

    def load(self) -> "EnsembleDetector":
        for det in self.detectors:
            det.load()
        return self

    def models_exist(self) -> bool:
        return all(det.model_exists() for det in self.detectors)
