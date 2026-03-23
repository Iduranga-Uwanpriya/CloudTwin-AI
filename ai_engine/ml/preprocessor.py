"""
Data Preprocessing Module for CloudTwin AI Anomaly Detection
Loads CloudTrail / VPC Flow logs, cleans, normalises, and engineers features.
"""

import csv
import io
import math
import hashlib
from collections import Counter
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Union

import numpy as np

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "api_call_frequency",
    "unique_ip_count",
    "session_entropy",
    "bytes_transferred",
    "geo_velocity",
    "error_rate",
    "request_interval_mean",
    "request_interval_std",
    "unique_user_agents",
    "privilege_escalation_score",
]

_SPLIT_TRAIN = 0.70
_SPLIT_VAL = 0.15
# test = 1 - train - val = 0.15


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _safe_float(value, default: float = 0.0) -> float:
    """Convert value to float safely."""
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _shannon_entropy(values: list) -> float:
    """Compute Shannon entropy of a list of categorical values."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _hash_to_numeric(value: str) -> float:
    """Deterministically map a string to a float in [0, 1]."""
    h = hashlib.md5(value.encode("utf-8", errors="replace")).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Feature engineering from raw log dicts
# ---------------------------------------------------------------------------

def _engineer_features_single(log: dict) -> np.ndarray:
    """Extract the feature vector from a single log entry (dict)."""
    features = np.zeros(len(FEATURE_NAMES), dtype=np.float64)

    # 1. api_call_frequency - proxy: count field or default 1
    features[0] = _safe_float(log.get("api_call_count") or log.get("count") or log.get("apiCallCount"), 1.0)

    # 2. unique_ip_count
    ip_field = log.get("sourceIPAddress") or log.get("source_ip") or log.get("srcaddr") or ""
    features[1] = max(1.0, len(set(ip_field.split(","))))

    # 3. session_entropy - use event names / actions as proxy
    action = log.get("eventName") or log.get("action") or log.get("event_name") or ""
    user = log.get("userIdentity") or log.get("user") or log.get("srcaddr") or ""
    features[2] = _shannon_entropy(list(str(action) + str(user)))

    # 4. bytes_transferred
    bytes_in = _safe_float(log.get("bytes") or log.get("bytesIn") or log.get("bytes_transferred"))
    bytes_out = _safe_float(log.get("bytesOut") or log.get("bytes_out"))
    features[3] = bytes_in + bytes_out

    # 5. geo_velocity - if lat/lon provided, else hash-based proxy
    lat = _safe_float(log.get("latitude") or log.get("lat"))
    lon = _safe_float(log.get("longitude") or log.get("lon"))
    if lat != 0.0 or lon != 0.0:
        features[4] = math.sqrt(lat ** 2 + lon ** 2)  # crude distance proxy
    else:
        region = log.get("awsRegion") or log.get("region") or ""
        features[4] = _hash_to_numeric(region) * 100  # map region to number

    # 6. error_rate
    error_code = log.get("errorCode") or log.get("error_code") or ""
    features[5] = 0.0 if error_code in ("", "None", None) else 1.0

    # 7. request_interval_mean (placeholder - single log has no interval)
    features[6] = _safe_float(log.get("request_interval") or log.get("interval_mean"))

    # 8. request_interval_std
    features[7] = _safe_float(log.get("request_interval_std") or log.get("interval_std"))

    # 9. unique_user_agents
    ua = log.get("userAgent") or log.get("user_agent") or ""
    features[8] = max(1.0, len(set(ua.split(","))))

    # 10. privilege_escalation_score
    event = (log.get("eventName") or log.get("action") or "").lower()
    priv_keywords = ["assume", "escalat", "admin", "root", "attach", "policy", "create"]
    features[9] = sum(1 for kw in priv_keywords if kw in event)

    return features


def _engineer_features_batch(logs: List[dict]) -> np.ndarray:
    """Engineer features for a batch of log entries."""
    if not logs:
        return np.empty((0, len(FEATURE_NAMES)))
    return np.vstack([_engineer_features_single(log) for log in logs])


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _log_transform(X: np.ndarray) -> np.ndarray:
    """Apply log1p transformation to stabilise skewed distributions."""
    return np.log1p(np.abs(X)) * np.sign(X)


def _zscore_normalize(X: np.ndarray, mean: Optional[np.ndarray] = None,
                      std: Optional[np.ndarray] = None) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Z-score normalisation.  Returns (X_norm, mean, std)."""
    if mean is None:
        mean = np.mean(X, axis=0)
    if std is None:
        std = np.std(X, axis=0)
    std = np.where(std == 0, 1.0, std)  # avoid division by zero
    X_norm = (X - mean) / std
    return X_norm, mean, std


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class CloudLogPreprocessor:
    """Stateful preprocessor that remembers normalisation statistics."""

    def __init__(self):
        self.mean_: Optional[np.ndarray] = None
        self.std_: Optional[np.ndarray] = None
        self.is_fitted: bool = False

    def fit_transform(self, logs: List[dict]) -> Tuple[np.ndarray, List[str]]:
        """Engineer features, fit normalisation, return transformed data."""
        raw = _engineer_features_batch(logs)
        transformed = _log_transform(raw)
        normalised, self.mean_, self.std_ = _zscore_normalize(transformed)
        self.is_fitted = True
        return normalised, list(FEATURE_NAMES)

    def transform(self, logs: List[dict]) -> Tuple[np.ndarray, List[str]]:
        """Transform new data using previously fitted statistics."""
        raw = _engineer_features_batch(logs)
        transformed = _log_transform(raw)
        if self.is_fitted:
            normalised, _, _ = _zscore_normalize(transformed, self.mean_, self.std_)
        else:
            normalised, self.mean_, self.std_ = _zscore_normalize(transformed)
            self.is_fitted = True
        return normalised, list(FEATURE_NAMES)

    def get_params(self) -> dict:
        return {"mean": self.mean_, "std": self.std_, "is_fitted": self.is_fitted}


def preprocess_logs(logs: List[dict]) -> Tuple[np.ndarray, List[str]]:
    """Convenience function: engineer features and normalise in one call."""
    preprocessor = CloudLogPreprocessor()
    return preprocessor.fit_transform(logs)


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------

def load_csv(filepath: Union[str, Path]) -> List[dict]:
    """Load a CSV file and return a list of dicts."""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"CSV file not found: {filepath}")
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        return list(reader)


def load_dataset(data_dir: Union[str, Path] = None) -> List[dict]:
    """Load all CSV files from the data-sets directory."""
    if data_dir is None:
        data_dir = Path(__file__).parent.parent / "data-sets"
    data_dir = Path(data_dir)
    all_logs: List[dict] = []
    for csv_file in sorted(data_dir.glob("*.csv")):
        all_logs.extend(load_csv(csv_file))
    return all_logs


# ---------------------------------------------------------------------------
# Train / Val / Test split
# ---------------------------------------------------------------------------

def split_data(X: np.ndarray, y: Optional[np.ndarray] = None,
               train: float = _SPLIT_TRAIN, val: float = _SPLIT_VAL,
               seed: int = 42) -> dict:
    """
    Split data into train / val / test sets (70/15/15 by default).
    Returns dict with keys: X_train, X_val, X_test (and y_* if y given).
    """
    rng = np.random.RandomState(seed)
    n = X.shape[0]
    indices = rng.permutation(n)

    n_train = int(n * train)
    n_val = int(n * val)

    train_idx = indices[:n_train]
    val_idx = indices[n_train:n_train + n_val]
    test_idx = indices[n_train + n_val:]

    result = {
        "X_train": X[train_idx],
        "X_val": X[val_idx],
        "X_test": X[test_idx],
    }
    if y is not None:
        result["y_train"] = y[train_idx]
        result["y_val"] = y[val_idx]
        result["y_test"] = y[test_idx]

    return result
