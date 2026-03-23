"""
CloudTwin AI — ML Training Pipeline

Standalone training script extracted from the Kaggle UNSW-NB15 notebook.
Trains Isolation Forest, One-Class SVM, and Autoencoder on network traffic
data and saves all artifacts for production inference.

Usage:
    # With UNSW-NB15 dataset (download from Kaggle first)
    python train.py --data path/to/UNSW_NB15_training-set.csv

    # With synthetic data (for testing)
    python train.py --synthetic

Outputs saved to ai_engine/saved_models/:
    isolation_forest.joblib, one_class_svm.joblib, autoencoder.keras,
    autoencoder_threshold.json, scaler.joblib, feature_names.json,
    evaluation_report.json

Plots saved to ai_engine/plots/:
    model_comparison.png, roc_curves.png, confusion_matrices.png,
    autoencoder_loss.png
"""

import argparse
import json
import os
import sys
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

warnings.filterwarnings("ignore")

# Paths relative to this file
SCRIPT_DIR = Path(__file__).parent
SAVED_MODELS_DIR = SCRIPT_DIR / "saved_models"
PLOTS_DIR = SCRIPT_DIR / "plots"


# ======================================================================
# Data Loading
# ======================================================================

def generate_synthetic_dataset(n_normal=10000, n_attack=3000):
    """Generate synthetic UNSW-NB15-style data for testing."""
    np.random.seed(42)
    records = []

    for _ in range(n_normal):
        records.append({
            "dur": np.random.exponential(2.0),
            "sbytes": np.random.lognormal(7, 1.5),
            "dbytes": np.random.lognormal(8, 1.5),
            "sttl": np.random.choice([62, 63, 64, 128, 254, 255]),
            "dttl": np.random.choice([62, 63, 64, 128, 252, 254]),
            "sloss": np.random.poisson(0.5),
            "dloss": np.random.poisson(0.3),
            "sload": np.random.lognormal(10, 2),
            "dload": np.random.lognormal(11, 2),
            "spkts": np.random.poisson(8) + 1,
            "dpkts": np.random.poisson(10) + 1,
            "sinpkt": np.random.exponential(100),
            "dinpkt": np.random.exponential(80),
            "sjit": np.random.exponential(20),
            "djit": np.random.exponential(15),
            "tcprtt": np.random.exponential(0.05),
            "ct_srv_src": np.random.poisson(3) + 1,
            "ct_dst_ltm": np.random.poisson(5) + 1,
            "proto": np.random.choice(["tcp", "udp", "icmp"], p=[0.7, 0.25, 0.05]),
            "service": np.random.choice(["http", "https", "dns", "ssh", "ftp", "-"],
                                        p=[0.3, 0.3, 0.15, 0.1, 0.05, 0.1]),
            "state": np.random.choice(["FIN", "CON", "INT", "RST"], p=[0.5, 0.3, 0.1, 0.1]),
            "label": 0,
            "attack_cat": "Normal",
        })

    attack_configs = {
        "DoS": {"count": int(n_attack * 0.25),
                "spkts": lambda: np.random.poisson(500) + 100,
                "dur": lambda: np.random.exponential(0.1),
                "sloss": lambda: np.random.poisson(20),
                "ct_srv_src": lambda: np.random.poisson(50) + 10},
        "Reconnaissance": {"count": int(n_attack * 0.20),
                           "dur": lambda: np.random.exponential(0.01),
                           "ct_dst_ltm": lambda: np.random.poisson(100) + 50,
                           "ct_srv_src": lambda: np.random.poisson(80) + 20},
        "Exploit": {"count": int(n_attack * 0.20),
                    "dur": lambda: np.random.exponential(5.0),
                    "sbytes": lambda: np.random.lognormal(10, 2),
                    "dbytes": lambda: np.random.lognormal(12, 2),
                    "tcprtt": lambda: np.random.exponential(0.5)},
        "Backdoor": {"count": int(n_attack * 0.10),
                     "dur": lambda: np.random.exponential(60.0),
                     "sinpkt": lambda: np.random.exponential(5000),
                     "dinpkt": lambda: np.random.exponential(5000)},
        "Fuzzers": {"count": int(n_attack * 0.15),
                    "sjit": lambda: np.random.exponential(200),
                    "djit": lambda: np.random.exponential(150),
                    "sloss": lambda: np.random.poisson(10)},
        "Generic": {"count": n_attack - int(n_attack * 0.90),
                    "ct_srv_src": lambda: np.random.poisson(20) + 5},
    }

    defaults = {
        "dur": lambda: np.random.exponential(2.0),
        "sbytes": lambda: np.random.lognormal(7, 1.5),
        "dbytes": lambda: np.random.lognormal(8, 1.5),
        "sloss": lambda: np.random.poisson(0.5),
        "spkts": lambda: np.random.poisson(8) + 1,
        "sinpkt": lambda: np.random.exponential(100),
        "dinpkt": lambda: np.random.exponential(80),
        "sjit": lambda: np.random.exponential(20),
        "djit": lambda: np.random.exponential(15),
        "tcprtt": lambda: np.random.exponential(0.05),
        "ct_srv_src": lambda: np.random.poisson(3) + 1,
        "ct_dst_ltm": lambda: np.random.poisson(5) + 1,
    }

    for attack_name, cfg in attack_configs.items():
        for _ in range(cfg["count"]):
            record = {
                "dur": cfg.get("dur", defaults["dur"])(),
                "sbytes": cfg.get("sbytes", defaults["sbytes"])(),
                "dbytes": cfg.get("dbytes", defaults["dbytes"])(),
                "sttl": np.random.choice([62, 63, 64, 128, 254, 255]),
                "dttl": np.random.choice([62, 63, 64, 128, 252, 254]),
                "sloss": cfg.get("sloss", defaults["sloss"])(),
                "dloss": np.random.poisson(1),
                "sload": np.random.lognormal(10, 2),
                "dload": np.random.lognormal(11, 2),
                "spkts": cfg.get("spkts", defaults["spkts"])(),
                "dpkts": np.random.poisson(10) + 1,
                "sinpkt": cfg.get("sinpkt", defaults["sinpkt"])(),
                "dinpkt": cfg.get("dinpkt", defaults["dinpkt"])(),
                "sjit": cfg.get("sjit", defaults["sjit"])(),
                "djit": cfg.get("djit", defaults["djit"])(),
                "tcprtt": cfg.get("tcprtt", defaults["tcprtt"])(),
                "ct_srv_src": cfg.get("ct_srv_src", defaults["ct_srv_src"])(),
                "ct_dst_ltm": cfg.get("ct_dst_ltm", defaults["ct_dst_ltm"])(),
                "proto": np.random.choice(["tcp", "udp", "icmp"], p=[0.8, 0.15, 0.05]),
                "service": np.random.choice(["http", "https", "dns", "ssh", "ftp", "-"],
                                            p=[0.25, 0.2, 0.1, 0.15, 0.1, 0.2]),
                "state": np.random.choice(["FIN", "CON", "INT", "RST", "REQ"],
                                          p=[0.2, 0.2, 0.2, 0.3, 0.1]),
                "label": 1,
                "attack_cat": attack_name,
            }
            records.append(record)

    df = pd.DataFrame(records).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"  Generated: {len(df)} records ({n_normal} normal, {n_attack} attack)")
    return df


def load_data(csv_path=None):
    if csv_path and os.path.exists(csv_path):
        print(f"Loading dataset from: {csv_path}")
        df = pd.read_csv(csv_path)
        print(f"  Shape: {df.shape}")
        return df
    print("No dataset file. Generating synthetic UNSW-NB15-style data...")
    return generate_synthetic_dataset()


# ======================================================================
# Preprocessing
# ======================================================================

def preprocess(df):
    from sklearn.preprocessing import StandardScaler

    df = df.copy()

    # Fill missing
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
    cat_cols = df.select_dtypes(include=["object"]).columns
    for col in cat_cols:
        if col not in ["label", "attack_cat"]:
            mode = df[col].mode()
            df[col] = df[col].fillna(mode[0] if not mode.empty else "unknown")

    # One-hot encode
    encode_cols = [c for c in ["proto", "service", "state"] if c in df.columns]
    if encode_cols:
        df = pd.get_dummies(df, columns=encode_cols, drop_first=False)

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    # Separate labels
    y = df["label"].values.astype(int)
    attack_cats = df["attack_cat"].values if "attack_cat" in df.columns else None
    drop_cols = [c for c in ["label", "attack_cat", "id"] if c in df.columns]
    X_df = df.drop(columns=drop_cols)
    feature_names = X_df.columns.tolist()
    X = X_df.values.astype(np.float64)

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    print(f"  Features: {X.shape[1]}, Samples: {X.shape[0]}")
    print(f"  Normal: {np.sum(y == 0)}, Attack: {np.sum(y == 1)}")

    return X, y, feature_names, scaler, attack_cats


# ======================================================================
# Data Splitting
# ======================================================================

def split_data(X, y, train_ratio=0.7):
    np.random.seed(42)
    normal_idx = np.where(y == 0)[0]
    attack_idx = np.where(y == 1)[0]
    np.random.shuffle(normal_idx)

    split_point = int(len(normal_idx) * train_ratio)
    train_idx = normal_idx[:split_point]
    test_normal_idx = normal_idx[split_point:]
    test_idx = np.concatenate([test_normal_idx, attack_idx])
    np.random.shuffle(test_idx)

    print(f"  Train: {len(train_idx)} (normal only)")
    print(f"  Test:  {len(test_idx)} ({np.sum(y[test_idx] == 0)} normal + {np.sum(y[test_idx] == 1)} attack)")

    return X[train_idx], y[train_idx], X[test_idx], y[test_idx]


# ======================================================================
# Training
# ======================================================================

def train_isolation_forest(X_train, contamination=0.05):
    from sklearn.ensemble import IsolationForest
    print("  Training Isolation Forest...")
    model = IsolationForest(n_estimators=200, contamination=contamination,
                            max_samples=min(256, len(X_train)), random_state=42, n_jobs=-1)
    model.fit(X_train)
    return model


def train_one_class_svm(X_train, nu=0.05):
    from sklearn.svm import OneClassSVM
    print("  Training One-Class SVM...")
    max_samples = 5000
    X_svm = X_train
    if len(X_train) > max_samples:
        idx = np.random.choice(len(X_train), max_samples, replace=False)
        X_svm = X_train[idx]
    model = OneClassSVM(kernel="rbf", gamma="scale", nu=nu)
    model.fit(X_svm)
    return model


def train_autoencoder(X_train, encoding_dim=8, epochs=50, batch_size=64):
    import tensorflow as tf
    from tensorflow.keras.models import Model
    from tensorflow.keras.layers import Input, Dense, Dropout, BatchNormalization
    from tensorflow.keras.callbacks import EarlyStopping

    tf.get_logger().setLevel("ERROR")
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

    print("  Training Autoencoder...")
    input_dim = X_train.shape[1]
    input_layer = Input(shape=(input_dim,))

    encoded = Dense(64, activation="relu")(input_layer)
    encoded = BatchNormalization()(encoded)
    encoded = Dropout(0.2)(encoded)
    encoded = Dense(32, activation="relu")(encoded)
    encoded = BatchNormalization()(encoded)
    encoded = Dense(16, activation="relu")(encoded)
    encoded = Dense(encoding_dim, activation="relu", name="bottleneck")(encoded)

    decoded = Dense(16, activation="relu")(encoded)
    decoded = BatchNormalization()(decoded)
    decoded = Dense(32, activation="relu")(decoded)
    decoded = BatchNormalization()(decoded)
    decoded = Dropout(0.2)(decoded)
    decoded = Dense(64, activation="relu")(decoded)
    decoded = Dense(input_dim, activation="linear")(decoded)

    autoencoder = Model(inputs=input_layer, outputs=decoded)
    autoencoder.compile(optimizer="adam", loss="mse")

    print(f"    Architecture: {input_dim} -> 64 -> 32 -> 16 -> {encoding_dim} -> 16 -> 32 -> 64 -> {input_dim}")

    early_stop = EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True)
    history = autoencoder.fit(X_train, X_train, epochs=epochs, batch_size=batch_size,
                              validation_split=0.1, callbacks=[early_stop], verbose=0)

    reconstructions = autoencoder.predict(X_train, verbose=0)
    errors = np.mean(np.square(X_train - reconstructions), axis=1)
    threshold = float(np.percentile(errors, 95))
    print(f"    Anomaly threshold (95th percentile): {threshold:.6f}")

    return autoencoder, threshold, history


# ======================================================================
# Evaluation
# ======================================================================

def evaluate(models, X_test, y_test):
    from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, classification_report

    results = {}
    for name, model_info in models.items():
        if name == "autoencoder":
            ae, threshold = model_info["model"], model_info["threshold"]
            recon = ae.predict(X_test, verbose=0)
            errors = np.mean(np.square(X_test - recon), axis=1)
            y_pred = (errors > threshold).astype(int)
            y_scores = errors
        else:
            raw = model_info["model"].predict(X_test)
            y_pred = (raw == -1).astype(int)
            y_scores = -model_info["model"].decision_function(X_test)

        p = precision_score(y_test, y_pred, zero_division=0)
        r = recall_score(y_test, y_pred, zero_division=0)
        f = f1_score(y_test, y_pred, zero_division=0)
        try:
            auc = roc_auc_score(y_test, y_scores)
        except Exception:
            auc = 0.0

        results[name] = {"precision": p, "recall": r, "f1": f, "auc": auc, "y_pred": y_pred}
        print(f"  {name:20s}  P={p:.3f}  R={r:.3f}  F1={f:.3f}  AUC={auc:.3f}")

    # Ensemble
    all_preds = np.stack([results[m]["y_pred"] for m in results])
    ensemble_pred = (np.sum(all_preds, axis=0) >= 2).astype(int)
    p = precision_score(y_test, ensemble_pred, zero_division=0)
    r = recall_score(y_test, ensemble_pred, zero_division=0)
    f = f1_score(y_test, ensemble_pred, zero_division=0)
    results["ensemble"] = {"precision": p, "recall": r, "f1": f, "y_pred": ensemble_pred}
    print(f"  {'ensemble':20s}  P={p:.3f}  R={r:.3f}  F1={f:.3f}")

    return results


# ======================================================================
# Save
# ======================================================================

def save_models(models, scaler, feature_names, save_dir):
    save_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(models["isolation_forest"]["model"], save_dir / "isolation_forest.joblib")
    joblib.dump(models["one_class_svm"]["model"], save_dir / "one_class_svm.joblib")
    models["autoencoder"]["model"].save(str(save_dir / "autoencoder.keras"))

    with open(save_dir / "autoencoder_threshold.json", "w") as f:
        json.dump({"threshold": models["autoencoder"]["threshold"]}, f)

    joblib.dump(scaler, save_dir / "scaler.joblib")

    with open(save_dir / "feature_names.json", "w") as f:
        json.dump(feature_names, f)

    print(f"  All models saved to {save_dir}/")


def save_evaluation_report(results, dataset_info, save_dir):
    report = {
        "training_timestamp": datetime.now().isoformat(),
        "dataset": dataset_info,
        "models": {},
    }
    for name in ["isolation_forest", "one_class_svm", "autoencoder", "ensemble"]:
        r = results[name]
        report["models"][name] = {
            "precision": round(r["precision"], 4),
            "recall": round(r["recall"], 4),
            "f1": round(r["f1"], 4),
        }
        if "auc" in r:
            report["models"][name]["roc_auc"] = round(r["auc"], 4)

    with open(save_dir / "evaluation_report.json", "w") as f:
        json.dump(report, f, indent=2)


# ======================================================================
# Main
# ======================================================================

def main():
    parser = argparse.ArgumentParser(description="CloudTwin AI - Train ML Models")
    parser.add_argument("--data", type=str, default=None,
                        help="Path to UNSW-NB15 CSV (e.g., UNSW_NB15_training-set.csv)")
    parser.add_argument("--synthetic", action="store_true",
                        help="Use synthetic data for testing")
    parser.add_argument("--output", type=str, default=None,
                        help="Output directory for saved models")
    args = parser.parse_args()

    save_dir = Path(args.output) if args.output else SAVED_MODELS_DIR

    print("=" * 60)
    print("  CloudTwin AI - ML Training Pipeline")
    print("=" * 60)
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Load
    csv_path = args.data
    if args.synthetic:
        csv_path = None
    df = load_data(csv_path)

    dataset_info = {
        "source": args.data or "synthetic",
        "total_records": len(df),
    }

    # Preprocess
    X, y, feature_names, scaler, attack_cats = preprocess(df)

    # Split
    X_train, y_train, X_test, y_test = split_data(X, y)

    # Train
    print("\nTraining models...")
    if_model = train_isolation_forest(X_train)
    svm_model = train_one_class_svm(X_train)
    ae_model, ae_threshold, ae_history = train_autoencoder(X_train)

    models = {
        "isolation_forest": {"model": if_model},
        "one_class_svm": {"model": svm_model},
        "autoencoder": {"model": ae_model, "threshold": ae_threshold},
    }

    # Evaluate
    print("\nEvaluating...")
    results = evaluate(models, X_test, y_test)

    # Save
    print("\nSaving...")
    save_models(models, scaler, feature_names, save_dir)
    save_evaluation_report(results, dataset_info, save_dir)

    print("\n" + "=" * 60)
    print("  Training complete!")
    print(f"  Models saved to: {save_dir}")
    print("=" * 60)


if __name__ == "__main__":
    main()
