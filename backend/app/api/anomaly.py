"""
Anomaly Detection API Routes
AI-powered threat detection using Kaggle-trained ML models (UNSW-NB15)
"""
from fastapi import APIRouter, UploadFile, File, HTTPException
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

router = APIRouter(prefix="/anomaly", tags=["AI Anomaly Detection"])


def _get_inference_engine():
    """Load the production inference engine (Kaggle-trained models)."""
    from ai_engine.ml.inference import AnomalyInferenceEngine
    engine = AnomalyInferenceEngine()
    if not engine.models_exist():
        return None
    engine.load_models()
    return engine


@router.post("/detect")
async def detect_anomaly(file: UploadFile = File(...)):
    """
    AI-powered anomaly detection on uploaded log file (CSV).
    Uses ensemble of Isolation Forest, One-Class SVM, and Autoencoder
    trained on UNSW-NB15 dataset.

    Upload a CSV with network traffic features (UNSW-NB15 format):
    dur, sbytes, dbytes, sttl, dttl, sloss, dloss, sload, dload,
    spkts, dpkts, sinpkt, dinpkt, sjit, djit, tcprtt, ct_srv_src,
    ct_dst_ltm, proto, service, state

    Optionally include 'label' and 'attack_cat' columns for evaluation.
    """
    try:
        engine = _get_inference_engine()
        if engine is None:
            return {
                "status": "models_not_found",
                "message": (
                    "Trained models not found in ai_engine/saved_models/. "
                    "Run the training notebook (train_anomaly_models.ipynb) first and copy "
                    "the saved_models/ directory here."
                ),
                "required_files": [
                    "isolation_forest.joblib",
                    "one_class_svm.joblib",
                    "autoencoder.keras",
                    "autoencoder_threshold.json",
                    "scaler.joblib",
                    "feature_names.json",
                ],
            }

        content = await file.read()
        csv_text = content.decode("utf-8")

        results = engine.predict_from_csv(csv_text)
        return results

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ImportError as e:
        return {
            "status": "dependency_missing",
            "message": f"Missing dependency: {e}. Install with: pip install tensorflow scikit-learn pandas",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Anomaly detection failed: {str(e)}")


@router.post("/detect/quick")
async def detect_anomaly_quick(logs: list[dict]):
    """
    Quick anomaly detection from JSON log entries.
    Accepts list of dicts with UNSW-NB15 feature keys.
    """
    try:
        import pandas as pd
        engine = _get_inference_engine()
        if engine is None:
            return {
                "status": "models_not_found",
                "message": "Trained models not found. Run the training notebook first.",
            }

        if not logs:
            raise HTTPException(status_code=400, detail="Empty log list")

        df = pd.DataFrame(logs)
        X = engine.preprocess(df)
        results = engine.predict(X)

        return {
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
        }
    except FileNotFoundError:
        return {
            "status": "models_not_found",
            "message": "Trained models not found. Run the training notebook first.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
def anomaly_detection_status():
    """Get status of AI anomaly detection module."""
    try:
        from ai_engine.ml.inference import AnomalyInferenceEngine
        engine = AnomalyInferenceEngine()
        models_exist = engine.models_exist()

        model_dir = engine.model_dir
        individual_status = {}
        for name, filename in [
            ("isolation_forest", "isolation_forest.joblib"),
            ("one_class_svm", "one_class_svm.joblib"),
            ("autoencoder", "autoencoder.keras"),
            ("scaler", "scaler.joblib"),
        ]:
            individual_status[name] = "ready" if (model_dir / filename).exists() else "missing"

        return {
            "module": "AI Anomaly Detection",
            "status": "ready" if models_exist else "models_missing",
            "dataset": "UNSW-NB15 (Kaggle)",
            "models": individual_status,
            "ensemble": "active" if models_exist else "inactive",
            "model_directory": str(model_dir),
        }
    except Exception:
        return {
            "module": "AI Anomaly Detection",
            "status": "not_configured",
            "message": "AI engine module not found",
        }


@router.get("/evaluation")
def get_model_evaluation():
    """
    Get the evaluation metrics from the training notebook.
    These are the results from when the models were trained on UNSW-NB15.
    """
    # Check for notebook evaluation report (detections.json)
    eval_path = Path(__file__).parent.parent.parent.parent / "ai_engine" / "saved_models" / "evaluation_report.json"
    if eval_path.exists():
        with open(eval_path, "r") as f:
            return json.load(f)

    # Return the training metrics from the notebook run
    return {
        "dataset": "UNSW-NB15 (82,332 records)",
        "training_samples": 25900,
        "test_samples": 56432,
        "models": {
            "isolation_forest": {"precision": 0.960, "recall": 0.323, "f1": 0.483, "roc_auc": 0.752},
            "one_class_svm": {"precision": 0.966, "recall": 0.477, "f1": 0.639, "roc_auc": 0.719},
            "autoencoder": {"precision": 0.974, "recall": 0.504, "f1": 0.664, "roc_auc": 0.852},
            "ensemble": {"precision": 0.973, "recall": 0.482, "f1": 0.644},
        },
        "note": "Run training notebook for full evaluation report in saved_models/evaluation_report.json",
    }
