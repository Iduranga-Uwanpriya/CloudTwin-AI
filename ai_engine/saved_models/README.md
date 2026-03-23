# Saved Models Directory

This directory holds the trained ML model artifacts produced by the
UNSW-NB15 training notebook (`ai_engine/train_anomaly_models.ipynb`).

## Required files

Copy these 6 files from the notebook's output (`saved_models/`) into this directory:

| File | Description |
|---|---|
| `isolation_forest.joblib` | Trained Isolation Forest model (sklearn) |
| `one_class_svm.joblib` | Trained One-Class SVM model (sklearn) |
| `autoencoder.keras` | Trained Autoencoder model (TensorFlow/Keras) |
| `autoencoder_threshold.json` | Reconstruction error threshold for anomaly detection |
| `scaler.joblib` | Fitted StandardScaler (must match training preprocessing) |
| `feature_names.json` | Ordered list of 190 feature column names after one-hot encoding |

## How to get these files

### Option A: From Google Colab
If you trained on Colab, download the `saved_models/` folder from your Colab runtime
and place the contents here.

### Option B: Re-run the notebook locally
```bash
cd ai_engine
pip install tensorflow scikit-learn pandas numpy joblib matplotlib seaborn

# Option 1: Run notebook
jupyter notebook train_anomaly_models.ipynb

# Option 2: Run training script
python train.py --data path/to/UNSW_NB15_training-set.csv
```

## Verification

Once files are in place, check the API:
```
GET http://localhost:8000/api/v1/anomaly/status
```
Should return `"status": "ready"`.
