"""
CloudTwin AI - ML Module
Anomaly detection models: Isolation Forest, One-Class SVM, Autoencoder (MLP)

For production inference with Kaggle-trained models:
    from ai_engine.ml.inference import get_engine
"""

# Use lazy imports to avoid circular issues and allow the package to be
# imported as ``ai_engine.ml``.

__all__ = [
    "preprocess_logs",
    "CloudLogPreprocessor",
    "IsolationForestDetector",
    "OneClassSVMDetector",
    "AutoencoderDetector",
    "EnsembleDetector",
    "AnomalyInferenceEngine",
    "get_engine",
]


def __getattr__(name):
    if name in ("preprocess_logs", "CloudLogPreprocessor"):
        from ai_engine.ml.preprocessor import preprocess_logs, CloudLogPreprocessor
        return locals()[name]
    if name in ("IsolationForestDetector", "OneClassSVMDetector",
                "AutoencoderDetector", "EnsembleDetector"):
        from ai_engine.ml.models import (
            IsolationForestDetector, OneClassSVMDetector,
            AutoencoderDetector, EnsembleDetector,
        )
        return locals()[name]
    if name in ("AnomalyInferenceEngine", "get_engine"):
        from ai_engine.ml.inference import AnomalyInferenceEngine, get_engine
        return locals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
