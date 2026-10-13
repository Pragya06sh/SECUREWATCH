"""
SecureWatch AI Detector
Loads trained models (Random Forest + Isolation Forest) at startup.
Falls back to rule-based if models are missing.
"""
import os
import json
import logging
import numpy as np

logger = logging.getLogger("securewatch.ai")

# Will be populated at load time
_rf_model = None
_iso_model = None
_model_features = None
_metrics = None


def load_models(models_dir):
    """Load trained models from disk. Called once at server startup."""
    global _rf_model, _iso_model, _model_features, _metrics

    rf_path = os.path.join(models_dir, "rf_model.pkl")
    iso_path = os.path.join(models_dir, "isolation_model.pkl")
    metrics_path = os.path.join(models_dir, "metrics.json")

    try:
        import joblib
        if os.path.exists(rf_path):
            _rf_model = joblib.load(rf_path)
            logger.info(f"Random Forest model loaded from {rf_path}")
        else:
            logger.warning(f"RF model not found at {rf_path} — using rule-based only")

        if os.path.exists(iso_path):
            _iso_model = joblib.load(iso_path)
            logger.info(f"Isolation Forest model loaded from {iso_path}")
        else:
            logger.warning(f"Isolation model not found at {iso_path}")

        if os.path.exists(metrics_path):
            with open(metrics_path, "r") as f:
                _metrics = json.load(f)
            logger.info("Model metrics loaded")

    except Exception as e:
        logger.error(f"Failed to load models: {e}")


def get_model_info():
    """Return info about loaded models for the dashboard."""
    models = []
    if _rf_model is not None:
        models.append({
            "name": "Random Forest Classifier",
            "type": "supervised",
            "status": "active",
            "description": "Trained on synthetic Bluetooth device feature dataset",
        })
    if _iso_model is not None:
        models.append({
            "name": "Isolation Forest (Anomaly Detection)",
            "type": "unsupervised",
            "status": "active",
            "description": "Detects outlier device behaviour patterns",
        })
    models.append({
        "name": "Rule-Based Scoring Engine",
        "type": "heuristic",
        "status": "active",
        "description": "Keyword matching, RSSI anomaly, request rate, manufacturer lookup, fingerprint change",
    })
    return {"models": models, "metrics": _metrics}


def predict_rf(features_dict):
    """
    Run the Random Forest model on device features.
    Returns (probability_of_attack, is_attack_flag).
    Features expected: rssi, request_count, device_type, manufacturer_known
    (matching the training data columns).
    """
    if _rf_model is None:
        return None, False

    try:
        # Build feature DataFrame matching training column names
        import pandas as pd
        feature_names = ["rssi", "request_count", "device_type", "manufacturer_known"]
        row = {f: float(features_dict.get(f, 0)) for f in feature_names}
        X = pd.DataFrame([row])

        prediction = _rf_model.predict(X)[0]
        try:
            proba = _rf_model.predict_proba(X)[0]
            attack_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
        except Exception:
            attack_prob = float(prediction)

        return float(attack_prob), bool(prediction == 1)
    except Exception as e:
        logger.error(f"RF prediction error: {e}")
        return None, False


def predict_isolation(features_dict):
    """
    Run the Isolation Forest on device features.
    Returns True if the device is an outlier/anomaly.
    """
    if _iso_model is None:
        return False

    try:
        import pandas as pd
        feature_names = ["rssi", "request_count", "device_type", "manufacturer_known"]
        row = {f: float(features_dict.get(f, 0)) for f in feature_names}
        X = pd.DataFrame([row])

        prediction = _iso_model.predict(X)[0]
        return bool(prediction == -1)  # -1 = anomaly
    except Exception as e:
        logger.error(f"Isolation Forest prediction error: {e}")
        return False