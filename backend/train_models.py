"""
SecureWatch Model Training Script
Trains Random Forest + Isolation Forest on the synthetic Bluetooth dataset.
Saves models and a metrics.json with honest evaluation metrics.

Usage: python train_models.py
"""
import os
import sys
import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, ConfusionMatrixDisplay,
    classification_report
)
import joblib

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
STATIC_DIR = os.path.join(BASE_DIR, "static", "img")
DATASET_PATH = os.path.join(BASE_DIR, "bluetooth_dataset.csv")
REALISTIC_DATASET_PATH = os.path.join(DATA_DIR, "bluetooth_realistic_dataset.csv")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)


def generate_dataset_if_missing(force=False):
    """Generate a synthetic Bluetooth dataset with realistic noise and class overlap."""
    if os.path.exists(DATASET_PATH) and not force:
        print(f"Dataset found at {DATASET_PATH}")
        return

    print("Generating synthetic Bluetooth device dataset with behavioral labels...")
    np.random.seed(42)
    n_samples = 8000

    records = []
    for _ in range(n_samples):
        rssi = np.random.randint(-95, -25)
        request_count = max(0, int(np.random.poisson(4) + np.random.normal(0, 1.5)))
        device_type = np.random.randint(1, 6)
        manufacturer_known = np.random.choice([0, 1], p=[0.4, 0.6])

        # Attacks are strictly driven by behavioral request flooding / volumetric bursts
        # Missing identity (unknown manufacturer) and signal strength (RSSI) NEVER cause attack labels
        attack_score = 0.0
        if request_count >= 16:
            attack_score += 0.75
        elif request_count >= 12:
            attack_score += 0.35
        elif request_count >= 8:
            attack_score += 0.10

        # Add slight noise
        noise = np.random.normal(0, 0.05)
        attack_prob = min(1.0, max(0.0, attack_score + noise))
        attack = 1 if attack_prob >= 0.50 else 0

        # Flip ~2% of labels for realistic noise
        if np.random.random() < 0.02:
            attack = 1 - attack

        records.append([rssi, request_count, device_type, manufacturer_known, attack])

    df = pd.DataFrame(records, columns=["rssi", "request_count", "device_type",
                                         "manufacturer_known", "attack"])
    df.to_csv(DATASET_PATH, index=False)
    print(f"Dataset created: {df.shape[0]} samples")
    print(f"Attack distribution:\n{df['attack'].value_counts()}")


def train():
    """Train both models and save metrics."""
    generate_dataset_if_missing(force=True)

    # Load dataset
    df = pd.read_csv(DATASET_PATH)
    print(f"\nLoaded dataset: {df.shape}")

    X = df.drop("attack", axis=1)
    y = df["attack"]

    # Proper 3-way split: train 60%, val 20%, test 20%
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.4, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )

    print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    # ===== Random Forest =====
    print("\nTraining Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)

    # Validation metrics
    y_val_pred = rf_model.predict(X_val)
    y_val_prob = rf_model.predict_proba(X_val)[:, 1]

    val_accuracy = accuracy_score(y_val, y_val_pred)
    val_precision = precision_score(y_val, y_val_pred, zero_division=0)
    val_recall = recall_score(y_val, y_val_pred, zero_division=0)
    val_f1 = f1_score(y_val, y_val_pred, zero_division=0)
    val_auc = roc_auc_score(y_val, y_val_prob)

    print(f"Validation — Acc: {val_accuracy:.4f}, P: {val_precision:.4f}, "
          f"R: {val_recall:.4f}, F1: {val_f1:.4f}, AUC: {val_auc:.4f}")

    # Test metrics (held out, reported honestly)
    y_test_pred = rf_model.predict(X_test)
    y_test_prob = rf_model.predict_proba(X_test)[:, 1]

    test_accuracy = accuracy_score(y_test, y_test_pred)
    test_precision = precision_score(y_test, y_test_pred, zero_division=0)
    test_recall = recall_score(y_test, y_test_pred, zero_division=0)
    test_f1 = f1_score(y_test, y_test_pred, zero_division=0)
    test_auc = roc_auc_score(y_test, y_test_prob)

    print(f"Test     — Acc: {test_accuracy:.4f}, P: {test_precision:.4f}, "
          f"R: {test_recall:.4f}, F1: {test_f1:.4f}, AUC: {test_auc:.4f}")

    # Save RF model
    joblib.dump(rf_model, os.path.join(MODELS_DIR, "rf_model.pkl"))
    print("Random Forest saved to models/rf_model.pkl")

    # ===== Isolation Forest =====
    print("\nTraining Isolation Forest...")
    iso_model = IsolationForest(
        n_estimators=200,
        contamination=0.15,
        random_state=42,
        n_jobs=-1
    )
    iso_model.fit(X_train)
    joblib.dump(iso_model, os.path.join(MODELS_DIR, "isolation_model.pkl"))
    print("Isolation Forest saved to models/isolation_model.pkl")

    # ===== Confusion Matrix Plot =====
    cm = confusion_matrix(y_test, y_test_pred)
    disp = ConfusionMatrixDisplay(cm, display_labels=["Normal", "Attack"])
    fig, ax = plt.subplots(figsize=(6, 5))
    disp.plot(ax=ax, cmap="Blues")
    ax.set_title("Random Forest — Confusion Matrix (Test Set)")
    plt.tight_layout()
    cm_path = os.path.join(STATIC_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=150)
    plt.savefig(os.path.join(BASE_DIR, "static", "confusion_matrix.png"), dpi=150)
    plt.savefig(os.path.join(BASE_DIR, "confusion_matrix.png"), dpi=150)
    plt.close()
    print(f"Confusion matrix saved to {cm_path}")

    # ===== Feature Importance Plot =====
    importance = rf_model.feature_importances_
    features = X.columns.tolist()
    sorted_idx = np.argsort(importance)[::-1]

    fig, ax = plt.subplots(figsize=(8, 5))
    colors = ["#4CAF50", "#2196F3", "#FF9800", "#F44336"]
    ax.bar(range(len(features)), importance[sorted_idx],
           color=colors[:len(features)], edgecolor="white", linewidth=0.5)
    ax.set_xticks(range(len(features)))
    ax.set_xticklabels([features[i] for i in sorted_idx], rotation=15)
    ax.set_title("Feature Importance — Random Forest")
    ax.set_ylabel("Importance")
    plt.tight_layout()
    fi_path = os.path.join(STATIC_DIR, "feature_importance.png")
    plt.savefig(fi_path, dpi=150)
    plt.savefig(os.path.join(BASE_DIR, "static", "feature_importance.png"), dpi=150)
    plt.savefig(os.path.join(BASE_DIR, "feature_importance.png"), dpi=150)
    plt.close()
    print(f"Feature importance saved to {fi_path}")

    # ===== Save Metrics JSON =====
    metrics = {
        "dataset": {
            "source": "Synthetic Bluetooth device feature dataset",
            "type": "synthetic",
            "note": "Evaluation on synthetic benchmark dataset; real-world accuracy depends on deployment environment and physical RF conditions. Synthetic accuracy is not presented as real-world accuracy.",
            "total_samples": len(df),
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test),
            "attack_ratio": float(y.mean()),
            "features": features,
        },
        "random_forest": {
            "validation": {
                "accuracy": round(val_accuracy, 4),
                "precision": round(val_precision, 4),
                "recall": round(val_recall, 4),
                "f1_score": round(val_f1, 4),
                "roc_auc": round(val_auc, 4),
            },
            "test": {
                "accuracy": round(test_accuracy, 4),
                "precision": round(test_precision, 4),
                "recall": round(test_recall, 4),
                "f1_score": round(test_f1, 4),
                "roc_auc": round(test_auc, 4),
            },
            "confusion_matrix": cm.tolist(),
            "feature_importance": {features[i]: round(float(importance[i]), 4)
                                   for i in sorted_idx},
            "hyperparameters": {
                "n_estimators": 200,
                "max_depth": 15,
                "min_samples_split": 5,
                "min_samples_leaf": 2,
            }
        },
        "isolation_forest": {
            "type": "unsupervised anomaly detection",
            "contamination": 0.15,
            "n_estimators": 200,
            "note": "No labeled accuracy — anomaly detection is used as an additional signal",
        },
        "images": {
            "confusion_matrix": "/static/img/confusion_matrix.png",
            "feature_importance": "/static/img/feature_importance.png",
        }
    }

    metrics_path = os.path.join(MODELS_DIR, "metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"\nMetrics saved to {metrics_path}")
    print("\n[OK] Training complete!")


if __name__ == "__main__":
    train()
