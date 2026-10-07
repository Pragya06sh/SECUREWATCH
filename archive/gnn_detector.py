# gnn_detector.py

import torch


def normalize_rssi(rssi):
    """
    Normalize RSSI to 0–1 scale
    """
    return (rssi + 100) / 80


def detect_gnn_attack(requests, rssi):
    """
    Advanced suspicious device detection
    using weighted scoring logic.
    """

    risk_score = 0

    # Request behavior scoring
    if requests <= 3:
        risk_score += 0

    elif requests <= 5:
        risk_score += 10

    elif requests <= 8:
        risk_score += 25

    else:
        risk_score += 40

    # RSSI behavior scoring
    normalized_rssi = normalize_rssi(rssi)

    if rssi < -90:
        risk_score += 40

    elif rssi < -80:
        risk_score += 25

    elif rssi < -70:
        risk_score += 10

    # Final decision
    if risk_score >= 60:
        return True

    return False