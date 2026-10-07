"""
SecureWatch Detection Engine
Combines rule-based scoring, Random Forest probability, and Isolation Forest
anomaly detection into a single transparent risk score with explainable reasons.

STRICT BEHAVIOURAL INTEGRITY:
Missing identity alone (unnamed device, unknown manufacturer, randomized MAC,
or static RSSI) NEVER causes risk points or SUSPICIOUS/ATTACK status.
Unverified devices with nominal behavior are classified as UNVERIFIED.
"""
import os
import csv
import hashlib
import logging
import time
from typing import Optional

from config import (
    CRITICAL_KEYWORDS,
    SUSPICIOUS_KEYWORDS,
    TRUSTED_MANUFACTURERS,
    OUI_CSV_PATH,
    BRAND_VENDOR_MAP,
    RISK_SUSPICIOUS_NAME,
    RISK_REQUEST_FLOOD,
    RISK_AI_FLAG,
    RISK_RSSI_SPOOF,
    RISK_UNKNOWN_MANUFACTURER,
    RISK_FINGERPRINT_CHANGE,
    RISK_IMPERSONATION,
    RISK_THRESHOLD_SUSPICIOUS,
    RISK_THRESHOLD_ATTACK,
    STATUS_SAFE,
    STATUS_UNVERIFIED,
    STATUS_SUSPICIOUS,
    STATUS_ATTACK,
    STATUS_BLOCKED,
    RSSI_JUMP_THRESHOLD,
    RSSI_HISTORY_LENGTH,
    REQUEST_COUNT_SUSPICIOUS,
    ACTIVITY_WINDOW_SECONDS,
    REPUTATION_INITIAL,
    REPUTATION_FLOOR,
    REPUTATION_CEILING,
    REPUTATION_DECAY_FACTOR,
    REPUTATION_RECOVERY_RATE,
)
from ai_detector import predict_rf, predict_isolation
from trusted_manager import is_device_trusted

logger = logging.getLogger("securewatch.detection")

# Cached OUI vendor lookup map
_OUI_CACHE = {}


def _load_oui_database():
    """Load combined OUI database from static config and OUI CSV."""
    global _OUI_CACHE
    _OUI_CACHE = dict(TRUSTED_MANUFACTURERS)
    if os.path.exists(OUI_CSV_PATH):
        try:
            with open(OUI_CSV_PATH, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    pref = row.get("prefix", "").strip().upper()
                    vendor = row.get("vendor", "").strip()
                    if pref and vendor:
                        _OUI_CACHE[pref] = vendor
        except Exception as e:
            logger.warning(f"Failed to load OUI CSV at {OUI_CSV_PATH}: {e}")


_load_oui_database()


def get_manufacturer(device_id: str) -> str:
    """Look up OUI prefix in combined manufacturer database."""
    if not device_id or len(device_id) < 8:
        return "Unknown"
    prefix = device_id.upper()[:8]
    return _OUI_CACHE.get(prefix, "Unknown")


def is_real_name(name: Optional[str]) -> bool:
    """Return True only if name is a real broadcast name, not empty or placeholder."""
    if not name:
        return False
    n = str(name).strip()
    return bool(n and n.lower() not in ("unknown_device", "unknown", "none", "null", "n/a", ""))


def generate_fingerprint(device_id: str, device_name: str) -> str:
    """SHA-256 fingerprint from device ID + name."""
    raw = (device_id or "") + (device_name or "")
    return hashlib.sha256(raw.encode()).hexdigest()


def detect_and_score(
    device_id: str,
    device_name: str,
    device_type: int = 1,
    rssi: int = None,
    request_count: int = 0,
    rssi_history: list = None,
    previous_fingerprint: str = None,
    current_fingerprint: str = None,
    name_change_count: int = 0,
    is_trusted: bool = False,
    is_baseline_known: bool = False,
) -> dict:
    """
    Run the full behavioral detection pipeline and return:
    - risk_score (int/float, 0-100+)
    - status: SAFE / UNVERIFIED / SUSPICIOUS / ATTACK
    - reasons: list of {reason, contribution} with points
    - ai_attack_detected, isolation_anomaly, rssi_spoof_detected
    """
    manufacturer = get_manufacturer(device_id)
    device_is_trusted = is_trusted or is_device_trusted(device_id)

    risk = 0
    reasons = []

    # ------ 1. Name keyword check (Malicious broadcast name) ------
    if device_name:
        name_lower = device_name.lower()
        matched_crit = [k for k in CRITICAL_KEYWORDS if k in name_lower]
        matched_susp = [k for k in SUSPICIOUS_KEYWORDS if k in name_lower]
        if matched_crit:
            risk += 50
            k_str = ", ".join(f"'{k}'" for k in matched_crit)
            reasons.append({
                "reason": f"+50 malicious keyword {k_str}",
                "contribution": 50
            })
        elif matched_susp:
            risk += 35
            k_str = ", ".join(f"'{k}'" for k in matched_susp)
            reasons.append({
                "reason": f"+35 suspicious keyword {k_str}",
                "contribution": 35
            })

    # ------ 2. Impersonation detection (Claiming brand with mismatched vendor) ------
    if device_name and is_real_name(device_name):
        name_lower = device_name.lower()
        for brand_key, expected_vendor in BRAND_VENDOR_MAP.items():
            if brand_key in name_lower:
                # If manufacturer is known and is DIFFERENT from expected, or brand claimed on non-matching vendor
                if manufacturer != "Unknown" and manufacturer.lower() != expected_vendor.lower():
                    risk += RISK_IMPERSONATION
                    reasons.append({
                        "reason": f"+{RISK_IMPERSONATION} brand impersonation ('{brand_key}' claim on {manufacturer} device)",
                        "contribution": RISK_IMPERSONATION
                    })
                    break

    # ------ 3. Request flood (Behavioral denial-of-service / bandwidth exhaustion) ------
    if request_count > REQUEST_COUNT_SUSPICIOUS:
        contribution = RISK_REQUEST_FLOOD
        risk += contribution
        reasons.append({
            "reason": f"+{contribution} high request rate ({request_count} reqs in {ACTIVITY_WINDOW_SECONDS}s window)",
            "contribution": contribution
        })

    # ------ 4. RSSI spoof detection (Instantaneous teleporting jump) ------
    rssi_spoof = False
    if rssi is not None and rssi_history and len(rssi_history) >= 1:
        last_rssi_val = rssi_history[-1].get("rssi", rssi) if isinstance(rssi_history[-1], dict) else rssi_history[-1]
        diff = abs(rssi - last_rssi_val)
        if diff >= RSSI_JUMP_THRESHOLD:
            rssi_spoof = True
            risk += RISK_RSSI_SPOOF
            reasons.append({
                "reason": f"+{RISK_RSSI_SPOOF} RSSI signal jump ({diff} dBm >= {RSSI_JUMP_THRESHOLD} dBm)",
                "contribution": RISK_RSSI_SPOOF
            })

    # ------ 5. Fingerprint change (Real name changed to DIFFERENT real name) ------
    if (previous_fingerprint and current_fingerprint and
            previous_fingerprint != current_fingerprint):
        risk += RISK_FINGERPRINT_CHANGE
        reasons.append({
            "reason": f"+{RISK_FINGERPRINT_CHANGE} name changed for same MAC",
            "contribution": RISK_FINGERPRINT_CHANGE
        })

    # ------ 6. Name change count tracking ------
    if name_change_count > 1:
        contrib = min(name_change_count * 10, 30)
        risk += contrib
        reasons.append({
            "reason": f"+{contrib} name changed {name_change_count} times",
            "contribution": contrib
        })

    # ------ 7. ML Models: Evaluated only with corroborating behavioral signals ------
    has_behavioral_signal = len(reasons) > 0

    features = {
        "rssi": rssi if rssi is not None else -60,
        "request_count": request_count,
        "device_type": device_type,
        "manufacturer_known": 0 if manufacturer == "Unknown" else 1,
    }

    rf_prob, rf_attack = predict_rf(features)
    if rf_attack and rf_prob is not None:
        if has_behavioral_signal:
            contribution = int(RISK_AI_FLAG * rf_prob)
            if contribution > 0:
                risk += contribution
                reasons.append({
                    "reason": f"+{contribution} ML Random Forest anomaly ({rf_prob:.1%} probability)",
                    "contribution": contribution
                })

    iso_anomaly = predict_isolation(features)
    if iso_anomaly and has_behavioral_signal:
        risk += 15
        reasons.append({
            "reason": "+15 Isolation Forest anomaly (corroborated)",
            "contribution": 15
        })

    # ------ Status Classification ------
    raw_risk = max(0, risk)

    if raw_risk >= RISK_THRESHOLD_ATTACK:
        calculated_status = STATUS_ATTACK
    elif raw_risk >= RISK_THRESHOLD_SUSPICIOUS:
        calculated_status = STATUS_SUSPICIOUS
    else:
        # Below 20 risk: distinguish verified SAFE vs UNVERIFIED
        if device_is_trusted or is_baseline_known or (is_real_name(device_name) and manufacturer != "Unknown"):
            calculated_status = STATUS_SAFE
        else:
            calculated_status = STATUS_UNVERIFIED

    # ------ Apply Whitelist / Trust Override ------
    if device_is_trusted:
        final_status = STATUS_SAFE
        final_risk = 0.0
        override_reasons = [{
            "reason": "[TRUST OVERRIDE] Device whitelisted in trusted configuration",
            "contribution": 0
        }] + reasons
    else:
        final_status = calculated_status
        final_risk = float(raw_risk)
        override_reasons = reasons if reasons else [{
            "reason": "Nominal baseline parameters",
            "contribution": 0
        }]

    return {
        "risk_score": final_risk,
        "raw_risk_score": float(raw_risk),
        "status": final_status,
        "calculated_status": calculated_status,
        "reasons": override_reasons,
        "manufacturer": manufacturer,
        "ai_attack_detected": rf_attack,
        "rf_probability": rf_prob,
        "isolation_anomaly": iso_anomaly,
        "rssi_spoof_detected": rssi_spoof,
        "trusted": device_is_trusted,
    }


def update_reputation(current_reputation: float, risk_score: int, status: str) -> float:
    """
    Update device reputation score, clamped between FLOOR and CEILING.
    - ATTACK/SUSPICIOUS: decay by risk * factor
    - SAFE/UNVERIFIED: slowly recover
    """
    if current_reputation is None:
        current_reputation = REPUTATION_INITIAL

    if status in (STATUS_ATTACK, STATUS_SUSPICIOUS, STATUS_BLOCKED):
        current_reputation -= risk_score * REPUTATION_DECAY_FACTOR
    else:
        current_reputation += REPUTATION_RECOVERY_RATE

    return max(REPUTATION_FLOOR, min(REPUTATION_CEILING, current_reputation))
