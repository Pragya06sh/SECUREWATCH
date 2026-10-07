import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import MODELS_DIR
from ai_detector import load_models
from detection_engine import detect_and_score

load_models(MODELS_DIR)

devices = [
    ("OnePlus Nord Buds 2", "08:12:87:16:4A:62", 1, -36),
    ("Unknown_Device", "33:30:1C:22:21:7E", 1, -66),
    ("Unknown_Device", "1E:49:2E:64:12:D4", 1, -68),
]

for name, mac, dtype, rssi in devices:
    res = detect_and_score(mac, name, device_type=dtype, rssi=rssi)
    print("==================================================")
    print("Device: %s (%s) at RSSI %s dBm" % (name, mac, rssi))
    print("Risk Score: %s | Status: %s" % (res["risk_score"], res["status"]))
    print("Manufacturer: %s" % res["manufacturer"])
    print("RF Attack Flag: %s (Probability: %s)" % (res["ai_attack_detected"], res["rf_probability"]))
    print("Isolation Forest Anomaly: %s" % res["isolation_anomaly"])
    print("Reasons Breakdown:")
    for r in res.get("reasons", []):
        print("  - %s" % r["reason"])
print("==================================================")
