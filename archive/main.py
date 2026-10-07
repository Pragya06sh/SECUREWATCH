from fastapi import FastAPI
import time
import hashlib

from blockchain import Blockchain
from ai_detector import detect_attack
from alerts import send_alert
from gnn_detector import detect_gnn_attack

app = FastAPI()

# ----------------------------------
# Blockchain Setup
# ----------------------------------

blockchain = Blockchain()

blockchain.add_block({
    "device_id": "AA:BB:CC",
    "device_name": "Galaxy Watch"
})

# ----------------------------------
# Storage
# ----------------------------------

device_logs = []
device_activity = {}
device_reputation = {}
device_fingerprints = {}
device_rssi_history = {}

quarantined_devices = set()
blocklist = set()

# ----------------------------------
# Manufacturer Database
# ----------------------------------

trusted_manufacturers = {
    "DC:DA:0C": "Samsung",
    "F4:7D:EF": "Samsung",
    "A4:C1:38": "Apple",
    "3C:5A:B4": "Fitbit"
}

# ----------------------------------
# Helper Functions
# ----------------------------------

def generate_fingerprint(device_id, device_name):
    raw = device_id + device_name
    return hashlib.sha256(raw.encode()).hexdigest()


def get_manufacturer(device_id):
    prefix = device_id.upper()[0:8]
    return trusted_manufacturers.get(prefix, "Unknown")


def calculate_risk(device_id, device_name, request_count, ai_flag, rssi_spoof):

    risk = 0

    suspicious_words = ["hack","spoof","fake","malicious","attack"]

    for word in suspicious_words:
        if word in device_name.lower():
            risk += 40

    if request_count > 5:
        risk += 25

    if ai_flag:
        risk += 30

    if rssi_spoof:
        risk += 35

    manufacturer = get_manufacturer(device_id)

    if manufacturer == "Unknown":
        risk += 10

    return risk


def classify_device(risk):

    if risk < 20:
        return "SAFE"
    elif risk < 50:
        return "SUSPICIOUS"
    else:
        return "ATTACK"


# ----------------------------------
# Device Verification API
# ----------------------------------

@app.get("/verify-device")

def verify_device(device_id: str,
                  device_name: str,
                  device_type: int,
                  timestamp: int,
                  rssi: int):

    current_time = time.time()

    # ---------- BLOCKED DEVICE CHECK ----------
    if device_id in blocklist:

        return {
            "device_id": device_id,
            "device_name": device_name,
            "status": "BLOCKED",
            "quarantined": True
        }

    # ---------- Activity Tracking ----------

    if device_id not in device_activity:
        device_activity[device_id] = []

    device_activity[device_id].append(current_time)

    device_activity[device_id] = [
        t for t in device_activity[device_id] if current_time - t < 10
    ]

    request_count = len(device_activity[device_id])

    # ---------- AI Detection ----------

    ai_suspicious = detect_attack(request_count, device_type)

    # ---------- GNN Detection ----------

    gnn_suspicious = detect_gnn_attack(request_count, rssi)

    if gnn_suspicious:
        ai_suspicious = True

    # ---------- Device Fingerprinting ----------

    fingerprint = generate_fingerprint(device_id, device_name)

    if device_id not in device_fingerprints:

        device_fingerprints[device_id] = fingerprint

    else:

        if device_fingerprints[device_id] != fingerprint:
            ai_suspicious = True

    # ---------- RSSI Spoof Detection ----------

    if device_id not in device_rssi_history:
        device_rssi_history[device_id] = []

    device_rssi_history[device_id].append(rssi)

    if len(device_rssi_history[device_id]) > 5:
        device_rssi_history[device_id].pop(0)

    rssi_spoof = False

    if len(device_rssi_history[device_id]) >= 2:

        diff = abs(
            device_rssi_history[device_id][-1] -
            device_rssi_history[device_id][-2]
        )

        if diff > 40:
            rssi_spoof = True

    # ---------- Manufacturer ----------

    manufacturer = get_manufacturer(device_id)

    # ---------- Risk Score ----------

    risk_score = calculate_risk(
        device_id,
        device_name,
        request_count,
        ai_suspicious,
        rssi_spoof
    )

    security_status = classify_device(risk_score)

    # ---------- Reputation ----------

    if device_id not in device_reputation:
        device_reputation[device_id] = 100

    device_reputation[device_id] -= risk_score * 0.1

    # ---------- Quarantine ----------

    if security_status == "ATTACK":

        quarantined_devices.add(device_id)
        blocklist.add(device_id)

        send_alert("Malicious Bluetooth device detected: " + device_name)

        blockchain.add_block({
            "device_id": device_id,
            "device_name": device_name,
            "event": "ATTACK_DETECTED",
            "timestamp": timestamp
        })
        # Save blockchain immediately
    blockchain.save_chain()
    # ---------- Logging ----------

    log = {
        "device_id": device_id,
        "device_name": device_name,
        "manufacturer": manufacturer,
        "timestamp": timestamp,
        "risk_score": risk_score,
        "status": security_status,
        "rssi": rssi,
        "rssi_spoof": rssi_spoof
    }

    device_logs.append(log)

    # ---------- Response ----------

    return {
        "device_id": device_id,
        "device_name": device_name,
        "manufacturer": manufacturer,
        "risk_score": risk_score,
        "security_status": security_status,
        "ai_attack_detected": ai_suspicious,
        "rssi_spoof_detected": rssi_spoof,
        "recent_requests": request_count,
        "reputation": device_reputation[device_id],
        "quarantined": device_id in quarantined_devices
    }


# ----------------------------------
# Dashboard API
# ----------------------------------

@app.get("/dashboard")

def dashboard():

    total = len(device_logs)

    safe = sum(1 for d in device_logs if d["status"] == "SAFE")
    suspicious = sum(1 for d in device_logs if d["status"] == "SUSPICIOUS")
    attacks = sum(1 for d in device_logs if d["status"] == "ATTACK")

    quarantined = len(quarantined_devices)

    return {
        "total_devices_scanned": total,
        "safe_devices": safe,
        "suspicious_devices": suspicious,
        "attacks_detected": attacks,
        "quarantined_devices": quarantined,
        "blockchain_events": len(blockchain.chain) - 1
    }
    
@app.get("/blockchain")

def view_blockchain():

    blockchain.save_chain()

    return {
        "total_blocks": len(blockchain.chain),
        "chain_valid": blockchain.is_chain_valid(),
        "latest_block_hash": blockchain.chain[-1].hash
    }