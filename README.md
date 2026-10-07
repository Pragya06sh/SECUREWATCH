# 🛡️ SECUREWATCH: Intelligent BLE & Smartwatch Threat Defense Platform

> **Real-Time Bluetooth Behavioral Intrusion Detection, Automated Quarantine, and Cryptographic Hash-Chained Audit Logging.**

---

## 🎯 Executive Overview & Judge Summary

**SecureWatch** protects smart personal IoT ecosystems (smartwatches, wearables, audio devices) from physical-proximity wireless attacks. Nearby Bluetooth Low Energy (BLE) advertisements are continuously monitored and sent to an intelligent multi-layer detection hub:

1. **Multi-Layer Behavioral & Heuristic Detection**:
   - **OUI Manufacturer Verification**: Validates whether the MAC prefix matches known hardware vendors (Samsung, Apple, Google, Fitbit, Garmin, boAt, Noise).
   - **Signal Teleportation (RSSI Spoofing)**: Flags unphysical instantaneous signal amplitude jumps (>40 dBm in milliseconds).
   - **Cryptographic Device Fingerprinting**: Detects MAC-spoofing identity switches when an attacker commandeers an authorized MAC address with a modified advertised payload.
   - **Connection Flood & DoS Defense**: Tracks per-device connection frequencies in sliding time windows.
   - **Exploit Keyword Signature Matching**: Identifies known rogue and malicious broadcast names.
2. **Machine Learning & Behavioral Outlier Engine**:
   - **Random Forest Classifier**: Supervised classification predicting probability of spoofing / attack from multi-dimensional telemetry (RSSI, request rate, device type, manufacturer credibility).
   - **Isolation Forest**: Unsupervised anomaly detection detecting zero-day behavioral deviations.
3. **Automated Quarantine & Reputation Scoring**:
   - Dynamic reputation decay/recovery (0 to 100). Malicious devices are instantly locked into quarantine and blocked locally on the BLE interface.
4. **Cryptographic Hash-Chained Audit Log ("Blockchain")**:
   - Every security event is immutably appended to a sequential SHA-256 hash chain ($H_n = \text{SHA256}(n, t, \text{data}, H_{n-1})$).
   - Includes live interactive **Tamper Detection Demonstration** proving mathematically that any alteration in past security logs is immediately caught.

---

## 🚀 Quick Start & Live Demo

### 1. Launch the Intelligence Hub & Web SOC
Run the launcher from the project root:
```bash
python run_server.py
```
This starts the FastAPI backend on `http://127.0.0.1:8000` and automatically opens the **Cyber SOC Dashboard** in your browser.

### 2. Live BLE Scanner (Hardware Mode)
In a separate terminal, to discover real Bluetooth devices around you:
```bash
cd backend
python scanner.py
```

### 3. Simulation Mode (No Bluetooth Hardware Needed)
If BLE hardware is unavailable or you are presenting on a demo machine, use the **One-Click Attack Injector** in the web dashboard or toggle **"Start Sim Stream"** at the top right of the dashboard.

---

## 🎭 Judge Presentation Walkthrough Script

Follow these steps for a 2-minute live judging demo:

1. **Step 1: The SOC Overview (`Threat Monitor` Tab)**
   - Show the live dashboard with real-time statistics (Total Devices, Verified Safe, Suspicious, Attacks, Quarantined).
   - Click **"Start Sim Stream"** to show real-time ingestion of ambient BLE devices with live reputation tracking.
2. **Step 2: Threat Injection & Automated Quarantine (`Attack Injector` Tab)**
   - Click **"Inject Spoof Attack"** or **"Inject RSSI Jump"**.
   - Watch the system immediately flag the threat, flash a crimson warning badge, trigger a desktop alert, dock reputation, and enforce quarantine.
3. **Step 3: Cryptographic Audit Trail (`Audit Ledger` Tab)**
   - Switch to the **Audit Ledger** tab to show the newly generated block containing the attack telemetry and cryptographic hash.
   - Click **"🛡️ Verify Cryptographic Integrity"** — show the green verified banner.
   - Click **"⚠️ Demo Tamper Test"** — demonstrate how altering a historical block immediately triggers an alert showing hash mismatch and broken chain link.
   - Click **"↺ Reset Tamper Demo"** to restore authentic state.
4. **Step 4: AI Telemetry (`AI & ML Engine` Tab)**
   - Show the Random Forest and Isolation Forest metrics, Confusion Matrix, and Feature Importance graphs.

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/verify-device` | Real-time BLE device verification (backward compatible) |
| `POST` | `/api/v1/verify` | Modern JSON device verification endpoint |
| `GET` | `/api/v1/stats` | Aggregated SOC statistics |
| `GET` | `/api/v1/devices` | Filtered list of all observed BLE devices |
| `GET` | `/api/v1/devices/{id}` | Deep inspection (RSSI history, fingerprint, reputation) |
| `POST` | `/api/v1/devices/{id}/quarantine` | Administrative quarantine override |
| `POST` | `/api/v1/devices/{id}/unblock` | Release device from quarantine |
| `GET` | `/api/v1/ledger` | Full sequential hash-chained audit blocks |
| `GET` | `/api/v1/ledger/verify` | Validate cryptographic chain integrity |
| `POST` | `/api/v1/ledger/tamper-test` | Interactive cryptographic tamper simulation |
| `GET` | `/api/v1/models/metrics` | Machine Learning model parameters & validation scores |
| `POST` | `/api/v1/simulation/inject/{scenario}` | Inject named attack vector (`spoofed_watch`, `request_flood`, `rssi_teleport`, etc.) |

---

## 🧪 Verification & Testing

To run the automated end-to-end test suite:
```bash
cd backend
python test_securewatch.py
```
All 8 test suites validate system health, heuristics, ML inference, quarantine enforcement, blockchain persistence, and tamper verification.
