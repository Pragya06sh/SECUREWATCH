"""
SecureWatch — Central FastAPI Security & AI Analysis Hub
Real-time Bluetooth device verification, AI anomaly detection,
reputation scoring, tamper-evident hash-chained audit logging,
and live SOC dashboard backend.
"""
import os
import time
import json
import logging
import asyncio
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, HTTPException, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from config import (
    BASE_DIR,
    MODELS_DIR,
    STATIC_DIR,
    CORS_ORIGINS,
    ACTIVITY_WINDOW_SECONDS,
    REPUTATION_INITIAL,
    REPUTATION_FLOOR,
    REPUTATION_CEILING,
    REPUTATION_DECAY_FACTOR,
    REPUTATION_RECOVERY_RATE,
)
import database as db
from blockchain import Blockchain
from ai_detector import load_models, get_model_info
from detection_engine import detect_and_score, get_manufacturer, generate_fingerprint
from alerts import send_alert
import simulation as sim
from trusted_manager import (
    is_device_trusted,
    add_trusted_device,
    remove_trusted_device,
    load_trusted_devices,
    clear_trusted_devices,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("securewatch.main")

# Module-level initialization to ensure ready state in all environments / test runners
db.init_db()
load_models(MODELS_DIR)
blockchain = Blockchain()
sim_task: Optional[asyncio.Task] = None
sim_running: bool = False


async def simulation_background_loop():
    """Background task for auto-generating simulated BLE device traffic."""
    global sim_running
    logger.info("Simulation background loop started.")
    while sim_running:
        try:
            # Generate a small stream of normal devices + occasional jitter
            devices = sim.generate_background_traffic(count=2)
            for dev in devices:
                process_device_verification(
                    device_id=dev["device_id"],
                    device_name=dev["device_name"],
                    device_type=dev["device_type"],
                    timestamp=dev["timestamp"],
                    rssi=dev["rssi"]
                )
            await asyncio.sleep(4)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in simulation loop: {e}")
            await asyncio.sleep(5)
    logger.info("Simulation background loop stopped.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global blockchain, sim_task, sim_running
    logger.info("Initializing SecureWatch core subsystems...")
    
    # 1. Initialize SQLite Database
    db.init_db()
    
    # 2. Load ML Models
    load_models(MODELS_DIR)
    
    # 3. Load / Initialize Blockchain
    blockchain = Blockchain()
    
    # Ensure static directory exists
    os.makedirs(STATIC_DIR, exist_ok=True)
    
    logger.info("SecureWatch initialized and ready.")
    yield
    
    # Shutdown
    if sim_running and sim_task:
        sim_running = False
        sim_task.cancel()
        try:
            await sim_task
        except asyncio.CancelledError:
            pass
    logger.info("SecureWatch shutdown complete.")


app = FastAPI(
    title="SecureWatch Intelligence Platform",
    description="Real-Time Smartwatch & Bluetooth Behavioral Intrusion Detection with Cryptographic Audit Logging",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files if directory exists
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ----------------------------------------------------
# Pydantic Schemas
# ----------------------------------------------------
class DeviceVerificationRequest(BaseModel):
    device_id: str = Field(..., example="DC:DA:0C:55:44:33", description="MAC address")
    device_name: str = Field("Unknown_Device", example="Galaxy Watch 5")
    device_type: int = Field(1, example=3, description="1: Earbuds/Audio, 2: Phone/Tablet, 3: Smartwatch/Wearable, 4: Computer, 0: Unknown")
    rssi: int = Field(-60, example=-55, description="Received Signal Strength Indicator in dBm")
    timestamp: Optional[int] = Field(None, description="Unix epoch timestamp")


class QuarantineToggleRequest(BaseModel):
    blocked: bool = Field(..., description="True to quarantine/block, False to unblock")


class DeviceTrustRequest(BaseModel):
    trusted: bool = Field(True, description="True to mark device as trusted whitelist, False to remove")
    notes: Optional[str] = Field("", description="Optional justification or user note")


# ----------------------------------------------------
def is_real_name(name: Optional[str]) -> bool:
    """Return True only if name is a real broadcast name, not empty or placeholder."""
    if not name:
        return False
    n = str(name).strip()
    return bool(n and n.lower() not in ("unknown_device", "unknown", "none", "null", "n/a", ""))


# ----------------------------------------------------
# Core Detection Orchestrator
# ----------------------------------------------------
def process_device_verification(
    device_id: str,
    device_name: str,
    device_type: int = 1,
    timestamp: Optional[int] = None,
    rssi: Optional[int] = None
) -> Dict[str, Any]:
    """
    Central orchestration function executed by all ingress routes.
    Runs persistence, behavioral rate analysis, fingerprinting,
    ML + heuristic detection engine, reputation decay/recovery,
    quarantine enforcement, and tamper-evident blockchain logging.
    """
    if timestamp is None:
        timestamp = int(time.time())
    if rssi is None:
        rssi = -65
    
    device_id = device_id.strip()
    incoming_name = device_name.strip() if device_name else ""

    # 1. Fetch previous state if existing
    prev_device = db.get_device(device_id)
    prev_name = prev_device.get("device_name") if prev_device else None
    prev_fingerprint = prev_device["fingerprint"] if prev_device else None
    name_changes = prev_device["name_changes"] if prev_device else 0
    current_reputation = prev_device["reputation"] if prev_device else REPUTATION_INITIAL
    is_trusted = is_device_trusted(device_id) or bool(prev_device and prev_device.get("trusted"))
    is_currently_blocked = bool(prev_device and prev_device["blocked"]) and not is_trusted

    # 2. Determine effective device name & evaluate name change without false positives
    # Real rule: Only flag when changing from one real name to a DIFFERENT real name.
    # Keep the last non-empty name per MAC when an empty/unknown name is seen later.
    pass_prev_fingerprint = None
    if is_real_name(incoming_name):
        effective_name = incoming_name
        if is_real_name(prev_name):
            if prev_name != incoming_name:
                name_changes += 1
                pass_prev_fingerprint = prev_fingerprint
            else:
                pass_prev_fingerprint = prev_fingerprint
        else:
            # First time receiving a real name after empty/Unknown -> NOT a spoof/change
            pass_prev_fingerprint = None
    else:
        # Incoming is empty or Unknown_Device
        if is_real_name(prev_name):
            # Retain the last non-empty real name!
            effective_name = prev_name
            pass_prev_fingerprint = prev_fingerprint
        else:
            effective_name = "Unknown_Device"
            pass_prev_fingerprint = None

    curr_fingerprint = generate_fingerprint(device_id, effective_name)

    # 3. Rate and RSSI history tracking
    db.record_activity(device_id)
    request_count = db.get_request_count(device_id, window_seconds=ACTIVITY_WINDOW_SECONDS)
    
    # Fetch previous RSSI history for delta comparison BEFORE adding current reading
    rssi_history_rows = db.get_rssi_history(device_id, limit=10)
    rssi_values = [r["rssi"] for r in rssi_history_rows]
    db.add_rssi(device_id, rssi)

    # 4. Execute Detection Pipeline
    detection = detect_and_score(
        device_id=device_id,
        device_name=effective_name,
        device_type=device_type,
        rssi=rssi,
        request_count=request_count,
        rssi_history=rssi_values,
        previous_fingerprint=pass_prev_fingerprint,
        current_fingerprint=curr_fingerprint,
        name_change_count=name_changes,
        is_trusted=is_trusted,
    )

    risk_score = detection["risk_score"]
    security_status = detection["status"]
    reasons = list(detection["reasons"])

    # If device was manually/previously quarantined, keep blocked status unless trusted
    if is_currently_blocked and not is_trusted:
        if security_status != "ATTACK":
            security_status = "BLOCKED"
        reasons.insert(0, {"reason": "Active quarantine enforcement is active for this device", "contribution": 0})

    # 5. Reputation Dynamics
    if security_status in ("ATTACK", "BLOCKED"):
        current_reputation = max(REPUTATION_FLOOR, current_reputation - (risk_score * REPUTATION_DECAY_FACTOR * 2))
    elif security_status == "SUSPICIOUS":
        current_reputation = max(REPUTATION_FLOOR, current_reputation - (risk_score * REPUTATION_DECAY_FACTOR))
    else:  # SAFE
        current_reputation = min(REPUTATION_CEILING, current_reputation + REPUTATION_RECOVERY_RATE)

    # 6. Action on ATTACK / Quarantine
    quarantined = False
    blocked = False
    if (security_status in ("ATTACK", "BLOCKED") or is_currently_blocked) and not is_trusted:
        quarantined = True
        blocked = True
        
        # Desktop alert
        send_alert(
            message=f"Threat detected from {effective_name} ({device_id}) — Risk: {risk_score}",
            title="SecureWatch Alert: Threat Quarantined"
        )
        
        # Append cryptographically chained block to audit log (only on first transition or ATTACK)
        if blockchain and security_status == "ATTACK":
            blockchain.add_block({
                "device_id": device_id,
                "device_name": effective_name,
                "manufacturer": detection["manufacturer"],
                "event": "ATTACK_DETECTED_AND_QUARANTINED",
                "risk_score": risk_score,
                "reasons": reasons,
                "rssi": rssi,
                "request_count": request_count,
                "timestamp": timestamp
            })

    # 7. Persist to DB
    db.upsert_device(
        device_id=device_id,
        device_name=effective_name,
        manufacturer=detection["manufacturer"],
        device_type=device_type,
        risk_score=risk_score,
        status=security_status,
        rssi=rssi,
        reputation=round(current_reputation, 1),
        fingerprint=curr_fingerprint,
        quarantined=1 if quarantined else 0,
        blocked=1 if blocked else 0,
        name_changes=name_changes,
        trusted=1 if is_trusted else 0,
        reasons=reasons,
    )

    db.add_event(
        device_id=device_id,
        device_name=effective_name,
        event_type="SCAN_VERIFIED",
        status=security_status,
        risk_score=risk_score,
        rssi=rssi,
        reasons=reasons,
    )

    # 9. Return Unified Payload
    return {
        "device_id": device_id,
        "device_name": effective_name,
        "manufacturer": detection["manufacturer"],
        "risk_score": risk_score,
        "security_status": security_status,
        "status": security_status,
        "trusted": is_trusted,
        "ai_attack_detected": detection["ai_attack_detected"],
        "rf_probability": detection.get("rf_probability"),
        "isolation_anomaly": detection["isolation_anomaly"],
        "rssi_spoof_detected": detection["rssi_spoof_detected"],
        "recent_requests": request_count,
        "reputation": round(current_reputation, 1),
        "quarantined": quarantined,
        "blocked": blocked,
        "reasons": reasons,
        "timestamp": timestamp,
    }


# ----------------------------------------------------
# Frontend Entry Point
# ----------------------------------------------------
@app.get("/")
def serve_dashboard():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "message": "SecureWatch Intelligence API is running.",
        "dashboard_ui": "/static/index.html",
        "docs": "/docs"
    }


# ----------------------------------------------------
# Backward Compatible Verification Endpoint
# ----------------------------------------------------
@app.get("/verify-device")
def verify_device_legacy(
    device_id: str = Query(..., description="Device MAC address"),
    device_name: str = Query("Unknown_Device", description="Device Broadcast Name"),
    device_type: int = Query(1, description="Device type integer"),
    timestamp: Optional[int] = Query(None, description="Unix timestamp"),
    rssi: int = Query(-60, description="RSSI signal in dBm")
):
    """Legacy GET endpoint for backward compatibility with BLE scanners."""
    return process_device_verification(
        device_id=device_id,
        device_name=device_name,
        device_type=device_type,
        timestamp=timestamp,
        rssi=rssi
    )


@app.post("/api/v1/verify")
def verify_device_v1(payload: DeviceVerificationRequest):
    """Modern JSON POST verification endpoint."""
    return process_device_verification(
        device_id=payload.device_id,
        device_name=payload.device_name,
        device_type=payload.device_type,
        timestamp=payload.timestamp,
        rssi=payload.rssi
    )


# ----------------------------------------------------
# Backward Compatible Dashboard & Blockchain
# ----------------------------------------------------
@app.get("/dashboard")
def get_dashboard_legacy():
    stats = db.get_stats()
    chain_len = len(blockchain.chain) if blockchain else 1
    return {
        "total_devices_scanned": stats["total_devices"],
        "safe_devices": stats["safe_devices"],
        "suspicious_devices": stats["suspicious_devices"],
        "attacks_detected": stats["attack_devices"],
        "quarantined_devices": stats["quarantined_devices"],
        "blockchain_events": max(0, chain_len - 1),
    }


@app.get("/blockchain")
def get_blockchain_legacy():
    if not blockchain:
        return {"total_blocks": 0, "chain_valid": True, "latest_block_hash": "N/A"}
    return {
        "total_blocks": len(blockchain.chain),
        "chain_valid": blockchain.is_chain_valid(),
        "latest_block_hash": blockchain.get_latest_block().hash
    }


# ----------------------------------------------------
# Modern REST API Endpoints (v1)
# ----------------------------------------------------
@app.get("/api/v1/stats")
def get_system_stats():
    """Aggregated statistics for the SOC Dashboard."""
    stats = db.get_stats()
    chain_data = blockchain.validate_detailed() if blockchain else {"valid": True, "total_blocks": 0, "errors": []}
    
    return {
        "devices": {
            "total": stats["total_devices"],
            "safe": stats["safe_devices"],
            "unverified": stats.get("unverified_devices", 0),
            "suspicious": stats["suspicious_devices"],
            "attacks": stats["attack_devices"],
            "quarantined": stats["quarantined_devices"],
            "blocked": stats["blocked_devices"],
        },
        "events_count": stats["total_events"],
        "ledger": {
            "total_blocks": chain_data["total_blocks"],
            "valid": chain_data["valid"],
            "errors": chain_data["errors"],
            "latest_hash": blockchain.get_latest_block().hash if blockchain and len(blockchain.chain) > 0 else ""
        },
        "simulation": {
            "running": sim_running,
            "mode": sim.get_mode()
        }
    }


@app.get("/api/v1/devices")
def get_devices(
    limit: int = Query(200, ge=1, le=1000),
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None)
):
    """List tracked devices with optional filtering."""
    devices = db.get_all_devices(limit=limit)
    if status_filter:
        if status_filter.upper() == "TRUSTED":
            devices = [d for d in devices if d.get("trusted")]
        else:
            devices = [d for d in devices if d.get("status", "").upper() == status_filter.upper()]
    if search:
        s = search.lower()
        devices = [
            d for d in devices
            if s in d.get("device_id", "").lower() or s in (d.get("device_name") or "").lower() or s in (d.get("manufacturer") or "").lower()
        ]
    return {"count": len(devices), "devices": devices}


@app.get("/api/v1/devices/{device_id}")
def get_device_details(device_id: str):
    """Deep inspection of a single device."""
    dev = db.get_device(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    
    rssi_hist = db.get_rssi_history(device_id, limit=30)
    
    return {
        "device": dev,
        "rssi_history": rssi_hist,
    }


@app.post("/api/v1/devices/{device_id}/quarantine")
def toggle_quarantine(device_id: str, req: QuarantineToggleRequest):
    """Manually quarantine or unquarantine a device."""
    dev = db.get_device(device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    
    db.set_blocked(device_id, req.blocked)
    action = "QUARANTINED" if req.blocked else "UNQUARANTINED"
    
    db.add_event(
        device_id=device_id,
        device_name=dev.get("device_name", "Unknown"),
        event_type=f"MANUAL_{action}",
        status="BLOCKED" if req.blocked else dev.get("status", "SAFE"),
        risk_score=dev.get("risk_score", 0.0),
        rssi=dev.get("rssi"),
        reasons=[{"reason": f"Manual administrative {action.lower()}", "contribution": 0}]
    )
    
    if req.blocked and blockchain:
        blockchain.add_block({
            "device_id": device_id,
            "device_name": dev.get("device_name", "Unknown"),
            "event": "MANUAL_QUARANTINE_OVERRIDE",
            "timestamp": int(time.time())
        })
        
    return {"device_id": device_id, "quarantined": req.blocked, "blocked": req.blocked}


@app.post("/api/v1/devices/{device_id}/unblock")
def unblock_device(device_id: str):
    """Release a device from quarantine and unblock it."""
    db.set_blocked(device_id, False)
    return {"device_id": device_id, "status": "UNBLOCKED", "quarantined": False}


@app.post("/api/v1/devices/{device_id}/trust")
def set_device_trust_status(device_id: str, req: Optional[DeviceTrustRequest] = None):
    """
    Mark a device as trusted (saved to trusted_devices.json config file)
    or remove trust. When trusted, device is guaranteed SAFE with 0 risk.
    When untrusted, it is immediately re-scored according to behavioral heuristics.
    """
    trusted_flag = req.trusted if req is not None else True
    notes = req.notes if req is not None else ""
    
    dev = db.get_device(device_id)
    device_name = dev.get("device_name", "Known_Device") if dev else "Known_Device"
    
    if trusted_flag:
        add_trusted_device(device_id, device_name=device_name, notes=notes)
        re_score = detect_and_score(
            device_id=device_id,
            device_name=device_name,
            device_type=dev.get("device_type", 1) if dev else 1,
            rssi=dev.get("rssi", -60) if dev else -60,
            request_count=db.get_request_count(device_id, window_seconds=ACTIVITY_WINDOW_SECONDS),
            name_change_count=dev.get("name_changes", 0) if dev else 0,
            is_trusted=True
        )
        db.set_trusted(device_id, True, status="SAFE", risk_score=0.0, reputation=100.0, reasons=re_score["reasons"])
        db.add_event(
            device_id=device_id,
            device_name=device_name,
            event_type="DEVICE_TRUSTED",
            status="SAFE",
            risk_score=0.0,
            rssi=dev.get("rssi") if dev else -60,
            reasons=re_score["reasons"]
        )
    else:
        remove_trusted_device(device_id)
        if dev:
            re_score = detect_and_score(
                device_id=device_id,
                device_name=dev.get("device_name", ""),
                device_type=dev.get("device_type", 1),
                rssi=dev.get("rssi", -60),
                request_count=db.get_request_count(device_id, window_seconds=ACTIVITY_WINDOW_SECONDS),
                name_change_count=dev.get("name_changes", 0),
                is_trusted=False
            )
            is_quarantined = re_score["status"] == "ATTACK"
            db.upsert_device(
                device_id=device_id,
                device_name=dev.get("device_name", ""),
                manufacturer=re_score["manufacturer"],
                device_type=dev.get("device_type", 1),
                risk_score=re_score["risk_score"],
                status=re_score["status"],
                rssi=dev.get("rssi", -60),
                reputation=dev.get("reputation", 100.0),
                fingerprint=dev.get("fingerprint", ""),
                quarantined=1 if is_quarantined else 0,
                blocked=1 if is_quarantined else 0,
                name_changes=dev.get("name_changes", 0),
                trusted=0,
                reasons=re_score["reasons"]
            )
            db.add_event(
                device_id=device_id,
                device_name=device_name,
                event_type="DEVICE_UNTRUSTED",
                status=re_score["status"],
                risk_score=re_score["risk_score"],
                rssi=dev.get("rssi") if dev else -60,
                reasons=re_score["reasons"]
            )
        else:
            db.set_trusted(device_id, False)
    
    updated = db.get_device(device_id) or {
        "device_id": device_id,
        "device_name": device_name,
        "status": "SAFE" if trusted_flag else "SUSPICIOUS",
        "risk_score": 0.0 if trusted_flag else 0.0,
        "trusted": trusted_flag,
        "quarantined": False,
        "blocked": False
    }
    return {
        "device_id": device_id,
        "trusted": trusted_flag,
        "status": updated.get("status", "SAFE"),
        "risk_score": updated.get("risk_score", 0.0),
        "reputation": updated.get("reputation", 100.0),
        "quarantined": bool(updated.get("quarantined") or updated.get("blocked")),
        "message": f"Device {device_id} {'marked as trusted' if trusted_flag else 'removed from trusted whitelist'}."
    }


@app.post("/api/v1/devices/{device_id}/untrust")
def untrust_device(device_id: str):
    """Remove a device from the trusted configuration file."""
    return set_device_trust_status(device_id, DeviceTrustRequest(trusted=False))


@app.get("/api/v1/trusted-devices")
def get_all_trusted_devices():
    """Retrieve all trusted devices from the JSON configuration file."""
    return {"trusted_devices": load_trusted_devices()}


@app.post("/api/v1/system/clear-data")
def clear_all_system_data():
    """
    Clears all tracked devices, events, and resets trusted devices config,
    while keeping the cryptographic audit ledger intact.
    """
    db.clear_all_data()
    clear_trusted_devices()
    return {
        "status": "SUCCESS",
        "message": "All devices, events, and trusted devices cleared. Ledger remains intact."
    }


@app.post("/api/v1/system/learn-environment")
def learn_environment_endpoint():
    """
    Scans & captures ambient RF baseline: marks all currently visible nominal devices
    as KNOWN environment baseline so ambient devices stay UNVERIFIED/SAFE, while
    any new device that exhibits malicious behavior will still be flagged.
    """
    count = db.learn_environment()
    return {
        "status": "SUCCESS",
        "learned_devices": count,
        "message": f"Environment baseline established for {count} ambient device(s)."
    }


@app.post("/api/v1/ledger/reset")
def reset_ledger_endpoint():
    """
    Separate action: Resets the cryptographic audit ledger to Genesis block.
    """
    if not blockchain:
        raise HTTPException(status_code=500, detail="Blockchain not initialized")
    return blockchain.reset_chain()


@app.get("/api/v1/events")
def get_security_events(
    limit: int = Query(100, ge=1, le=500),
    since: Optional[float] = Query(None)
):
    """Live chronological security events feed."""
    events = db.get_events(limit=limit, since=since)
    return {"count": len(events), "events": events}


# ----------------------------------------------------
# Cryptographic Audit Log / Blockchain API
# ----------------------------------------------------
@app.get("/api/v1/ledger")
def get_ledger_blocks():
    """Retrieve the full hash-chained audit log."""
    if not blockchain:
        return {"blocks": []}
    return {
        "total_blocks": len(blockchain.chain),
        "blocks": blockchain.get_chain_data()
    }


@app.get("/api/v1/ledger/verify")
def verify_ledger(tamper: bool = Query(False, description="Set to true to verify the tampered demo copy")):
    """
    Verify the cryptographic integrity of the hash chain.
    If tamper=true, validates the demo tamper copy to demonstrate alert triggers.
    """
    if not blockchain:
        return {"valid": True, "total_blocks": 0, "errors": []}
    
    if tamper:
        return blockchain.validate_tamper_copy()
    else:
        return blockchain.validate_detailed()


@app.post("/api/v1/ledger/tamper-test")
def trigger_tamper_test(block_index: Optional[int] = Query(None)):
    """
    DEMO TOOL: Modifies a block in an isolated memory copy of the chain
    to illustrate how the hash chain immediately flags any tampering.
    """
    if not blockchain:
        raise HTTPException(status_code=500, detail="Blockchain not initialized")
    return blockchain.start_tamper_test(block_index=block_index)


@app.post("/api/v1/ledger/tamper-reset")
def reset_tamper_test():
    """Resets the demo tamper simulation."""
    if not blockchain:
        return {"message": "Reset complete"}
    return blockchain.reset_tamper_test()


# ----------------------------------------------------
# AI & ML Inspection
# ----------------------------------------------------
@app.get("/api/v1/models/metrics")
def get_ai_metrics():
    """Inspection endpoint for judges/auditors to examine model performance."""
    return get_model_info()


# ----------------------------------------------------
# Simulation Engine Control
# ----------------------------------------------------
@app.get("/api/v1/simulation/scenarios")
def list_simulation_scenarios():
    """List all available predefined attack scenarios."""
    scenarios = []
    for key, val in sim.SCENARIOS.items():
        scenarios.append({
            "key": key,
            "name": val["name"],
            "description": val["description"]
        })
    return {"scenarios": scenarios}


@app.post("/api/v1/simulation/inject/{scenario_name}")
def inject_scenario(scenario_name: str):
    """
    Inject a specific attack scenario into the live detection pipeline.
    Useful for live judging demonstrations.
    """
    if scenario_name not in sim.SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario '{scenario_name}'. Available: {list(sim.SCENARIOS.keys())}"
        )
    
    devices = sim.generate_scenario(scenario_name)
    results = []
    for dev in devices:
        res = process_device_verification(
            device_id=dev["device_id"],
            device_name=dev["device_name"],
            device_type=dev["device_type"],
            timestamp=dev["timestamp"],
            rssi=dev["rssi"]
        )
        results.append(res)
    
    return {
        "scenario": scenario_name,
        "injected_count": len(devices),
        "results": results
    }


@app.post("/api/v1/simulation/start")
async def start_simulation():
    """Start background continuous BLE traffic simulator."""
    global sim_task, sim_running
    if sim_running:
        return {"status": "already_running"}
    
    sim_running = True
    sim_task = asyncio.create_task(simulation_background_loop())
    return {"status": "started", "mode": "SIMULATION"}


@app.post("/api/v1/simulation/stop")
async def stop_simulation():
    """Stop background continuous BLE traffic simulator."""
    global sim_task, sim_running
    if not sim_running:
        return {"status": "already_stopped"}
    
    sim_running = False
    if sim_task:
        sim_task.cancel()
        try:
            await sim_task
        except asyncio.CancelledError:
            pass
    return {"status": "stopped"}


@app.get("/api/v1/simulation/status")
def get_simulation_status():
    """Get current background simulation status."""
    return {
        "running": sim_running,
        "mode": sim.get_mode()
    }


# ----------------------------------------------------
# System Health
# ----------------------------------------------------
@app.get("/api/v1/system/health")
def system_health():
    """Diagnostic health check for the entire security stack."""
    models_info = get_model_info()
    return {
        "status": "HEALTHY",
        "service": "SecureWatch Detection Hub",
        "version": "2.0.0",
        "database": "CONNECTED",
        "blockchain_loaded": blockchain is not None,
        "blockchain_valid": blockchain.is_chain_valid() if blockchain else False,
        "models_active": len(models_info.get("models", [])),
        "simulation_running": sim_running,
        "server_time": time.time(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)