"""
SecureWatch Comprehensive End-to-End System Test
Validates all backend subsystems, ML detectors, risk scoring,
quarantine enforcement, blockchain audit logging, and REST APIs.
"""
import time
import random
from fastapi.testclient import TestClient
import database as db
from main import app

client = TestClient(app)

def random_mac(prefix="EE:FF:11"):
    return f"{prefix}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"

def run_tests():
    print("=" * 60)
    print("  RUNNING SECUREWATCH SYSTEM TEST SUITE")
    print("=" * 60)

    # Reset any existing state from previous test runs
    db.clear_all_data()

    # 1. Health Check
    print("\n[TEST 1] System Health Diagnostic...")
    r = client.get("/api/v1/system/health")
    assert r.status_code == 200, f"Health check failed: {r.text}"
    health = r.json()
    assert health["status"] == "HEALTHY"
    assert health["blockchain_valid"] is True
    print(f"  [PASS] Health check OK: {health['status']} | Active Models: {health['models_active']}")

    # 2. Legacy /verify-device (Safe Device)
    safe_mac = "DC:DA:0C:" + random_mac().split(":", 3)[-1]
    print(f"\n[TEST 2] Verifying Safe Bluetooth Device ({safe_mac})...")
    r = client.get("/verify-device", params={
        "device_id": safe_mac,
        "device_name": "Galaxy Watch 5",
        "device_type": 3,
        "rssi": -55,
        "timestamp": int(time.time())
    })
    assert r.status_code == 200
    res = r.json()
    assert res["status"] in ["SAFE", "SUSPICIOUS"]
    assert res["quarantined"] is False
    print(f"  [PASS] Safe Device Result: Status={res['status']}, Risk={res['risk_score']}, Rep={res['reputation']}")

    # 3. Malicious Attack Detection & Quarantine
    attack_mac = random_mac(prefix="99:88:77")
    print(f"\n[TEST 3] Verifying Malicious Device Detection & Quarantine ({attack_mac})...")
    r = client.get("/verify-device", params={
        "device_id": attack_mac,
        "device_name": "HACK_EVIL_SPOOF_WATCH",
        "device_type": 3,
        "rssi": -20,
        "timestamp": int(time.time())
    })
    assert r.status_code == 200
    res = r.json()
    assert res["status"] in ["ATTACK", "BLOCKED"]
    assert res["quarantined"] is True
    print(f"  [PASS] Attack Flagged & Quarantined: Status={res['status']}, Risk={res['risk_score']}, Quarantined={res['quarantined']}")

    # 4. Backward-Compatible Dashboard & Blockchain
    print("\n[TEST 4] Legacy Dashboard & Blockchain Endpoints...")
    r_dash = client.get("/dashboard")
    assert r_dash.status_code == 200
    dash = r_dash.json()
    assert "total_devices_scanned" in dash
    assert dash["attacks_detected"] >= 1
    print(f"  [PASS] Legacy Dashboard: Total={dash['total_devices_scanned']}, Attacks={dash['attacks_detected']}")

    r_chain = client.get("/blockchain")
    assert r_chain.status_code == 200
    chain = r_chain.json()
    assert chain["total_blocks"] >= 2
    assert chain["chain_valid"] is True
    print(f"  [PASS] Legacy Blockchain: Total Blocks={chain['total_blocks']}, Valid={chain['chain_valid']}")

    # 5. Blockchain Cryptographic Verification & Tamper Test
    print("\n[TEST 5] Cryptographic Audit Chain & Tamper Test Demo...")
    # Verify authentic chain
    r_verify = client.get("/api/v1/ledger/verify")
    assert r_verify.status_code == 200
    v = r_verify.json()
    assert v["valid"] is True
    print(f"  [PASS] Authentic Chain Verification: Valid={v['valid']}, Blocks={v['total_blocks']}")

    # Trigger Tamper Test
    r_tamper = client.post("/api/v1/ledger/tamper-test")
    assert r_tamper.status_code == 200
    r_verify_tamper = client.get("/api/v1/ledger/verify?tamper=true")
    assert r_verify_tamper.status_code == 200
    vt = r_verify_tamper.json()
    assert vt["valid"] is False
    assert len(vt["errors"]) > 0
    print(f"  [PASS] Cryptographic Tamper Detection Succeeded: Flagged {len(vt['errors'])} error(s)")

    # Reset Tamper Test
    r_reset = client.post("/api/v1/ledger/tamper-reset")
    assert r_reset.status_code == 200
    r_verify_post_reset = client.get("/api/v1/ledger/verify")
    assert r_verify_post_reset.json()["valid"] is True
    print("  [PASS] Reset Tamper Demo: Authentic chain restored.")

    # 6. Attack Scenario Injector
    print("\n[TEST 6] Attack Scenario Injection Suite...")
    scenarios = ["spoofed_watch", "request_flood", "rssi_teleport"]
    for sc in scenarios:
        r_inj = client.post(f"/api/v1/simulation/inject/{sc}")
        assert r_inj.status_code == 200
        inj_res = r_inj.json()
        print(f"  [PASS] Scenario '{sc}': Injected {inj_res['injected_count']} device(s)")

    # 7. Device Manual Unblock & Quarantine Override
    print("\n[TEST 7] Administrative Quarantine Override & Unblock...")
    r_unblock = client.post(f"/api/v1/devices/{attack_mac}/unblock")
    assert r_unblock.status_code == 200
    assert r_unblock.json()["quarantined"] is False

    r_block = client.post(f"/api/v1/devices/{attack_mac}/quarantine", json={"blocked": True})
    assert r_block.status_code == 200
    assert r_block.json()["quarantined"] is True
    print("  [PASS] Administrative quarantine controls functioning properly.")

    # 8. ML Telemetry
    print("\n[TEST 8] ML Telemetry & Inspection...")
    r_models = client.get("/api/v1/models/metrics")
    assert r_models.status_code == 200
    models_data = r_models.json()
    assert len(models_data["models"]) >= 2
    print(f"  [PASS] ML Telemetry loaded: {len(models_data['models'])} models available.")

    # 9. Mark as Trusted Whitelist & Config Persistence
    print(f"\n[TEST 9] Trusted Device Whitelisting & Persistence ({attack_mac})...")
    # Mark previously flagged malicious device as trusted
    r_trust = client.post(f"/api/v1/devices/{attack_mac}/trust", json={"trusted": True, "notes": "Verified test device"})
    assert r_trust.status_code == 200
    trust_res = r_trust.json()
    assert trust_res["trusted"] is True
    assert trust_res["status"] == "SAFE"
    assert trust_res["risk_score"] == 0.0

    # Verify trusted list endpoint returns the device
    r_list = client.get("/api/v1/trusted-devices")
    assert r_list.status_code == 200
    trusted_map = r_list.json()["trusted_devices"]
    assert attack_mac.upper() in trusted_map

    # Re-verify device with malicious name; should now be classified as SAFE due to trusted config whitelist
    r_reverify = client.get("/verify-device", params={
        "device_id": attack_mac,
        "device_name": "HACK_EVIL_SPOOF_WATCH",
        "device_type": 3,
        "rssi": -20,
        "timestamp": int(time.time())
    })
    assert r_reverify.status_code == 200
    reverify_res = r_reverify.json()
    assert reverify_res["status"] == "SAFE"
    assert reverify_res["risk_score"] == 0.0
    assert reverify_res["trusted"] is True
    assert reverify_res["quarantined"] is False

    # 10. User Case 1: Benign Unnamed Device with Random MAC at -36, -66, -90 dBm -> UNVERIFIED (Risk < 20)
    print("\n[TEST 10] Benign Unnamed Device at -36, -66, -90 dBm...")
    unnamed_mac = random_mac(prefix="33:30:1C")
    for r_val in [-36, -66, -90]:
        r = client.get("/verify-device", params={
            "device_id": unnamed_mac,
            "device_name": "Unknown_Device",
            "device_type": 1,
            "rssi": r_val,
            "timestamp": int(time.time())
        })
        assert r.status_code == 200
        res = r.json()
        assert res["status"] == "UNVERIFIED", f"Expected UNVERIFIED, got {res['status']}"
        assert res["risk_score"] < 20, f"Expected risk < 20, got {res['risk_score']}"
        assert res["quarantined"] is False
    print(f"  [PASS] Unnamed device with random MAC scored UNVERIFIED (Risk: {res['risk_score']}) across all RSSI levels.")

    # 11. User Case 2: OnePlus Nord Buds 2 at any RSSI -> Never SUSPICIOUS
    print("\n[TEST 11] OnePlus Nord Buds 2 (08:12:87:16:4A:62) at Any RSSI...")
    nord_mac = "08:12:87:16:4A:62"
    for r_val in [-30, -50, -75, -92]:
        r = client.get("/verify-device", params={
            "device_id": nord_mac,
            "device_name": "OnePlus Nord Buds 2",
            "device_type": 1,
            "rssi": r_val,
            "timestamp": int(time.time())
        })
        assert r.status_code == 200
        res = r.json()
        assert res["status"] in ["SAFE", "UNVERIFIED"], f"Nord Buds became {res['status']} at RSSI {r_val}"
        assert res["status"] != "SUSPICIOUS" and res["status"] != "ATTACK"
        assert res["risk_score"] < 20
        assert res["quarantined"] is False
    print(f"  [PASS] OnePlus Nord Buds 2 verified: Status={res['status']}, Risk={res['risk_score']} at RSSI -30 to -92 dBm.")

    # 12. User Case 3: Device named HACK_WATCH_01 -> ATTACK, quarantined, ledger block added
    print("\n[TEST 12] Device named HACK_WATCH_01 -> ATTACK & Ledger Block Added...")
    hack_mac = random_mac(prefix="EE:11:22")
    chain_before = client.get("/api/v1/ledger").json()["total_blocks"]
    r_hack = client.get("/verify-device", params={
        "device_id": hack_mac,
        "device_name": "HACK_WATCH_01",
        "device_type": 3,
        "rssi": -45,
        "timestamp": int(time.time())
    })
    assert r_hack.status_code == 200
    res_hack = r_hack.json()
    assert res_hack["status"] == "ATTACK", f"Expected ATTACK, got {res_hack['status']}"
    assert res_hack["risk_score"] >= 50, f"Expected risk >= 50, got {res_hack['risk_score']}"
    assert res_hack["quarantined"] is True
    chain_after = client.get("/api/v1/ledger").json()["total_blocks"]
    assert chain_after == chain_before + 1, f"Expected ledger to append block: {chain_before} -> {chain_after}"
    print(f"  [PASS] HACK_WATCH_01 flagged as ATTACK (Risk: {res_hack['risk_score']}), quarantined, block added.")

    # 13. User Case 4: Device named SPOOF_WATCH -> SUSPICIOUS or ATTACK
    print("\n[TEST 13] Device named SPOOF_WATCH -> Flagged...")
    spoof_mac = random_mac(prefix="EE:33:44")
    r_spoof = client.get("/verify-device", params={
        "device_id": spoof_mac,
        "device_name": "SPOOF_WATCH",
        "device_type": 3,
        "rssi": -55,
        "timestamp": int(time.time())
    })
    assert r_spoof.status_code == 200
    res_spoof = r_spoof.json()
    assert res_spoof["status"] in ["SUSPICIOUS", "ATTACK"], f"Expected SUSPICIOUS/ATTACK, got {res_spoof['status']}"
    assert res_spoof["risk_score"] >= 20
    print(f"  [PASS] SPOOF_WATCH correctly flagged: Status={res_spoof['status']}, Risk={res_spoof['risk_score']}")

    # 14. User Case 5: Same MAC Changing Real Names ("Galaxy Watch" -> "Pixel Watch") -> SUSPICIOUS
    print("\n[TEST 14] Name Change Between Real Names (Galaxy Watch -> Pixel Watch)...")
    switch_mac = random_mac(prefix="DC:DA:0C")
    # Scan 1: Galaxy Watch
    r_sw1 = client.get("/verify-device", params={
        "device_id": switch_mac,
        "device_name": "Galaxy Watch",
        "device_type": 3,
        "rssi": -60,
        "timestamp": int(time.time())
    })
    assert r_sw1.status_code == 200
    # Scan 2: Pixel Watch (different real name)
    r_sw2 = client.get("/verify-device", params={
        "device_id": switch_mac,
        "device_name": "Pixel Watch",
        "device_type": 3,
        "rssi": -60,
        "timestamp": int(time.time())
    })
    assert r_sw2.status_code == 200
    res_sw2 = r_sw2.json()
    assert res_sw2["status"] in ["SUSPICIOUS", "ATTACK"]
    assert any("name changed" in r.get("reason", "").lower() for r in res_sw2.get("reasons", []))
    print(f"  [PASS] Real name change detected: Status={res_sw2['status']}, Risk={res_sw2['risk_score']}")

    # 15. User Case 6: RSSI Jump (-90 to -30 dBm) -> Flagged
    print("\n[TEST 15] RSSI Teleporting Jump (-90 dBm to -30 dBm)...")
    jump_mac = random_mac(prefix="DC:DA:0C")
    # Step 1: Baseline at -90 dBm
    client.get("/verify-device", params={
        "device_id": jump_mac,
        "device_name": "Galaxy Buds Pro",
        "device_type": 1,
        "rssi": -90,
        "timestamp": int(time.time())
    })
    # Step 2: Instant jump to -30 dBm (60 dBm diff > 40 dBm threshold)
    r_jump = client.get("/verify-device", params={
        "device_id": jump_mac,
        "device_name": "Galaxy Buds Pro",
        "device_type": 1,
        "rssi": -30,
        "timestamp": int(time.time())
    })
    assert r_jump.status_code == 200
    res_jump = r_jump.json()
    assert res_jump["status"] in ["SUSPICIOUS", "ATTACK"]
    assert any("rssi signal jump" in r.get("reason", "").lower() for r in res_jump.get("reasons", []))
    print(f"  [PASS] RSSI jump flagged: Status={res_jump['status']}, Risk={res_jump['risk_score']}")

    # 16. User Case 7: Request Flood (16 requests in window) -> Flagged
    print("\n[TEST 16] Request Flooding Attack Simulation...")
    flood_mac = random_mac(prefix="00:1A:7D")
    res_flood = None
    for i in range(16):
        r_fl = client.get("/verify-device", params={
            "device_id": flood_mac,
            "device_name": "Pixel Watch 2",
            "device_type": 3,
            "rssi": -65,
            "timestamp": int(time.time())
        })
        res_flood = r_fl.json()
    assert res_flood["status"] in ["SUSPICIOUS", "ATTACK"]
    assert any("high request rate" in r.get("reason", "").lower() for r in res_flood.get("reasons", []))
    print(f"  [PASS] Request flood flagged: Status={res_flood['status']}, Risk={res_flood['risk_score']}")

    # 17. User Case 8: 50 Random Benign Devices -> Zero SUSPICIOUS or ATTACK
    print("\n[TEST 17] 50 Random Benign Devices Scalability & False Positive Verification...")
    benign_flags = 0
    benign_names = ["Galaxy Watch 5", "AirPods Pro", "Fitbit Versa 3", "OnePlus Nord Buds 2", "Unknown_Device", ""]
    for i in range(50):
        b_mac = random_mac()
        b_name = random.choice(benign_names)
        b_rssi = random.randint(-92, -30)
        r_b = client.get("/verify-device", params={
            "device_id": b_mac,
            "device_name": b_name,
            "device_type": 1,
            "rssi": b_rssi,
            "timestamp": int(time.time())
        })
        assert r_b.status_code == 200
        b_res = r_b.json()
        if b_res["status"] in ["SUSPICIOUS", "ATTACK"]:
            benign_flags += 1
    assert benign_flags == 0, f"False positives detected! {benign_flags}/50 benign devices flagged"
    print("  [PASS] 50/50 benign devices passed with ZERO false positives (0 SUSPICIOUS, 0 ATTACK).")

    # 18. Name-Change False Positive & Retention (C0:09:D0:27:FD:0A)
    print("\n[TEST 18] Name Retention Rules (C0:09:D0:27:FD:0A)...")
    target_mac = "C0:09:D0:27:FD:0A"
    client.post(f"/api/v1/devices/{target_mac}/unblock")
    client.post(f"/api/v1/devices/{target_mac}/untrust")
    with db.get_db() as conn:
        conn.execute("DELETE FROM devices WHERE device_id = ?", (target_mac,))

    # First scan unnamed -> UNVERIFIED
    r1 = client.get("/verify-device", params={"device_id": target_mac, "device_name": "Unknown_Device", "device_type": 1, "rssi": -65})
    assert r1.json()["status"] == "UNVERIFIED"

    # Second scan real name -> SAFE / UNVERIFIED (No spoof penalty)
    r2 = client.get("/verify-device", params={"device_id": target_mac, "device_name": "Galaxy Watch 5", "device_type": 3, "rssi": -65})
    assert r2.json()["device_name"] == "Galaxy Watch 5"
    assert not any("name changed" in r.get("reason", "").lower() for r in r2.json().get("reasons", []))

    # Third scan blank -> Keeps "Galaxy Watch 5"
    r3 = client.get("/verify-device", params={"device_id": target_mac, "device_name": "", "device_type": 3, "rssi": -65})
    assert r3.json()["device_name"] == "Galaxy Watch 5"

    # Fourth scan DIFFERENT real name -> Flags name change
    r4 = client.get("/verify-device", params={"device_id": target_mac, "device_name": "Apple Watch Ultra", "device_type": 3, "rssi": -65})
    assert any("name changed" in r.get("reason", "").lower() for r in r4.json().get("reasons", []))
    print("  [PASS] Name retention and accurate spoofing detection confirmed.")

    # 19. Learn Environment Endpoint
    print("\n[TEST 19] Learn Environment Baseline Registration...")
    r_learn = client.post("/api/v1/system/learn-environment")
    assert r_learn.status_code == 200
    assert r_learn.json()["status"] == "SUCCESS"
    print(f"  [PASS] Learn Environment baseline established for {r_learn.json()['learned_devices']} devices.")

    # 20. Clear All Data & Reset Ledger
    print("\n[TEST 20] Clear Data & Reset Ledger Subsystems...")
    r_clear = client.post("/api/v1/system/clear-data")
    assert r_clear.status_code == 200
    assert client.get("/api/v1/stats").json()["devices"]["total"] == 0

    r_reset = client.post("/api/v1/ledger/reset")
    assert r_reset.status_code == 200
    assert client.get("/api/v1/ledger").json()["total_blocks"] == 1
    assert client.get("/api/v1/ledger/verify").json()["valid"] is True
    print("  [PASS] Clear Data and Ledger Reset verified successfully.")

    print("\n" + "=" * 60)
    print("  ALL 20 COMPREHENSIVE TEST SUITES PASSED! ZERO FALSE POSITIVES.")
    print("=" * 60)


if __name__ == "__main__":
    run_tests()

