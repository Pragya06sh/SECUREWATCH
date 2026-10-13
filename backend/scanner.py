"""
SecureWatch — BLE Continuous Scanner with Rich Advertisement Parsing

Uses a continuous BleakScanner with detection callbacks to capture
every advertisement and merge fields across multiple packets from the
same MAC address (the name often arrives in a different packet than
the manufacturer data).

Collects: local name, manufacturer_data (Bluetooth SIG company IDs),
service_uuids, service_data, tx_power, RSSI — then runs multi-layered
device identification before forwarding to the backend.

Devices remain visible for 60 seconds after their last advertisement.
"""
import sys
import time
import asyncio
import logging
import requests
from typing import Dict, Optional, Any

from config import (
    API_KEY,
    TRUSTED_MANUFACTURERS,
)
from device_identifier import (
    identify_device,
    classify_mac_type,
    mac_type_label,
    infer_device_type_code,
    BT_COMPANY_IDS,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] scanner: %(message)s"
)
logger = logging.getLogger("securewatch.scanner")

BACKEND_URL = "http://127.0.0.1:8000/verify-device"
STATUS_URL = "http://127.0.0.1:8000/api/v1/system/health"

# Local cache of quarantined devices
local_quarantine = set()

# Merged device state — keyed by MAC address
# Stores accumulated advertisement fields across multiple callbacks
_merged_devices: Dict[str, Dict[str, Any]] = {}

# Visibility window (seconds) — device stays visible after last adv
DEVICE_VISIBILITY_SECONDS = 60


# ──────────────────────────────────────────────────────────
# Advertisement Merging
# ──────────────────────────────────────────────────────────
def _merge_advertisement(mac: str, name: Optional[str], adv_data: dict):
    """
    Merge fields from a new advertisement into the accumulated state
    for a device identified by MAC.  Fields are never overwritten with
    empty/None values — only enriched.
    """
    now = time.time()
    if mac not in _merged_devices:
        _merged_devices[mac] = {
            "mac": mac,
            "local_name": None,
            "manufacturer_data": {},
            "service_uuids": set(),
            "service_data": {},
            "tx_power": None,
            "rssi_values": [],
            "first_seen": now,
            "last_seen": now,
        }

    dev = _merged_devices[mac]
    dev["last_seen"] = now

    # Merge name (prefer non-empty)
    if name and name.strip() and name.strip().lower() not in ("unknown_device", "unknown"):
        dev["local_name"] = name.strip()

    # Merge manufacturer_data (company_id → payload)
    mfr_data = adv_data.get("manufacturer_data")
    if mfr_data:
        for company_id, payload in mfr_data.items():
            dev["manufacturer_data"][company_id] = payload

    # Merge service_uuids
    svc_uuids = adv_data.get("service_uuids")
    if svc_uuids:
        for uuid_str in svc_uuids:
            dev["service_uuids"].add(uuid_str.lower())

    # Merge service_data
    svc_data = adv_data.get("service_data")
    if svc_data:
        for uuid_str, payload in svc_data.items():
            dev["service_data"][uuid_str.lower()] = payload

    # TX Power (take latest non-None)
    tx = adv_data.get("tx_power")
    if tx is not None:
        dev["tx_power"] = tx

    # RSSI
    rssi = adv_data.get("rssi")
    if rssi is not None:
        dev["rssi_values"].append(rssi)
        # Keep only last 10
        if len(dev["rssi_values"]) > 10:
            dev["rssi_values"] = dev["rssi_values"][-10:]


def _get_visible_devices() -> list:
    """Return devices seen within the visibility window, sorted by last_seen."""
    cutoff = time.time() - DEVICE_VISIBILITY_SECONDS
    visible = [d for d in _merged_devices.values() if d["last_seen"] >= cutoff]
    visible.sort(key=lambda d: d["last_seen"], reverse=True)
    return visible


def _get_unique_device_count() -> int:
    """Count devices seen in the last DEVICE_VISIBILITY_SECONDS."""
    cutoff = time.time() - DEVICE_VISIBILITY_SECONDS
    return sum(1 for d in _merged_devices.values() if d["last_seen"] >= cutoff)


def _evict_stale_devices():
    """Remove devices not seen for > 5 minutes to prevent unbounded memory."""
    cutoff = time.time() - 300
    stale = [mac for mac, d in _merged_devices.items() if d["last_seen"] < cutoff]
    for mac in stale:
        del _merged_devices[mac]


# ──────────────────────────────────────────────────────────
# Legacy Type Inference (from name)
# ──────────────────────────────────────────────────────────
def infer_device_type(name: str) -> int:
    """Heuristic mapping from device name to integer type."""
    if not name:
        return 0
    name_l = name.lower()
    if any(w in name_l for w in ["watch", "band", "gear", "fit", "tracker", "wear"]):
        return 3  # Smartwatch/Wearable
    if any(w in name_l for w in ["pod", "buds", "ear", "headphone", "audio", "airpods", "tune", "sound"]):
        return 1  # Audio / Earbuds
    if any(w in name_l for w in ["phone", "galaxy", "pixel", "iphone", "redmi", "oneplus", "ipad", "tab"]):
        return 2  # Phone / Tablet
    if any(w in name_l for w in ["macbook", "laptop", "pc", "desktop", "thinkpad", "dell"]):
        return 4  # Computer
    return 0


async def check_backend_alive():
    """Verify backend API is accessible."""
    try:
        r = requests.get(STATUS_URL, timeout=2.0)
        return r.status_code == 200
    except Exception:
        return False


def send_to_backend(device_data: dict) -> dict:
    """Send device scan payload to SecureWatch backend."""
    try:
        resp = requests.get(
            BACKEND_URL,
            params={
                "device_id": device_data["device_id"],
                "device_name": device_data["device_name"],
                "device_type": device_data["device_type"],
                "timestamp": device_data["timestamp"],
                "rssi": device_data["rssi"],
            },
            timeout=3.0
        )
        if resp.status_code == 200:
            return resp.json()
        else:
            logger.error(f"Backend error {resp.status_code}: {resp.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to reach backend at {BACKEND_URL}: {e}")
    return None


# ──────────────────────────────────────────────────────────
# Continuous BLE Scanner
# ──────────────────────────────────────────────────────────
async def scan_ble_continuous(duration: float = 10.0):
    """
    Run a continuous BleakScanner with a detection callback for `duration` seconds.
    Merges advertisement fields across multiple packets from each device.
    Returns a list of fully-identified device dicts.
    """
    try:
        from bleak import BleakScanner
    except ImportError:
        logger.error("Bleak is not installed. Install with: pip install bleak")
        return None

    def _detection_callback(device, advertisement_data):
        """Called for every single BLE advertisement received."""
        mac = device.address
        name = device.name or advertisement_data.local_name

        adv_dict = {
            "manufacturer_data": dict(advertisement_data.manufacturer_data) if advertisement_data.manufacturer_data else {},
            "service_uuids": list(advertisement_data.service_uuids) if advertisement_data.service_uuids else [],
            "service_data": {str(k): v for k, v in advertisement_data.service_data.items()} if advertisement_data.service_data else {},
            "tx_power": advertisement_data.tx_power,
            "rssi": advertisement_data.rssi,
        }

        _merge_advertisement(mac, name, adv_dict)

    scanner = BleakScanner(detection_callback=_detection_callback)

    try:
        await scanner.start()
        await asyncio.sleep(duration)
        await scanner.stop()
    except Exception as e:
        logger.warning(f"BLE continuous scan failed ({e}). Ensure Bluetooth is enabled.")
        return None

    # Build results from merged device state
    from detection_engine import get_manufacturer
    results = []
    for dev in _get_visible_devices():
        mac = dev["mac"]
        oui_mfr = get_manufacturer(mac)

        identification = identify_device(
            mac=mac,
            local_name=dev["local_name"],
            manufacturer_data=dev["manufacturer_data"],
            service_uuids=list(dev["service_uuids"]),
            service_data=dev["service_data"],
            tx_power=dev["tx_power"],
            oui_manufacturer=oui_mfr,
        )

        name = dev["local_name"] or "Unknown_Device"
        latest_rssi = dev["rssi_values"][-1] if dev["rssi_values"] else -70

        # Use identification to determine device type code
        type_code = infer_device_type_code(identification["device_type"])
        if type_code == 0:
            type_code = infer_device_type(name)

        results.append({
            "device_id": mac,
            "device_name": name,
            "device_type": type_code,
            "rssi": latest_rssi,
            "timestamp": int(time.time()),
            "brand": identification["brand"],
            "device_type_str": identification["device_type"],
            "device_type_icon": identification["device_type_icon"],
            "how_identified": identification["how_identified"],
            "mac_type": identification["mac_type"],
            "mac_type_label": identification["mac_type_label"],
            "mac_type_color": identification["mac_type_color"],
            "company_ids": identification["company_ids"],
            "service_categories": identification["service_categories"],
            "tx_power": dev["tx_power"],
            "last_seen": dev["last_seen"],
            "first_seen": dev["first_seen"],
            "manufacturer_data_keys": list(dev["manufacturer_data"].keys()),
            "service_uuids": list(dev["service_uuids"]),
        })

    return results


# ──────────────────────────────────────────────────────────
# Fallback: One-shot discover scan (original approach)
# ──────────────────────────────────────────────────────────
async def scan_ble_hardware():
    """Perform a live scan using Bleak (fallback one-shot)."""
    try:
        from bleak import BleakScanner
    except ImportError:
        logger.error("Bleak is not installed. Install with: pip install bleak")
        return None

    try:
        devices = await BleakScanner.discover(timeout=5.0, return_adv=True)
        from detection_engine import get_manufacturer

        results = []
        for device, adv in devices.values():
            mac = device.address
            name = device.name or adv.local_name or "Unknown_Device"

            # Merge into our global state
            adv_dict = {
                "manufacturer_data": dict(adv.manufacturer_data) if adv.manufacturer_data else {},
                "service_uuids": list(adv.service_uuids) if adv.service_uuids else [],
                "service_data": {str(k): v for k, v in adv.service_data.items()} if adv.service_data else {},
                "tx_power": adv.tx_power,
                "rssi": adv.rssi,
            }
            _merge_advertisement(mac, name, adv_dict)

            # Identify
            oui_mfr = get_manufacturer(mac)
            identification = identify_device(
                mac=mac,
                local_name=name if name != "Unknown_Device" else None,
                manufacturer_data=adv_dict["manufacturer_data"],
                service_uuids=adv_dict["service_uuids"],
                service_data=adv_dict["service_data"],
                tx_power=adv_dict["tx_power"],
                oui_manufacturer=oui_mfr,
            )

            type_code = infer_device_type_code(identification["device_type"])
            if type_code == 0:
                type_code = infer_device_type(name)

            results.append({
                "device_id": mac,
                "device_name": name,
                "device_type": type_code,
                "rssi": adv.rssi if adv.rssi is not None else -70,
                "timestamp": int(time.time()),
                "brand": identification["brand"],
                "device_type_str": identification["device_type"],
                "device_type_icon": identification["device_type_icon"],
                "how_identified": identification["how_identified"],
                "mac_type": identification["mac_type"],
                "mac_type_label": identification["mac_type_label"],
                "mac_type_color": identification["mac_type_color"],
                "company_ids": identification["company_ids"],
                "service_categories": identification["service_categories"],
            })
        return results
    except Exception as e:
        logger.warning(f"BLE hardware scan failed ({e}). Ensure Bluetooth is enabled.")
        return None


# ──────────────────────────────────────────────────────────
# Main Scanner Loop
# ──────────────────────────────────────────────────────────
async def run_scanner(poll_interval: float = 6.0):
    """Main scanner loop with continuous BLE scanning."""
    print("=" * 72)
    print("  SECUREWATCH EDGE SCANNER ENGINE — ADVANCED DEVICE IDENTIFICATION")
    print("=" * 72)

    alive = await check_backend_alive()
    if not alive:
        print("[!] Warning: SecureWatch backend (http://127.0.0.1:8000) is currently offline.")
        print("    Please start the backend server: uvicorn main:app --reload")
        print("=" * 72)

    print("[*] Initializing continuous BLE scanner (scan window: %ss)..." % poll_interval)
    print("[i] Only devices that are broadcasting can be seen. Connected devices stay silent.")

    use_continuous = True
    scan_cycle = 0

    while True:
        try:
            scan_cycle += 1
            unique_count = _get_unique_device_count()
            print(f"\n{'─' * 72}")
            print(f"[*] Scan cycle #{scan_cycle} | Unique devices in last 60s: {unique_count}")
            print(f"[i] Only devices that are broadcasting can be seen. Connected devices stay silent.")

            if use_continuous:
                scanned = await scan_ble_continuous(duration=poll_interval)
            else:
                scanned = await scan_ble_hardware()

            if scanned is None:
                print("[-] BLE Hardware unavailable or no adapter. Trying fallback...")
                if use_continuous:
                    use_continuous = False
                    scanned = await scan_ble_hardware()
                if scanned is None:
                    print("[-] No BLE adapter found. Run the web dashboard's Simulation Engine instead.")
                    await asyncio.sleep(poll_interval * 2)
                    continue

            print(f"[+] Captured {len(scanned)} device(s) in this cycle.")

            # Print identification table
            if scanned:
                print(f"\n  {'Name':<22} {'Brand':<16} {'Type':<14} {'MAC Type':<12} {'RSSI':>5}  How Identified")
                print(f"  {'─'*22} {'─'*16} {'─'*14} {'─'*12} {'─'*5}  {'─'*30}")

            for dev in scanned:
                mac = dev["device_id"]
                name = dev["device_name"]
                rssi = dev["rssi"]
                brand = dev.get("brand") or "Unidentified"
                dev_type = dev.get("device_type_str") or "—"
                mac_type_str = dev.get("mac_type_label", "?")
                how = dev.get("how_identified", "")

                icon = dev.get("device_type_icon", "📶")
                print(f"  {name:<22} {brand:<16} {icon} {dev_type:<12} {mac_type_str:<12} {rssi:>5}  {how}")

                if mac in local_quarantine:
                    print(f"    [BLOCKED] Skipping quarantined device: {name} [{mac}]")
                    continue

                res = send_to_backend(dev)
                if not res:
                    continue

                status = res.get("security_status", "UNKNOWN")
                risk = res.get("risk_score", 0)
                reputation = res.get("reputation", 100)
                quarantined = res.get("quarantined", False)

                tag = f"[{status}]"
                if status == "ATTACK":
                    tag = f"[ALERT: ATTACK - RISK {risk}]"
                    local_quarantine.add(mac)
                elif status == "SUSPICIOUS":
                    tag = f"[WARN: SUSP - RISK {risk}]"
                elif status == "UNVERIFIED":
                    tag = f"[UNVERIFIED - NOMINAL]"
                elif status == "SAFE":
                    tag = f"[SAFE - VERIFIED]"

                print(f"    → {tag:<24} MAC: {mac:<18} Rep: {reputation:>5.1f}")

                if quarantined:
                    print(f"      >>> QUARANTINE ENFORCED on {mac}")

            # Evict stale entries
            _evict_stale_devices()

        except Exception as e:
            logger.error(f"Unexpected scanner exception: {e}")

        await asyncio.sleep(1.0)  # Short sleep between continuous scan cycles


if __name__ == "__main__":
    interval = 6.0
    if len(sys.argv) > 1:
        try:
            interval = float(sys.argv[1])
        except ValueError:
            pass
    try:
        asyncio.run(run_scanner(poll_interval=interval))
    except KeyboardInterrupt:
        print("\nScanner stopped by user.")