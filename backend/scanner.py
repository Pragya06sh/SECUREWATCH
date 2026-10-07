"""
SecureWatch — BLE Hardware & Simulation Edge Scanner
Discovers nearby Bluetooth/BLE devices, extracts telemetry (RSSI, MAC, Device Name, Type),
sends to SecureWatch Backend (/verify-device), and enforces local quarantine blocks.
"""
import sys
import time
import asyncio
import logging
import requests

from config import (
    API_KEY,
    TRUSTED_MANUFACTURERS,
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


async def scan_ble_hardware():
    """Perform a live scan using Bleak."""
    try:
        from bleak import BleakScanner
    except ImportError:
        logger.error("Bleak is not installed. Install with: pip install bleak")
        return None

    try:
        devices = await BleakScanner.discover(timeout=5.0, return_adv=True)
        results = []
        for device, adv in devices.values():
            name = device.name or adv.local_name or "Unknown_Device"
            results.append({
                "device_id": device.address,
                "device_name": name,
                "device_type": infer_device_type(name),
                "rssi": adv.rssi if adv.rssi is not None else -70,
                "timestamp": int(time.time()),
            })
        return results
    except Exception as e:
        logger.warning(f"BLE hardware scan failed ({e}). Ensure Bluetooth is enabled.")
        return None


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


async def run_scanner(poll_interval: float = 6.0):
    """Main scanner loop with live BLE or fallback warning."""
    print("=" * 60)
    print("  SECUREWATCH EDGE SCANNER ENGINE")
    print("=" * 60)
    
    alive = await check_backend_alive()
    if not alive:
        print("[!] Warning: SecureWatch backend (http://127.0.0.1:8000) is currently offline.")
        print("    Please start the backend server: uvicorn main:app --reload")
        print("=" * 60)

    print("[*] Initializing Bluetooth scanner loop (interval: %ss)..." % poll_interval)

    while True:
        try:
            print(f"\n[*] Scanning for nearby BLE broadcasts...")
            scanned = await scan_ble_hardware()

            if scanned is None:
                print("[-] BLE Hardware unavailable or no adapter. You can also run the web dashboard's Simulation Engine.")
                await asyncio.sleep(poll_interval * 2)
                continue

            print(f"[+] Found {len(scanned)} Bluetooth device(s).")

            for dev in scanned:
                mac = dev["device_id"]
                name = dev["device_name"]
                rssi = dev["rssi"]

                if mac in local_quarantine:
                    print(f" [BLOCKED] Skipping quarantined device: {name} [{mac}]")
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

                print(f" -> {tag:<24} {name:<22} MAC: {mac:<18} RSSI: {rssi:>4}dBm  Rep: {reputation:>5.1f}")
                
                if quarantined:
                    print(f"    >>> QUARANTINE ENFORCED on {mac}")

        except Exception as e:
            logger.error(f"Unexpected scanner exception: {e}")

        await asyncio.sleep(poll_interval)


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