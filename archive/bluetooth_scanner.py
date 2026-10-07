import asyncio
from bleak import BleakScanner
import requests
import time

API_URL = "http://127.0.0.1:8000/verify-device"

# Store blocked devices locally
blocked_devices = set()


async def scan_devices():

    print("\nScanning devices...\n")

    devices = await BleakScanner.discover(return_adv=True)

    for device, adv in devices.values():

        device_name = device.name or "Unknown_Device"
        device_id = device.address
        rssi = adv.rssi

        # Skip blocked devices
        if device_id in blocked_devices:
            print("Blocked device ignored:", device_id)
            continue

        payload = {
            "device_id": device_id,
            "device_name": device_name,
            "device_type": 1,
            "timestamp": int(time.time()),
            "rssi": rssi
        }

        try:
            response = requests.get(API_URL, params=payload)

            data = response.json()

            print("Device:", device_name)
            print("RSSI:", rssi)
            print("Security Check:", data)
            print("----------------------------------")

            # If server quarantines device → block locally
            if data.get("quarantined") == True:
                blocked_devices.add(device_id)
                print("Device added to blocklist:", device_id)

        except Exception as e:
            print("API error:", e)


async def main():

    while True:
        await scan_devices()

        # Wait before next scan
        await asyncio.sleep(50)


asyncio.run(main())