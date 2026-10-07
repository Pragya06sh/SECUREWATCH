import asyncio
from bleak import BleakScanner
import requests
import time

API_URL = "http://127.0.0.1:8000/verify-device"

blocked_devices = set()

# ----------------------------------
# Trusted Devices (ADD YOUR MACS)
# ----------------------------------

trusted_devices = {

    # Example — replace with your real ones
    "DC:DA:0C:D4:55:3D": "Smartwatch",
    "08:59:5E:CA:B5:EC": "Earbuds",

}

# ----------------------------------
# Manufacturer Detection
# ----------------------------------

def get_manufacturer(mac):

    prefix = mac[0:8]

    manufacturers = {

        "DC:DA:0C": "Samsung",
        "F4:7D:EF": "Samsung",

        "A4:C1:38": "Apple",

        "08:59:5E": "Realme",

        # boAt / Noise prefixes (common)
        "40:ED:98": "boAt",
        "70:2C:1F": "boAt",
        "C8:FD:19": "Noise",
        "E8:4E:06": "Noise"

    }

    return manufacturers.get(prefix, "Unknown")

# ----------------------------------
# Device Trust Classification
# ----------------------------------

def classify_device(device_id):

    if device_id in trusted_devices:
        return "SAFE"

    else:
        return "UNSAFE"

# ----------------------------------
# Scanner
# ----------------------------------

async def scan_devices():

    print("Scanning for Bluetooth devices...\n")

    while True:

        devices = await BleakScanner.discover(return_adv=True)

        for device, adv in devices.values():

            device_name = device.name

            if not device_name:
                device_name = adv.local_name

            if not device_name:
                device_name = "Unknown_Device"

            device_id = device.address
            rssi = adv.rssi

            if device_id in blocked_devices:
                print("Blocked device ignored:", device_id)
                continue

            manufacturer = get_manufacturer(device_id)

            # SAFE / UNSAFE logic
            trust_status = classify_device(device_id)

            print("Device Name:", device_name)
            print("Manufacturer:", manufacturer)
            print("MAC Address:", device_id)
            print("RSSI:", rssi)
            print("Trust Status:", trust_status)

            # Send only trusted to API
            try:

                response = requests.get(
                    API_URL,
                    params={
                        "device_id": device_id,
                        "device_name": device_name,
                        "device_type": 1,
                        "timestamp": int(time.time()),
                        "rssi": rssi
                    }
                )

                result = response.json()

                print("Security Status:",
                      result["security_status"])

                if trust_status == "UNSAFE":

                    blocked_devices.add(device_id)

                    print("⚠️ Unsafe device blocked")

            except Exception as e:
                print("API Error:", e)

            print("-------------------------")

        await asyncio.sleep(5)

asyncio.run(scan_devices())