import requests
import time
import random

SERVER = "http://127.0.0.1:8000/verify-device"

fake_devices = [
    "HACK_WATCH_01",
    "SPOOF_WATCH_02",
    "MALICIOUS_DEVICE"
]

while True:

    device = random.choice(fake_devices)

    params = {
        "device_id": "99:88:77:66",
        "device_name": device,
        "device_type": 3,
        "timestamp": int(time.time())
    }

    try:

        response = requests.get(SERVER, params=params)

        print("Attack request sent:", response.json())

    except:
        print("Server not reachable")

    time.sleep(1)