"""
SecureWatch Simulation Engine
Generates a realistic continuous stream of Bluetooth devices
for demo/judging when real BLE hardware is unavailable.

Each scenario is designed to trigger specific detection responses.
"""
import random
import time
import asyncio
import logging
from config import SIMULATION_NORMAL_DEVICES, TRUSTED_MANUFACTURERS

logger = logging.getLogger("securewatch.simulation")

# ---- State ----
_running = False
_mode = "SIMULATION"  # or "LIVE_BLE"


def get_mode():
    return _mode


def set_mode(mode):
    global _mode
    _mode = mode


def is_running():
    return _running


def _random_rssi(base=-55, spread=15):
    """Realistic RSSI with some jitter."""
    return max(-95, min(-20, base + random.randint(-spread, spread)))


def _generate_normal_device():
    """Produce a single normal-looking device scan."""
    device = random.choice(SIMULATION_NORMAL_DEVICES)
    return {
        "device_id": device["mac"],
        "device_name": device["name"],
        "device_type": device["type"],
        "rssi": _random_rssi(base=-55, spread=12),
        "timestamp": int(time.time()),
    }


# ===================================================
# Attack Scenarios
# ===================================================

def scenario_spoofed_watch():
    """Scenario 1: Same MAC suddenly changes its name."""
    return [
        {
            "device_id": "AA:BB:CC:DD:EE:01",
            "device_name": "Galaxy Watch 5",
            "device_type": 3,
            "rssi": _random_rssi(-50, 5),
            "timestamp": int(time.time()),
        },
        {
            "device_id": "AA:BB:CC:DD:EE:01",
            "device_name": "SPOOF_Galaxy_Watch",
            "device_type": 3,
            "rssi": _random_rssi(-48, 5),
            "timestamp": int(time.time()),
        },
    ]


def scenario_request_flood():
    """Scenario 2: Rapid burst of requests from one device."""
    mac = "FF:EE:DD:CC:BB:02"
    devices = []
    for i in range(15):
        devices.append({
            "device_id": mac,
            "device_name": "SUS_Earbuds",
            "device_type": 1,
            "rssi": _random_rssi(-45, 3),
            "timestamp": int(time.time()),
        })
    return devices


def scenario_rssi_teleport():
    """Scenario 3: RSSI jumps 50+ dBm (impossible physically)."""
    mac = "11:22:33:44:55:03"
    return [
        {
            "device_id": mac,
            "device_name": "Pixel Watch",
            "device_type": 3,
            "rssi": -75,
            "timestamp": int(time.time()),
        },
        {
            "device_id": mac,
            "device_name": "Pixel Watch",
            "device_type": 3,
            "rssi": -20,  # Jump of 55 dBm
            "timestamp": int(time.time()),
        },
    ]


def scenario_malicious_name():
    """Scenario 4: Device with an obviously malicious name."""
    return [{
        "device_id": "99:88:77:66:55:04",
        "device_name": "HACK_WATCH_01",
        "device_type": 3,
        "rssi": _random_rssi(-40, 5),
        "timestamp": int(time.time()),
    }]


def scenario_unknown_lurker():
    """Scenario 5: Unknown manufacturer, very high signal strength."""
    return [{
        "device_id": "BA:DC:0F:FE:ED:05",
        "device_name": "Unknown_Device_X",
        "device_type": 2,
        "rssi": -25,  # Suspiciously strong
        "timestamp": int(time.time()),
    }]


def scenario_mixed_wave():
    """Scenario 6: Multiple simultaneous attack types."""
    devices = []
    # Spoofed watch
    devices.extend(scenario_spoofed_watch())
    # Malicious name
    devices.extend(scenario_malicious_name())
    # Unknown lurker
    devices.extend(scenario_unknown_lurker())
    # A few normal devices mixed in
    for _ in range(4):
        devices.append(_generate_normal_device())
    random.shuffle(devices)
    return devices


SCENARIOS = {
    "spoofed_watch": {
        "name": "Spoofed Smartwatch",
        "description": "Same MAC suddenly changes its device name",
        "func": scenario_spoofed_watch,
    },
    "request_flood": {
        "name": "Request Flood / DoS",
        "description": "Rapid burst of requests from a single device",
        "func": scenario_request_flood,
    },
    "rssi_teleport": {
        "name": "RSSI Teleport",
        "description": "Signal strength jumps 50+ dBm (physically impossible)",
        "func": scenario_rssi_teleport,
    },
    "malicious_name": {
        "name": "Malicious Device Name",
        "description": "Device broadcasting a clearly malicious name",
        "func": scenario_malicious_name,
    },
    "unknown_lurker": {
        "name": "Unknown Manufacturer Lurker",
        "description": "Unknown-manufacturer device at very high signal strength",
        "func": scenario_unknown_lurker,
    },
    "mixed_wave": {
        "name": "Mixed Attack Wave",
        "description": "Multiple simultaneous attack types with normal traffic",
        "func": scenario_mixed_wave,
    },
}


def generate_scenario(scenario_name: str):
    """Generate devices for a named scenario."""
    scenario = SCENARIOS.get(scenario_name)
    if not scenario:
        return []
    return scenario["func"]()


def generate_background_traffic(count=3):
    """Generate a small batch of normal background devices."""
    devices = []
    for _ in range(min(count, len(SIMULATION_NORMAL_DEVICES))):
        devices.append(_generate_normal_device())
    return devices
