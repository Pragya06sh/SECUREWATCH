"""
SecureWatch Trusted Devices Configuration Manager
Handles persistent storage of user-whitelisted devices in trusted_devices.json.
"""
import os
import json
import time
import logging
from typing import Dict, Any, Optional
from config import TRUSTED_DEVICES_PATH

logger = logging.getLogger("securewatch.trusted")


def _ensure_file_exists():
    """Ensure trusted_devices.json exists with valid structure."""
    if not os.path.exists(TRUSTED_DEVICES_PATH):
        try:
            with open(TRUSTED_DEVICES_PATH, "w", encoding="utf-8") as f:
                json.dump({"version": "1.0", "devices": {}}, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to create trusted_devices.json: {e}")


def load_trusted_devices() -> Dict[str, Any]:
    """Load the mapping of trusted devices from the JSON config file."""
    _ensure_file_exists()
    try:
        with open(TRUSTED_DEVICES_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("devices", {})
    except Exception as e:
        logger.error(f"Failed to read trusted_devices.json: {e}")
        return {}


def save_trusted_devices(devices_map: Dict[str, Any]) -> bool:
    """Save the trusted devices dictionary to the JSON config file."""
    try:
        data = {
            "version": "1.0",
            "last_updated": time.time(),
            "devices": devices_map
        }
        with open(TRUSTED_DEVICES_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to write trusted_devices.json: {e}")
        return False


def is_device_trusted(device_id: str) -> bool:
    """Check if a MAC address / device ID is in the trusted devices config."""
    if not device_id:
        return False
    norm_id = device_id.strip().upper()
    trusted = load_trusted_devices()
    return norm_id in trusted


def add_trusted_device(device_id: str, device_name: str = "Known Device", notes: str = "") -> Dict[str, Any]:
    """Add or update a device in the trusted config file."""
    if not device_id:
        return {}
    norm_id = device_id.strip().upper()
    devices = load_trusted_devices()
    entry = {
        "device_id": norm_id,
        "device_name": device_name or "Known Device",
        "trusted_at": time.time(),
        "notes": notes or "Marked as trusted by user"
    }
    devices[norm_id] = entry
    save_trusted_devices(devices)
    logger.info(f"Device {norm_id} marked as trusted and saved to {TRUSTED_DEVICES_PATH}")
    return entry


def remove_trusted_device(device_id: str) -> bool:
    """Remove a device from the trusted config file."""
    if not device_id:
        return False
    norm_id = device_id.strip().upper()
    devices = load_trusted_devices()
    if norm_id in devices:
        del devices[norm_id]
        save_trusted_devices(devices)
        logger.info(f"Device {norm_id} removed from trusted configuration.")
        return True
    return False


def clear_trusted_devices() -> bool:
    """Clear all trusted devices from the JSON config file."""
    return save_trusted_devices({})

