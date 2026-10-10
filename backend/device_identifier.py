"""
SecureWatch — Advanced BLE Device Identification Engine

Multi-layered identification using:
  1. Broadcast name
  2. Brand keywords in name (with company-ID cross-check)
  3. Bluetooth SIG company ID from manufacturer_data
  4. MAC OUI prefix (public addresses only)
  5. Service UUID category mapping

Provides: brand, device_type, how_identified, mac_address_type
NEVER invents or guesses a brand without evidence.
"""
import re
from typing import Optional, Dict, List, Any, Tuple


# ──────────────────────────────────────────────────────────
# Bluetooth SIG Assigned Company IDs  (top 300+ vendors)
# Source: https://www.bluetooth.com/specifications/assigned-numbers/
# Key = 16-bit company ID (int), Value = vendor name
# ──────────────────────────────────────────────────────────
BT_COMPANY_IDS: Dict[int, str] = {
    # Apple
    0x004C: "Apple",
    # Samsung
    0x0075: "Samsung",
    # Google
    0x00E0: "Google",
    # Microsoft
    0x0006: "Microsoft",
    # Xiaomi
    0x038F: "Xiaomi",
    # Huawei
    0x027D: "Huawei",
    # Sony
    0x012D: "Sony",
    0x054C: "Sony",
    # LG Electronics
    0x00C7: "LG Electronics",
    # Bose
    0x009E: "Bose",
    # JBL / Harman International
    0x0057: "Harman/JBL",
    0x0087: "Harman/JBL",
    # Qualcomm
    0x000A: "Qualcomm",
    0x001D: "Qualcomm",
    # Broadcom
    0x000F: "Broadcom",
    # Intel
    0x0002: "Intel",
    # Texas Instruments
    0x000D: "Texas Instruments",
    # Nordic Semiconductor
    0x0059: "Nordic Semiconductor",
    # Realtek
    0x005D: "Realtek",
    # MediaTek
    0x0046: "MediaTek",
    # Cypress / Infineon
    0x0131: "Cypress/Infineon",
    # Dialog Semiconductor
    0x00D2: "Dialog Semiconductor",
    # Silicon Labs
    0x02FF: "Silicon Labs",
    # STMicroelectronics
    0x0030: "STMicroelectronics",
    # NXP Semiconductors
    0x0025: "NXP",
    # Motorola
    0x0008: "Motorola",
    # Garmin
    0x0087: "Garmin",
    # Fitbit
    0x0224: "Fitbit",
    # Amazfit / Huami / Zepp
    0x0157: "Amazfit/Huami",
    # OnePlus / OPPO / Realme (BBK Electronics umbrella)
    0x0489: "OnePlus/OPPO",
    0x025E: "OPPO",
    # Vivo
    0x038B: "Vivo",
    # Realme
    0x042E: "Realme",
    # boAt (Imagine Marketing)
    0x0652: "boAt",
    # Noise (Nexxbase)
    0x0690: "Noise",
    # Jabra / GN Audio
    0x0069: "Jabra/GN",
    # Sennheiser
    0x00A0: "Sennheiser",
    # Bang & Olufsen
    0x0095: "Bang & Olufsen",
    # Skullcandy
    0x0183: "Skullcandy",
    # Beats (Apple subsidiary)
    0x0276: "Beats",
    # Anker / Soundcore
    0x02B5: "Anker/Soundcore",
    # Tile
    0x0215: "Tile",
    # Logitech
    0x0046: "Logitech",
    # Plantronics / Poly
    0x000E: "Plantronics/Poly",
    # HTC
    0x007C: "HTC",
    # Lenovo
    0x038A: "Lenovo",
    # Dell
    0x0382: "Dell",
    # HP Inc.
    0x0380: "HP",
    # ASUS
    0x03DA: "ASUS",
    # Panasonic
    0x0032: "Panasonic",
    # Philips
    0x0044: "Philips",
    # Xiaomi ecosystem brands
    0x0397: "Xiaomi",  # Alternate Xiaomi
    # Oppo sub-brands
    0x048E: "OnePlus",
    # Realtek audio
    0x0362: "Realtek",
    # Amazon
    0x0171: "Amazon",
    # Facebook / Meta
    0x0330: "Meta",
    # Fossil Group
    0x0237: "Fossil",
    # Suunto
    0x0256: "Suunto",
    # Polar Electro
    0x006B: "Polar",
    # Wahoo Fitness
    0x0234: "Wahoo",
    # Peloton
    0x0428: "Peloton",
    # Roku
    0x030E: "Roku",
    # Sonos
    0x02CA: "Sonos",
    # Marshall
    0x0310: "Marshall",
    # Audio-Technica
    0x0393: "Audio-Technica",
    # TOZO
    0x0588: "TOZO",
    # QCY
    0x05D7: "QCY",
    # Nothing (Carl Pei)
    0x0616: "Nothing",
    # CMF by Nothing
    0x0694: "CMF/Nothing",
    # Google (Fast Pair manager)
    0x00E0: "Google",
    # Raspberry Pi
    0x0482: "Raspberry Pi",
    # Espressif (ESP32)
    0x02E5: "Espressif",
    # Withings
    0x02D2: "Withings",
    # Oura
    0x04E2: "Oura",
    # WHOOP
    0x0467: "WHOOP",
    # Coros
    0x060A: "Coros",
    # Boult Audio
    0x0665: "Boult",
    # Mivi
    0x0672: "Mivi",
    # pTron
    0x0680: "pTron",
    # Zebronics
    0x068A: "Zebronics",
    # Fire-Boltt
    0x0695: "Fire-Boltt",
}


# ──────────────────────────────────────────────────────────
# Well-Known Service UUIDs → Device Category
# ──────────────────────────────────────────────────────────
SERVICE_UUID_CATEGORIES: Dict[str, Tuple[str, str]] = {
    # Standard BLE Services (16-bit UUIDs in 128-bit form)
    "0000180d-0000-1000-8000-00805f9b34fb": ("Health Monitor", "heart_rate"),
    "0000180f-0000-1000-8000-00805f9b34fb": ("Battery Service", "generic"),
    "00001812-0000-1000-8000-00805f9b34fb": ("HID Device", "input_device"),
    "0000181a-0000-1000-8000-00805f9b34fb": ("Environmental Sensor", "sensor"),
    "0000181c-0000-1000-8000-00805f9b34fb": ("Body Composition", "health"),
    "0000181e-0000-1000-8000-00805f9b34fb": ("Bond Management", "generic"),
    "00001822-0000-1000-8000-00805f9b34fb": ("Pulse Oximeter", "health"),
    "00001816-0000-1000-8000-00805f9b34fb": ("Cycling Sensor", "fitness"),
    "00001814-0000-1000-8000-00805f9b34fb": ("Running Sensor", "fitness"),
    "00001826-0000-1000-8000-00805f9b34fb": ("Fitness Machine", "fitness"),
    "00001810-0000-1000-8000-00805f9b34fb": ("Blood Pressure", "health"),
    "00001808-0000-1000-8000-00805f9b34fb": ("Glucose Monitor", "health"),
    "00001809-0000-1000-8000-00805f9b34fb": ("Thermometer", "health"),

    # Audio services
    "0000184e-0000-1000-8000-00805f9b34fb": ("Audio Stream", "audio"),
    "00001853-0000-1000-8000-00805f9b34fb": ("Common Audio", "audio"),
    "00001850-0000-1000-8000-00805f9b34fb": ("Published Audio", "audio"),

    # 16-bit custom short UUIDs (commonly seen as 0xFE2C etc.)
    "0000fe2c-0000-1000-8000-00805f9b34fb": ("Google Fast Pair", "earbuds"),
    "0000fd6f-0000-1000-8000-00805f9b34fb": ("Exposure Notification", "phone"),
    "0000fe9f-0000-1000-8000-00805f9b34fb": ("Google Eddystone", "beacon"),
    "0000feaa-0000-1000-8000-00805f9b34fb": ("Google Eddystone", "beacon"),

    # Apple Continuity / iBeacon related
    "7905f431-b5ce-4e99-a40f-4b1e122d00d0": ("Apple Continuity", "phone"),

    # Tile tracker
    "0000feed-0000-1000-8000-00805f9b34fb": ("Tile Tracker", "tracker"),
    "0000feec-0000-1000-8000-00805f9b34fb": ("Tile Tracker", "tracker"),

    # Samsung
    "0000fd5a-0000-1000-8000-00805f9b34fb": ("Samsung Service", "phone"),

    # Fitbit
    "adabfb00-6e7d-4601-bda2-bffaa68956ba": ("Fitbit Service", "watch"),

    # Garmin
    "6a4e3200-667b-11e3-949a-0800200c9a66": ("Garmin Service", "watch"),

    # Smart home / IoT
    "0000fe95-0000-1000-8000-00805f9b34fb": ("Xiaomi MiHome", "smart_home"),
    "0000fe61-0000-1000-8000-00805f9b34fb": ("Logitech Service", "input_device"),

    # TV / Media
    "0000fe67-0000-1000-8000-00805f9b34fb": ("TV Remote", "tv"),

    # Speakers
    "0000febe-0000-1000-8000-00805f9b34fb": ("Bose Service", "speaker"),

    # Generic GATT
    "00001800-0000-1000-8000-00805f9b34fb": ("Generic Access", "generic"),
    "00001801-0000-1000-8000-00805f9b34fb": ("Generic Attribute", "generic"),
}

# Short 16-bit UUID lookup (for convenience when scanner reports short form)
SERVICE_UUID_16BIT: Dict[int, Tuple[str, str]] = {
    0x180D: ("Heart Rate", "health"),
    0x180F: ("Battery Service", "generic"),
    0x1812: ("HID Device", "input_device"),
    0x181A: ("Environmental Sensor", "sensor"),
    0x1826: ("Fitness Machine", "fitness"),
    0x1810: ("Blood Pressure", "health"),
    0x1808: ("Glucose Monitor", "health"),
    0x1809: ("Thermometer", "health"),
    0x184E: ("Audio Stream", "audio"),
    0xFE2C: ("Google Fast Pair", "earbuds"),
    0xFD6F: ("Exposure Notification", "phone"),
    0xFE9F: ("Google Eddystone", "beacon"),
    0xFEAA: ("Google Eddystone", "beacon"),
    0xFEED: ("Tile Tracker", "tracker"),
    0xFE95: ("Xiaomi MiHome", "smart_home"),
    0xFD5A: ("Samsung Service", "phone"),
}


# ──────────────────────────────────────────────────────────
# Brand Keywords → Brand Name
# Searched in the broadcast name (case-insensitive)
# ──────────────────────────────────────────────────────────
BRAND_KEYWORDS: Dict[str, str] = {
    "airpods": "Apple",
    "iphone": "Apple",
    "ipad": "Apple",
    "macbook": "Apple",
    "apple watch": "Apple",
    "homepod": "Apple",
    "galaxy": "Samsung",
    "samsung": "Samsung",
    "buds pro": "Samsung",
    "buds2": "Samsung",
    "buds fe": "Samsung",
    "pixel": "Google",
    "google": "Google",
    "nest": "Google",
    "chromecast": "Google",
    "redmi": "Xiaomi",
    "xiaomi": "Xiaomi",
    "mi band": "Xiaomi",
    "poco": "Xiaomi",
    "oneplus": "OnePlus",
    "nord buds": "OnePlus",
    "oppo": "OPPO",
    "realme": "Realme",
    "vivo": "Vivo",
    "huawei": "Huawei",
    "honor": "Honor",
    "freebuds": "Huawei",
    "sony": "Sony",
    "wh-1000": "Sony",
    "wf-1000": "Sony",
    "linkbuds": "Sony",
    "bose": "Bose",
    "quietcomfort": "Bose",
    "soundsport": "Bose",
    "jbl": "JBL",
    "harman": "Harman",
    "boat": "boAt",
    "airdopes": "boAt",
    "rockerz": "boAt",
    "noise": "Noise",
    "colorfit": "Noise",
    "fitbit": "Fitbit",
    "versa": "Fitbit",
    "charge": "Fitbit",
    "garmin": "Garmin",
    "forerunner": "Garmin",
    "fenix": "Garmin",
    "venu": "Garmin",
    "amazfit": "Amazfit",
    "gts": "Amazfit",
    "bip": "Amazfit",
    "jabra": "Jabra",
    "sennheiser": "Sennheiser",
    "momentum": "Sennheiser",
    "bang": "Bang & Olufsen",
    "beoplay": "Bang & Olufsen",
    "skullcandy": "Skullcandy",
    "beats": "Beats",
    "powerbeats": "Beats",
    "soundcore": "Anker/Soundcore",
    "anker": "Anker",
    "tile": "Tile",
    "marshall": "Marshall",
    "nothing": "Nothing",
    "ear (2)": "Nothing",
    "ear (1)": "Nothing",
    "cmf": "CMF/Nothing",
    "boult": "Boult",
    "mivi": "Mivi",
    "ptron": "pTron",
    "zebronics": "Zebronics",
    "fire-boltt": "Fire-Boltt",
    "firebolt": "Fire-Boltt",
    "fossil": "Fossil",
    "suunto": "Suunto",
    "polar": "Polar",
    "wahoo": "Wahoo",
    "peloton": "Peloton",
    "echo": "Amazon",
    "kindle": "Amazon",
    "alexa": "Amazon",
    "roku": "Roku",
    "sonos": "Sonos",
    "tozo": "TOZO",
    "qcy": "QCY",
    "thinkpad": "Lenovo",
    "lenovo": "Lenovo",
    "dell": "Dell",
    "surface": "Microsoft",
    "xbox": "Microsoft",
    "logitech": "Logitech",
    "raspberry": "Raspberry Pi",
    "esp32": "Espressif",
    "withings": "Withings",
    "oura": "Oura",
    "whoop": "WHOOP",
    "coros": "Coros",
}


# ──────────────────────────────────────────────────────────
# Device Type Categories (keyword-based inference)
# ──────────────────────────────────────────────────────────
DEVICE_TYPE_KEYWORDS: Dict[str, str] = {
    "watch": "Smartwatch",
    "band": "Fitness Band",
    "fit": "Fitness Tracker",
    "tracker": "Tracker",
    "buds": "Earbuds",
    "pods": "Earbuds",
    "airpods": "Earbuds",
    "airdopes": "Earbuds",
    "earphone": "Earbuds",
    "headphone": "Headphones",
    "headset": "Headset",
    "speaker": "Speaker",
    "soundbar": "Soundbar",
    "phone": "Phone",
    "iphone": "Phone",
    "galaxy s": "Phone",
    "pixel": "Phone",
    "redmi": "Phone",
    "oneplus": "Phone",
    "ipad": "Tablet",
    "tab": "Tablet",
    "laptop": "Computer",
    "macbook": "Computer",
    "thinkpad": "Computer",
    "desktop": "Computer",
    "surface": "Computer",
    "tv": "TV",
    "echo": "Smart Speaker",
    "homepod": "Smart Speaker",
    "nest": "Smart Home",
    "chromecast": "Media Streamer",
    "roku": "Media Streamer",
    "tile": "Tracker",
    "tag": "Tracker",
    "mouse": "Mouse",
    "keyboard": "Keyboard",
    "controller": "Controller",
    "gamepad": "Controller",
    "xbox": "Controller",
    "scale": "Smart Scale",
    "thermometer": "Thermometer",
    "sensor": "Sensor",
    "beacon": "Beacon",
    "light": "Smart Light",
    "bulb": "Smart Light",
    "lock": "Smart Lock",
    "camera": "Camera",
    "printer": "Printer",
    "pen": "Stylus",
}

# Map service categories to device type labels
SERVICE_CATEGORY_TO_TYPE: Dict[str, str] = {
    "earbuds": "Earbuds",
    "audio": "Audio Device",
    "health": "Health Monitor",
    "heart_rate": "Health Monitor",
    "fitness": "Fitness Device",
    "watch": "Smartwatch",
    "phone": "Phone",
    "tracker": "Tracker",
    "speaker": "Speaker",
    "tv": "TV",
    "smart_home": "Smart Home",
    "input_device": "Input Device",
    "sensor": "Sensor",
    "beacon": "Beacon",
    "generic": None,  # Not specific enough
}

# Map device type labels to type icon emojis
DEVICE_TYPE_ICONS: Dict[str, str] = {
    "Smartwatch": "⌚",
    "Fitness Band": "⌚",
    "Fitness Tracker": "⌚",
    "Fitness Device": "🏃",
    "Earbuds": "🎧",
    "Headphones": "🎧",
    "Headset": "🎧",
    "Audio Device": "🎵",
    "Speaker": "🔊",
    "Smart Speaker": "🔊",
    "Soundbar": "🔊",
    "Phone": "📱",
    "Tablet": "📱",
    "Computer": "💻",
    "TV": "📺",
    "Media Streamer": "📺",
    "Tracker": "📍",
    "Smart Home": "🏠",
    "Smart Light": "💡",
    "Smart Lock": "🔒",
    "Smart Scale": "⚖️",
    "Mouse": "🖱️",
    "Keyboard": "⌨️",
    "Input Device": "🖱️",
    "Controller": "🎮",
    "Health Monitor": "❤️",
    "Sensor": "🌡️",
    "Thermometer": "🌡️",
    "Beacon": "📡",
    "Camera": "📷",
    "Printer": "🖨️",
    "Stylus": "✏️",
}


# ──────────────────────────────────────────────────────────
# MAC Address Type Detection
# ──────────────────────────────────────────────────────────
def classify_mac_type(mac: str) -> str:
    """
    Determine MAC address type from the two most-significant bits
    of the first octet.

    BLE address types (from Bluetooth Core Spec):
      - Public:              Multicast bit = 0, Local bit = 0  → bits 1:0 = 00
      - Random Static:       bits 7:6 = 11
      - Random Resolvable:   bits 7:6 = 01
      - Random Non-Resolvable: bits 7:6 = 00 AND local bit set

    Simplified heuristic for BLE advertisements:
      Check the first byte's two MSBs.
    """
    if not mac or len(mac) < 2:
        return "unknown"

    # Parse the first byte
    first_octet_str = mac.replace(":", "").replace("-", "")[:2]
    try:
        first_byte = int(first_octet_str, 16)
    except ValueError:
        return "unknown"

    # Check the "locally administered" bit (bit 1 of first octet, i.e., second-least-significant bit)
    is_local = bool(first_byte & 0x02)

    if not is_local:
        return "public"

    # It's a random/local address — check the two MSBs (bits 7 and 6)
    msb_two = (first_byte >> 6) & 0x03
    if msb_two == 0x03:  # 11
        return "random_static"
    elif msb_two == 0x01:  # 01
        return "resolvable_private"
    else:  # 00 or 10
        return "non_resolvable_private"


def mac_type_label(mac_type: str) -> str:
    """Human-readable label for MAC address type."""
    return {
        "public": "Public",
        "random_static": "Random Static",
        "resolvable_private": "Resolvable Private",
        "non_resolvable_private": "Non-Resolvable Private",
        "unknown": "Unknown",
    }.get(mac_type, "Unknown")


def mac_type_badge_color(mac_type: str) -> str:
    """CSS color class hint for the MAC type badge."""
    return {
        "public": "#10b981",            # green — OUI prefix is usable
        "random_static": "#f59e0b",     # amber
        "resolvable_private": "#f59e0b", # amber
        "non_resolvable_private": "#ef4444",  # red — fully anonymous
        "unknown": "#6b7280",
    }.get(mac_type, "#6b7280")


# ──────────────────────────────────────────────────────────
# Unified Device Identification Function
# ──────────────────────────────────────────────────────────

def identify_device(
    mac: str,
    local_name: Optional[str] = None,
    manufacturer_data: Optional[Dict[int, bytes]] = None,
    service_uuids: Optional[List[str]] = None,
    service_data: Optional[Dict[str, bytes]] = None,
    tx_power: Optional[int] = None,
    rssi: Optional[int] = None,
    oui_manufacturer: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Multi-layered device identification.

    Priority order:
      1. Broadcast name
      2. Brand keywords in name (with company-ID cross-check)
      3. Company ID from manufacturer_data
      4. MAC OUI prefix (public addresses only)
      5. Service UUID category

    Returns dict with:
      - brand: str or None
      - device_type: str or None (e.g. "Earbuds", "Smartwatch")
      - device_type_icon: str emoji
      - how_identified: str description of evidence
      - mac_type: str
      - mac_type_label: str
      - mac_type_color: str
      - company_ids: list of found company IDs
      - service_categories: list of matched service categories
    """
    brand = None
    device_type = None
    how_identified = None
    company_ids_found = []
    service_categories_found = []

    mac_type = classify_mac_type(mac)
    is_public_mac = (mac_type == "public")

    # Normalize name
    name = (local_name or "").strip()
    name_lower = name.lower() if name else ""

    # Extract company IDs from manufacturer_data
    if manufacturer_data:
        for cid in manufacturer_data:
            company_ids_found.append(cid)

    # Extract service categories from service_uuids
    if service_uuids:
        for uuid_str in service_uuids:
            uuid_norm = uuid_str.lower().strip()
            if uuid_norm in SERVICE_UUID_CATEGORIES:
                cat_name, cat_key = SERVICE_UUID_CATEGORIES[uuid_norm]
                service_categories_found.append((cat_name, cat_key))
            else:
                # Try matching as a short 16-bit UUID
                try:
                    if len(uuid_norm) == 4 or (len(uuid_norm) >= 6 and uuid_norm.startswith("0x")):
                        short_val = int(uuid_norm.replace("0x", ""), 16)
                        if short_val in SERVICE_UUID_16BIT:
                            cat_name, cat_key = SERVICE_UUID_16BIT[short_val]
                            service_categories_found.append((cat_name, cat_key))
                except (ValueError, TypeError):
                    pass

    # ─── Layer 1: Broadcast Name ───
    if name and name_lower not in ("unknown_device", "unknown", "none", "null", "n/a", ""):
        # ─── Layer 2: Brand Keywords in Name ───
        matched_brand_kw = None
        for keyword, kw_brand in BRAND_KEYWORDS.items():
            if keyword in name_lower:
                matched_brand_kw = (keyword, kw_brand)
                break

        if matched_brand_kw:
            keyword, kw_brand = matched_brand_kw

            # Cross-check with company ID if available
            if company_ids_found:
                for cid in company_ids_found:
                    if cid in BT_COMPANY_IDS:
                        cid_vendor = BT_COMPANY_IDS[cid]
                        # Check if the company ID vendor is consistent with the keyword brand
                        if _brands_match(kw_brand, cid_vendor):
                            brand = kw_brand
                            how_identified = f"Name keyword '{keyword}' + Company ID 0x{cid:04X} ({cid_vendor})"
                            break
                if not brand:
                    # Company ID exists but doesn't match — still use keyword
                    # (device might use a chipset from different vendor)
                    brand = kw_brand
                    how_identified = f"Name keyword '{keyword}'"
            else:
                brand = kw_brand
                how_identified = f"Name keyword '{keyword}'"
        else:
            # Name present but no known keyword match
            how_identified = f"Broadcast name '{name}'"

    # ─── Layer 3: Company ID from manufacturer_data ───
    if not brand and company_ids_found:
        for cid in company_ids_found:
            if cid in BT_COMPANY_IDS:
                brand = BT_COMPANY_IDS[cid]
                how_identified = f"Company ID 0x{cid:04X} = {brand}"
                break

    # ─── Layer 4: MAC OUI Prefix (public addresses only) ───
    if not brand and is_public_mac and oui_manufacturer and oui_manufacturer != "Unknown":
        brand = oui_manufacturer
        how_identified = f"MAC OUI prefix ({mac[:8]})"

    # ─── Layer 5: Service UUID Category ───
    if not brand and service_categories_found:
        # Service UUIDs can hint at device type but rarely identify brand
        pass  # Brand stays None; device_type may be set below

    # ─── Device Type Inference ───
    # From name keywords
    if name_lower:
        for type_kw, type_label in DEVICE_TYPE_KEYWORDS.items():
            if type_kw in name_lower:
                device_type = type_label
                break

    # From service categories if type not determined from name
    if not device_type and service_categories_found:
        for cat_name, cat_key in service_categories_found:
            mapped_type = SERVICE_CATEGORY_TO_TYPE.get(cat_key)
            if mapped_type:
                device_type = mapped_type
                if not how_identified:
                    how_identified = f"Service UUID: {cat_name}"
                break

    # Determine icon
    device_type_icon = DEVICE_TYPE_ICONS.get(device_type, "📶") if device_type else "📶"

    # If nothing identified at all
    if not brand and not how_identified:
        how_identified = "Device hides its name and vendor for privacy"

    return {
        "brand": brand,
        "device_type": device_type,
        "device_type_icon": device_type_icon,
        "how_identified": how_identified,
        "mac_type": mac_type,
        "mac_type_label": mac_type_label(mac_type),
        "mac_type_color": mac_type_badge_color(mac_type),
        "company_ids": company_ids_found,
        "service_categories": [(n, k) for n, k in service_categories_found],
    }


def _brands_match(brand_a: str, brand_b: str) -> bool:
    """Check if two brand names refer to the same company (fuzzy)."""
    if not brand_a or not brand_b:
        return False
    a = brand_a.lower().replace("/", " ").replace("-", " ")
    b = brand_b.lower().replace("/", " ").replace("-", " ")

    # Direct match
    if a == b:
        return True

    # Check if one contains the other
    if a in b or b in a:
        return True

    # BBK Electronics umbrella: OnePlus, OPPO, Realme, Vivo
    bbk_brands = {"oneplus", "oppo", "realme", "vivo"}
    if any(x in a for x in bbk_brands) and any(x in b for x in bbk_brands):
        return True

    # Apple ecosystem: Apple, Beats
    apple_brands = {"apple", "beats"}
    if any(x in a for x in apple_brands) and any(x in b for x in apple_brands):
        return True

    # Xiaomi ecosystem
    xiaomi_brands = {"xiaomi", "amazfit", "huami", "poco", "redmi"}
    if any(x in a for x in xiaomi_brands) and any(x in b for x in xiaomi_brands):
        return True

    return False


def infer_device_type_code(device_type_str: Optional[str]) -> int:
    """Map a device type string to the legacy integer type code."""
    if not device_type_str:
        return 0
    dt = device_type_str.lower()
    if any(w in dt for w in ["watch", "band", "fitness", "tracker", "health"]):
        return 3  # Wearable
    if any(w in dt for w in ["earbuds", "headphone", "headset", "audio", "speaker", "soundbar"]):
        return 1  # Audio
    if any(w in dt for w in ["phone", "tablet", "computer"]):
        return 2  # Phone/Computer
    if any(w in dt for w in ["tv", "media", "smart home", "smart light", "smart lock"]):
        return 4  # IoT
    return 0
