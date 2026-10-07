"""
SecureWatch Configuration
All detection thresholds, paths, and settings in one place.
"""
import os

# ----------------------------------
# Paths
# ----------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_PATH = os.path.join(BASE_DIR, "securewatch.db")
BLOCKCHAIN_PATH = os.path.join(BASE_DIR, "blockchain_logs.json")
METRICS_PATH = os.path.join(MODELS_DIR, "metrics.json")
TRUSTED_DEVICES_PATH = os.path.join(BASE_DIR, "trusted_devices.json")
OUI_CSV_PATH = os.path.join(DATA_DIR, "oui_vendors.csv")

# ----------------------------------
# Server
# ----------------------------------
API_KEY = os.environ.get("SECUREWATCH_API_KEY", "securewatch-demo-key-2024")
CORS_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
]

# ----------------------------------
# Detection Thresholds & Weights
# ----------------------------------
# Activity window: seconds of history to track per device
ACTIVITY_WINDOW_SECONDS = 10

# Request count thresholds
REQUEST_COUNT_SUSPICIOUS = 15  # 15+ requests/advertisements in window = flood
REQUEST_COUNT_ATTACK = 25      # Extreme flood

# RSSI thresholds
RSSI_JUMP_THRESHOLD = 40  # dBm jump between consecutive readings = teleporting spoof
RSSI_HISTORY_LENGTH = 10  # how many RSSI values to keep per device

# Risk score contributions (Purely Behavioural or Explicit Evidence)
RISK_SUSPICIOUS_NAME = 40        # Malicious keywords in name
RISK_REQUEST_FLOOD = 30          # Request flood above threshold
RISK_RSSI_SPOOF = 35             # RSSI jump 40+ dBm
RISK_FINGERPRINT_CHANGE = 30     # Real name changed to different real name
RISK_IMPERSONATION = 35          # Brand claiming without matching vendor OUI
RISK_AI_FLAG = 20                # ML anomaly (only with at least one other behavioural signal)

# Explicit zero-penalty items (Missing identity alone NEVER causes risk)
RISK_UNKNOWN_MANUFACTURER = 0    # 0 points for unknown OUI / missing identity
RISK_NO_NAME = 0                 # 0 points for empty / Unknown_Device name
RISK_RANDOM_MAC = 0              # 0 points for randomized MAC
RISK_STATIC_RSSI = 0             # 0 points for static high or low RSSI

# Risk classification boundaries
RISK_THRESHOLD_SUSPICIOUS = 20   # 20 to 49 = SUSPICIOUS
RISK_THRESHOLD_ATTACK = 50       # 50+ = ATTACK

# Status definitions
STATUS_SAFE = "SAFE"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_SUSPICIOUS = "SUSPICIOUS"
STATUS_ATTACK = "ATTACK"
STATUS_BLOCKED = "BLOCKED"

# Reputation
REPUTATION_INITIAL = 100
REPUTATION_FLOOR = 0
REPUTATION_CEILING = 100
REPUTATION_DECAY_FACTOR = 0.1
REPUTATION_RECOVERY_RATE = 0.5  # per safe scan

# ----------------------------------
# Suspicious & Malicious keywords in device names
# ----------------------------------
CRITICAL_KEYWORDS = ["hack", "evil", "attack", "malicious", "exploit", "trojan"]
SUSPICIOUS_KEYWORDS = ["spoof", "fake", "rogue", "inject"]
ALL_KEYWORDS = CRITICAL_KEYWORDS + SUSPICIOUS_KEYWORDS

# ----------------------------------
# Brand Impersonation Keyword to Vendor Mapping
# ----------------------------------
BRAND_VENDOR_MAP = {
    "galaxy": "Samsung",
    "samsung": "Samsung",
    "apple": "Apple",
    "iphone": "Apple",
    "airpod": "Apple",
    "iwatch": "Apple",
    "pixel": "Google",
    "fitbit": "Fitbit",
    "oneplus": "OnePlus",
    "nord": "OnePlus",
    "realme": "Realme",
    "xiaomi": "Xiaomi",
    "redmi": "Xiaomi",
    "garmin": "Garmin",
    "boat": "boAt",
    "noise": "Noise",
}

# ----------------------------------
# Known Manufacturer OUI Prefixes
# ----------------------------------
TRUSTED_MANUFACTURERS = {
    "DC:DA:0C": "Samsung",
    "F4:7D:EF": "Samsung",
    "A4:C1:38": "Apple",
    "3C:5A:B4": "Fitbit",
    "08:59:5E": "Realme",
    "40:ED:98": "boAt",
    "70:2C:1F": "boAt",
    "C8:FD:19": "Noise",
    "E8:4E:06": "Noise",
    "00:1A:7D": "Google",
    "AC:DE:48": "Apple",
    "FC:E9:98": "Apple",
    "3C:22:FB": "Apple",
    "88:66:A5": "Apple",
    "D0:D2:B0": "Apple",
    "7C:D1:C3": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    "2C:CF:67": "Raspberry Pi",
    "00:25:00": "Apple",
    "F0:B4:D2": "Amazon",
    "44:65:0D": "Amazon",
    "74:C6:3B": "Amazon",
    "F0:27:2D": "Amazon",
    "68:54:FD": "Amazon",
    "A0:02:DC": "Amazon",
    "AC:63:BE": "Amazon",
    "50:F5:DA": "Amazon",
    "6C:56:97": "Amazon",
    "38:F7:3D": "Amazon",
    "78:E1:03": "Amazon",
    "84:D6:D0": "Amazon",
    "00:FC:8B": "Amazon",
    "34:D2:70": "Amazon",
    "B0:FC:0D": "Amazon",
    "18:74:2E": "Amazon",
}

# ----------------------------------
# Simulation
# ----------------------------------
SIMULATION_NORMAL_DEVICES = [
    {"name": "Galaxy Watch 5", "mac": "DC:DA:0C:A1:22:33", "type": 3},
    {"name": "AirPods Pro", "mac": "A4:C1:38:B2:44:55", "type": 1},
    {"name": "Fitbit Versa 3", "mac": "3C:5A:B4:C3:66:77", "type": 3},
    {"name": "iPhone 15", "mac": "FC:E9:98:D4:88:99", "type": 1},
    {"name": "Galaxy Buds Pro", "mac": "F4:7D:EF:E5:AA:BB", "type": 1},
    {"name": "boAt Airdopes 441", "mac": "40:ED:98:F6:CC:DD", "type": 1},
    {"name": "Noise ColorFit Pro", "mac": "C8:FD:19:01:EE:FF", "type": 3},
    {"name": "Pixel Watch 2", "mac": "00:1A:7D:02:11:22", "type": 3},
    {"name": "MacBook Pro", "mac": "AC:DE:48:03:33:44", "type": 2},
    {"name": "Realme Buds Air", "mac": "08:59:5E:04:55:66", "type": 1},
    {"name": "Samsung TV", "mac": "DC:DA:0C:05:77:88", "type": 2},
    {"name": "Amazon Echo", "mac": "F0:B4:D2:06:99:AA", "type": 2},
]

# ----------------------------------
# MAC Randomization Note
# ----------------------------------
MAC_RANDOMIZATION_NOTE = (
    "Modern phones (iOS 14+, Android 10+) use random MAC addresses for "
    "Bluetooth scanning. This means the same physical device may appear "
    "with different MACs across scan sessions. SecureWatch tracks devices "
    "within a session and uses fingerprinting (name + behaviour) as a "
    "secondary identifier. Cross-session tracking of randomised MACs is "
    "a known limitation."
)
