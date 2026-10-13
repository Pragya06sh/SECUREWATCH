import asyncio
from bleak import BleakScanner
from detection_engine import detect_and_score

def print_diagnostic_targets():
    print("=" * 80)
    print("  DIAGNOSTIC TARGET DEVICES VERIFICATION")
    print("=" * 80)
    targets = [
        ("08:12:87:16:4A:62", "OnePlus Nord Buds 2", -36),
        ("33:30:1C:22:21:7E", "Unknown_Device", -66),
        ("1E:49:2E:64:12:D4", "Unknown_Device", -68),
    ]
    for mac, name, rssi in targets:
        res = detect_and_score(device_id=mac, device_name=name, rssi=rssi)
        reasons_fmt = "; ".join(f"{r['reason']}" for r in res["reasons"])
        print(f"Device: {name:<22} ({mac}) at RSSI {rssi} dBm")
        print(f"  -> Status:       {res['status']}")
        print(f"  -> Risk Score:   {res['risk_score']}")
        print(f"  -> Manufacturer: {res['manufacturer']}")
        print(f"  -> Reasons:      {reasons_fmt}")
        print("-" * 80)

async def scan():
    print("\n" + "=" * 80)
    print("  LIVE BLE HARDWARE SCAN")
    print("=" * 80)
    try:
        devices = await BleakScanner.discover(timeout=5.0, return_adv=True)
        print(f"Discovered {len(devices)} active BLE device(s) in proximity:\n")
        for address, (device, adv_data) in devices.items():
            name = adv_data.local_name or device.name or ""
            rssi = adv_data.rssi
            result = detect_and_score(
                device_id=address,
                device_name=name,
                rssi=rssi
            )
            reasons_str = "; ".join(f"{r['reason']}" for r in result["reasons"])
            print(f"[{result['status']:^11}] MAC: {address} | Name: {(name or '<None>'):<25} | Mfr: {result['manufacturer']:<10} | RSSI: {rssi:>4} dBm | Risk: {result['risk_score']:>4.1f} | Reasons: {reasons_str}")
        print("\n" + "=" * 80)
        print("Live BLE scan completed.")
        print("=" * 80)
    except Exception as e:
        print(f"BLE scan error or adapter unavailable: {e}")

if __name__ == "__main__":
    print_diagnostic_targets()
    asyncio.run(scan())
