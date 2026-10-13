"""
SecureWatch — Bluetooth Scanner Entrypoint
Runs the edge BLE device discovery loop and streams observations to the backend.
"""
from scanner import run_scanner
import asyncio
import sys

if __name__ == "__main__":
    interval = 5.0
    if len(sys.argv) > 1:
        try:
            interval = float(sys.argv[1])
        except ValueError:
            pass
    try:
        asyncio.run(run_scanner(poll_interval=interval))
    except KeyboardInterrupt:
        print("\nScanner halted.")