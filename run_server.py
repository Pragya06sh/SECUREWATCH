"""
SecureWatch One-Click Launch Engine
Starts the FastAPI intelligence hub and launches the web SOC dashboard.
"""
import os
import sys
import asyncio
import webbrowser
import threading

def main():
    print("=" * 65)
    print("      SECUREWATCH: BLE CYBERSECURITY & AUDIT PLATFORM")
    print("=" * 65)
    
    backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
    os.chdir(backend_dir)
    sys.path.insert(0, backend_dir)

    # Windows-specific event loop policy to avoid ProactorEventLoop shutdown exceptions on Ctrl+C
    if sys.platform == "win32":
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    
    try:
        import uvicorn
    except ImportError:
        print("[!] Error: uvicorn is not installed. Please install requirements:")
        print("    pip install fastapi uvicorn scikit-learn pandas bleak")
        sys.exit(1)

    print("[*] Starting SecureWatch API & Web SOC Server on http://127.0.0.1:8000 ...")
    print("[*] Dashboard accessible at: http://127.0.0.1:8000")
    print("[*] Swagger API Docs at:     http://127.0.0.1:8000/docs")
    print("=" * 65)
    print("[*] Press Ctrl+C to stop the server.")
    print("=" * 65 + "\n")

    # Launch browser after a short delay
    def open_browser():
        import time
        time.sleep(1.5)
        try:
            webbrowser.open("http://127.0.0.1:8000")
        except Exception:
            pass

    threading.Thread(target=open_browser, daemon=True).start()

    from main import app
    
    config = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=8000,
        log_level="info",
        loop="asyncio"
    )
    server = uvicorn.Server(config)
    
    try:
        server.run()
    except (KeyboardInterrupt, SystemExit):
        pass
    except Exception as e:
        print(f"\n[!] Server stopped: {e}")
    finally:
        print("\n[+] SecureWatch server shut down cleanly.")

if __name__ == "__main__":
    main()
