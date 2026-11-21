"""
Unified Application Launcher for GroundedCVE Threat Intelligence Platform.
Starts the Flask REST API and serves the GroundedCVE dashboard.
"""
import sys
import webbrowser
import threading
import time
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.api.app import create_app

PORT = 5000
HOST = "0.0.0.0"


def open_browser():
    """Wait for server to spin up, then open browser."""
    time.sleep(1.2)
    url = f"http://localhost:{PORT}"
    print(f"[*] Opening browser to Primary Executive Dashboard: {url}\n")
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"[!] Could not auto-launch browser: {e}")


def main():
    print("\n" + "=" * 70)
    print("      GroundedCVE: Threat Intelligence & Newsletter Hub")
    print("      ICT 2114 Integrative Team Project — IS 24 | Team 4 (SIT)")
    print("=" * 70)
    print(f"[*] Primary Delivery Channel:  http://localhost:{PORT}")
    print(f"[*] Secondary Channel:         Telegram Alerts (Opt-in push notifications)")
    print(f"[*] REST API Base:             http://localhost:{PORT}/api")
    print(f"[*] Raw Ingestion Staging:     http://localhost:{PORT}/ingestion")
    print("=" * 70)
    print("Press Ctrl+C to stop the server.\n")

    app = create_app()

    # Launch browser in a background thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Flask development server
    app.run(host=HOST, port=PORT, debug=False)


if __name__ == "__main__":
    main()
