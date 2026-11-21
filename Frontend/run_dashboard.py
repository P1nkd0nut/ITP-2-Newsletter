"""
Launcher for GroundedCVE Threat Intelligence & Newsletter Web Dashboard.
Starts the Flask server hosting the GroundedCVE dashboard on port 8080.
"""
import sys
import webbrowser
import threading
import time
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from Backend.api.app import create_app
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

PORT = 8080
HOST = "0.0.0.0"


def open_browser():
    time.sleep(1.0)
    dashboard_url = f"http://localhost:{PORT}"
    print(f"[*] Opening browser to GroundedCVE dashboard: {dashboard_url}\n")
    try:
        webbrowser.open(dashboard_url)
    except Exception as e:
        print(f"[!] Could not auto-launch browser: {e}")


def main():
    print("=" * 70)
    print("     GroundedCVE dashboard")
    print("     Primary Delivery Channel: Web Dashboard (Port 8080)")
    print("=" * 70)

    if HAS_FLASK:
        app = create_app()
        threading.Thread(target=open_browser, daemon=True).start()
        print(f"[*] Serving unified API and Executive Dashboard on http://localhost:{PORT}")
        print("Press Ctrl+C to stop the server.\n")
        app.run(host=HOST, port=PORT, debug=False)
    else:
        import http.server
        import socketserver
        print(f"[!] Flask not available, falling back to static server on http://localhost:{PORT}")
        dashboard_url = f"http://localhost:{PORT}/dashboard/index.html"
        webbrowser.open(dashboard_url)
        with socketserver.TCPServer(("", PORT), http.server.SimpleHTTPRequestHandler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nServer stopped.")


if __name__ == "__main__":
    main()
