"""
Launcher for GroundedCVE Ingestion Web Dashboard.
Starts a lightweight local HTTP server and automatically opens your browser.
"""
import http.server
import socketserver
import webbrowser
from pathlib import Path

PORT = 8080
FRONTEND_DIR = Path(__file__).resolve().parent


class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)


def main():
    dashboard_url = f"http://localhost:{PORT}/index.html"
    print("=" * 65)
    print("     GroundedCVE - Threat Intelligence Ingestion Dashboard")
    print("=" * 65)
    print(f"🚀 Serving local UI at: {dashboard_url}")
    print("Press Ctrl+C to stop the server.\n")

    # Automatically open the browser
    webbrowser.open(dashboard_url)

    with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard server stopped.")


if __name__ == "__main__":
    main()
