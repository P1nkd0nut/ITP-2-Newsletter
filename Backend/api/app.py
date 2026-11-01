"""
Flask application factory for GroundedCVE Threat Intelligence & Newsletter Hub.
Serves both REST API endpoints and the unified Web Dashboard.
"""
from pathlib import Path
from flask import Flask, send_from_directory, send_file
from flask_cors import CORS
from .routes import api_bp
from .data_service import data_service

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = ROOT_DIR / "Frontend"
DASHBOARD_DIR = FRONTEND_DIR / "dashboard"
READER_DIR = FRONTEND_DIR / "reader"


def create_app():
    app = Flask(__name__, static_folder=str(DASHBOARD_DIR), static_url_path="")
    CORS(app)

    # Register API routes
    app.register_blueprint(api_bp)

    # Root route serves the primary Newsletter Dashboard
    @app.route("/")
    def index():
        dashboard_index = DASHBOARD_DIR / "index.html"
        if dashboard_index.exists():
            return send_file(str(dashboard_index))
        # Fallback to Frontend/index.html if dashboard folder not found
        return send_file(str(FRONTEND_DIR / "index.html"))

    # Reader page for one incident; Telegram messages link here
    @app.route("/incident/<path:item_id>")
    def incident_page(item_id):
        if not data_service.get_candidate_by_id(item_id):
            return send_file(str(READER_DIR / "not_found.html")), 404
        return send_file(str(READER_DIR / "incident.html"))

    # Dedicated route to view raw ingestion staging envelopes
    @app.route("/ingestion")
    def ingestion_view():
        return send_file(str(FRONTEND_DIR / "index.html"))

    # Serve static assets from Frontend/dashboard or Frontend
    @app.route("/dashboard/<path:filename>")
    def dashboard_static(filename):
        return send_from_directory(str(DASHBOARD_DIR), filename)

    @app.route("/static-raw/<path:filename>")
    def raw_static(filename):
        return send_from_directory(str(FRONTEND_DIR), filename)

    # Allow direct loading of Backend data files if requested
    @app.route("/Backend/data/staging/<path:filename>")
    def staging_data(filename):
        staging_dir = ROOT_DIR / "Backend" / "data" / "staging"
        return send_from_directory(str(staging_dir), filename)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
