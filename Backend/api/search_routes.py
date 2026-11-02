"""
Search endpoint (Task 3.3): GET /api/search?q=<query>&limit=10&mode=hybrid

mode is hybrid (default), keyword or semantic. Returns title, link, scope,
score, AI rationale and a snippet for each matching item, including items that
were not selected for the weekly digest.
"""
from flask import Blueprint, jsonify, request

from Backend.search_engine import MODES, default_searcher

search_bp = Blueprint("search", __name__, url_prefix="/api")

_searcher = None


def get_searcher():
    global _searcher
    if _searcher is None:
        _searcher = default_searcher()
    return _searcher


@search_bp.route("/search", methods=["GET"])
def search():
    query = (request.args.get("q") or "").strip()
    if not query:
        return jsonify({"error": "Add a search query, e.g. /api/search?q=frida+root+detection"}), 400

    try:
        limit = max(1, min(int(request.args.get("limit", 10)), 50))
    except ValueError:
        return jsonify({"error": "limit must be a number between 1 and 50"}), 400

    mode = request.args.get("mode", "hybrid")
    if mode not in MODES:
        return jsonify({"error": f"mode must be one of: {', '.join(MODES)}"}), 400

    return jsonify(get_searcher().search(query, limit=limit, mode=mode))
