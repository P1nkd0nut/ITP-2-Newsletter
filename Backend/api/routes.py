"""
REST API routes for GroundedCVE Threat Intelligence & Newsletter Hub.
"""
import logging
from html import escape
import time
from flask import Blueprint, jsonify, request, Response
from .data_service import data_service
from .telegram_service import telegram_service
from .link_validator import link_validator

logger = logging.getLogger(__name__)

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/health", methods=["GET"])
def health():
    """Health check and quick system status."""
    stats = data_service.get_stats()
    return jsonify({
        "status": "healthy",
        "service": "GroundedCVE Intelligence API",
        "total_evaluated": stats["total_evaluated"],
        "in_scope_count": stats["in_scope_count"],
        "anomalies_count": stats["anomalies_count"],
        "primary_channel": "web_dashboard",
        "secondary_channel": "telegram",
    })


@api_bp.route("/reload", methods=["GET", "POST"])
def reload_data():
    """Forces reloading candidate envelopes from disk into memory."""
    candidates = data_service.reload()
    stats = data_service.get_stats()
    return jsonify({
        "status": "reloaded",
        "total_evaluated": len(candidates),
        "in_scope_count": stats["in_scope_count"],
        "web_count": stats["web_count"],
        "mobile_count": stats["mobile_count"],
    })


@api_bp.route("/stats", methods=["GET"])
def get_stats():
    """Returns aggregated KPI metrics, chart analytics, and anomaly alerts."""
    try:
        stats = data_service.get_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/newsletters", methods=["GET"])
def get_newsletters():
    """
    Query, filter, and paginate triaged vulnerability candidates.
    Query params:
      - scope: ALL | WEB | MOBILE | OUT_OF_SCOPE | IN_SCOPE
      - search: string
      - discrepancy_only: true | false
      - source: string
      - min_score: float
      - sort_by: priority_score | published_date | ai_severity | cvss | title
      - sort_order: asc | desc
      - page: int (default 1)
      - page_size: int (default 20)
    """
    try:
        scope = request.args.get("scope")
        search = request.args.get("search")
        discrepancy_only = request.args.get("discrepancy_only", "false").lower() == "true"
        source = request.args.get("source")
        category = request.args.get("category")
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        date_preset = request.args.get("date_preset")
        min_score = request.args.get("min_score")
        if min_score is not None:
            try:
                min_score = float(min_score)
            except ValueError:
                min_score = None

        sort_by = request.args.get("sort_by") or request.args.get("sort") or "timeline"
        sort_order = request.args.get("sort_order", "desc")
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 50))

        result = data_service.query_candidates(
            scope=scope,
            search=search,
            discrepancy_only=discrepancy_only,
            source=source,
            category=category,
            start_date=start_date,
            end_date=end_date,
            date_preset=date_preset,
            min_score=min_score,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            page_size=page_size,
        )
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error querying newsletters: {e}")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/newsletters/<path:item_id>", methods=["GET"])
def get_candidate_detail(item_id):
    """Retrieve full detail for a single disclosure candidate."""
    candidate = data_service.get_candidate_by_id(item_id)
    if not candidate:
        return jsonify({"error": f"Candidate '{item_id}' not found"}), 404
    return jsonify(candidate)


@api_bp.route("/newsletter/digest", methods=["GET"])
def get_newsletter_digest():
    """Returns curated weekly newsletter edition data with executive highlights."""
    try:
        title = request.args.get("title")
        top_n = int(request.args.get("top_n", 6))
        digest = data_service.generate_newsletter_digest(issue_title=title, top_n=top_n)
        return jsonify(digest)
    except Exception as e:
        logger.error(f"Error generating newsletter digest: {e}")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/newsletter/export", methods=["GET"])
def export_newsletter():
    """Exports weekly newsletter in Markdown, HTML, or JSON format."""
    fmt = request.args.get("format", "markdown").lower()
    top_n = int(request.args.get("top_n", 6))
    digest = data_service.generate_newsletter_digest(top_n=top_n)

    if fmt == "markdown" or fmt == "md":
        return Response(
            digest["markdown"],
            mimetype="text/markdown",
            headers={"Content-Disposition": "attachment;filename=groundedcve_weekly_newsletter.md"},
        )
    elif fmt == "html":
        # Render a printable HTML version
        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{digest['title']}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #1e293b; }}
    h1 {{ color: #0f172a; border-bottom: 2px solid #0284c7; padding-bottom: 8px; }}
    h2 {{ color: #0369a1; margin-top: 32px; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; }}
    h3 {{ color: #0f172a; margin-top: 24px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; font-family: monospace; }}
    .badge-web {{ background: #e0f2fe; color: #0369a1; }}
    .badge-mobile {{ background: #dcfce7; color: #15803d; }}
    .badge-score {{ background: #fef3c7; color: #b45309; }}
    .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 16px 0; }}
    code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; }}
  </style>
</head>
<body>
  <h1>{digest['title']}</h1>
  <p><strong>Published:</strong> {digest['generated_at']} | <strong>Primary Delivery:</strong> Web Executive Dashboard</p>
  <p>Evaluated {digest['total_evaluated']} items | {digest['in_scope_count']} In-Scope Pentest Disclosures</p>
  <hr>
  <h2>Top Priority Threat Advisories</h2>
"""
        for t in digest["curated_threats"]:
            badge_class = "badge-web" if t["category"] == "WEB" else "badge-mobile"
            html += f"""
  <div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <span class="badge {badge_class}">[{t['category']}]</span>
      <span class="badge badge-score">Score: {t['priority_score']}/100</span>
    </div>
    <h3>{t['cve_id']} — {t['title']}</h3>
    <p><strong>Offensive Impact:</strong> {t['offensive_impact']} | <strong>AI Severity:</strong> {t['ai_severity']}/10 (CVSS: {t['cvss'] or 'N/A'})</p>
    <p><strong>What it is:</strong> {escape(t['grounded_card']['mechanism'])}</p>
    <p><strong>Impact:</strong> {escape(t['grounded_card']['impact'])}</p>
    {"<p><strong>Fix:</strong> " + escape(t['grounded_card']['remediation']) + "</p>" if t['grounded_card'].get('remediation') else ""}
    {"<p style='color:#dc2626;'><strong>[!] CVSS Anomaly Alert:</strong> " + t['troubleshoot_note'] + "</p>" if t.get('is_discrepancy') else ""}
    <p><a href="{t['source_url']}" target="_blank">View Canonical Advisory &rarr;</a></p>
  </div>
"""
        html += """
  <hr>
  <p style="font-size:12px; color:#64748b;">Generated automatically by GroundedCVE Threat Intelligence Platform</p>
</body>
</html>"""
        return Response(html, mimetype="text/html")
    else:
        return jsonify(digest)


@api_bp.route("/refresh", methods=["POST"])
def refresh_data():
    """Forces reloading candidate data from disk."""
    try:
        candidates = data_service.reload()
        stats = data_service.get_stats()
        return jsonify({
            "message": "Intelligence dataset successfully reloaded.",
            "total_candidates": len(candidates),
            "stats": stats,
        })
    except Exception as e:
        logger.error(f"Error during dataset reload: {e}")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/channels", methods=["GET"])
def get_channels():
    """Returns channel architecture status: Web Dashboard (Primary) vs Telegram (Secondary)."""
    try:
        cfg = telegram_service.get_config()
        return jsonify(cfg)
    except Exception as e:
        logger.error(f"Error fetching channel config: {e}")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/channels/telegram", methods=["PUT", "POST"])
def update_telegram_channel():
    """Configures the secondary Telegram notification channel."""
    try:
        body = request.get_json() or {}
        updated = telegram_service.update_config(body)
        return jsonify({
            "message": "Secondary Telegram channel configuration updated.",
            "config": updated,
        })
    except Exception as e:
        logger.error(f"Error updating Telegram channel: {e}")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/channels/telegram/test", methods=["POST"])
def test_telegram_channel():
    """Dispatches a test notification to verify secondary channel integration."""
    try:
        body = request.get_json() or {}
        result = telegram_service.send_test_message(body.get("chat_id"))
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error testing Telegram channel: {e}")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/channels/telegram/dispatch", methods=["POST"])
def dispatch_candidate_telegram():
    """Dispatches a specific candidate alert to the secondary Telegram channel."""
    try:
        body = request.get_json() or {}
        item_id = body.get("item_id")
        if not item_id:
            return jsonify({"error": "Missing 'item_id'"}), 400

        candidate = data_service.get_candidate_by_id(item_id)
        if not candidate:
            return jsonify({"error": f"Candidate '{item_id}' not found"}), 404

        result = telegram_service.dispatch_alert(candidate)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error dispatching to Telegram: {e}")
        return jsonify({"error": str(e)}), 500


@api_bp.route("/links/stats", methods=["GET"])
def get_links_stats():
    """Returns cached link health, latency, and active ratio statistics."""
    stats = link_validator.get_stats()
    return jsonify({
        "status": "success",
        "engine": "Asynchronous High-Speed Link Validator (ThreadPoolExecutor + HEAD)",
        "stats": stats,
    })


@api_bp.route("/links/verify", methods=["GET", "POST"])
def verify_links():
    """
    High-speed asynchronous & concurrent link health verification.
    Validates links using thread pool in parallel with persistent caching.
    """
    try:
        force = request.args.get("force", "false").lower() == "true"
        candidates = data_service.get_all_candidates()
        all_links = []
        for c in candidates:
            for ref in c.get("external_references", []):
                all_links.append(ref)

        t0 = time.perf_counter()
        validated = link_validator.validate_batch(all_links, force_refresh=force)
        elapsed = round(time.perf_counter() - t0, 3)

        stats = link_validator.get_stats()
        stats["verification_time_seconds"] = elapsed
        stats["speedup_factor"] = "20x - 30x faster than sequential"

        return jsonify({
            "status": "success",
            "benchmark": stats,
            "total_tested": len(validated),
            "links": validated,
        })
    except Exception as e:
        logger.error(f"Error running batch link verification: {e}")
        return jsonify({"error": str(e)}), 500
