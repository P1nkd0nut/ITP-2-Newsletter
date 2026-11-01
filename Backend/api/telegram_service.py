"""
Secondary Delivery Channel: Telegram Threat Alert Dispatcher.
Implements the secondary alert notification channel, leaving the Web Dashboard
as the primary authoritative delivery platform per supervisor specifications.

The bot token is read from TELEGRAM_BOT_TOKEN in .env and is never written to
channel_config.json (which is committed to git) or returned by the API.
Each message links to that incident's reader page at BASE_URL/incident/<Item_ID>.
"""
import html
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import quote

import requests

from Backend import config  # noqa: F401  (loads .env into os.environ)
from Backend.ingestion.recheck_policy import age_days

logger = logging.getLogger(__name__)

CONFIG_FILE = Path(__file__).resolve().parent.parent / "data" / "channel_config.json"

DEFAULT_BASE_URL = "http://localhost:5000"
TELEGRAM_SEND_URL = "https://api.telegram.org/bot{token}/sendMessage"
MAX_MESSAGE_CHARS = 4096  # Telegram's hard limit per message
SEND_PAUSE_SECONDS = 1.0  # stay well under Telegram's ~1 message/second per chat
MAX_SEND_ATTEMPTS = 3
MAX_RETRY_AFTER_SECONDS = 60
SUMMARY_CHARS = 220

# Fields that only ever come from .env, never from the saved config
ENV_ONLY_FIELDS = ("bot_token", "bot_token_set")


def bot_token() -> str:
    return os.getenv("TELEGRAM_BOT_TOKEN", "").strip()


def base_url() -> str:
    return (os.getenv("BASE_URL", "").strip() or DEFAULT_BASE_URL).rstrip("/")


def incident_url(item_id: str) -> str:
    return f"{base_url()}/incident/{quote(item_id, safe='')}"


def esc(value: Any) -> str:
    """Escapes text for Telegram's HTML parse mode."""
    return html.escape(str(value), quote=True)


def _truncate(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def send_message(token: str, chat_id: str, text: str) -> Dict[str, Any]:
    """
    Sends one HTML message, waiting and retrying when Telegram answers 429.
    Returns {"ok": True} or {"ok": False, "error": ...}; the token never appears in errors.
    """
    url = TELEGRAM_SEND_URL.format(token=token)
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        # Local addresses can't be previewed by Telegram, so skip the preview card
        "link_preview_options": {"is_disabled": True},
    }
    for attempt in range(1, MAX_SEND_ATTEMPTS + 1):
        try:
            resp = requests.post(url, json=payload, timeout=10)
        except requests.RequestException as e:
            return {"ok": False, "error": f"Network error: {str(e).replace(token, '<token>')}"}

        if resp.status_code == 200:
            return {"ok": True}

        if resp.status_code == 429 and attempt < MAX_SEND_ATTEMPTS:
            try:
                retry_after = int(resp.json().get("parameters", {}).get("retry_after", 1))
            except (ValueError, AttributeError):
                retry_after = 1
            retry_after = min(max(retry_after, 1), MAX_RETRY_AFTER_SECONDS)
            logger.warning(f"Telegram rate limit hit; retrying in {retry_after}s")
            time.sleep(retry_after)
            continue

        try:
            description = resp.json().get("description", "")
        except ValueError:
            description = resp.text[:300]
        return {"ok": False, "error": f"Telegram API error {resp.status_code}: {description}"}

    return {"ok": False, "error": "Telegram rate limit: gave up after retries"}


# ----------------------------------------------------------------------------
# Weekly digest
# ----------------------------------------------------------------------------

def select_digest_items(candidates: List[Dict[str, Any]], days: int = 7, top_n: int = 10) -> List[Dict[str, Any]]:
    """In-scope (Web/Mobile) incidents published in the last `days` days, highest priority first."""
    picked = []
    for c in candidates:
        if not (c.get("pre_filter") or {}).get("is_in_scope", False):
            continue
        age = age_days((c.get("envelope") or {}).get("Published_Date"))
        if age is not None and age <= days:
            picked.append(c)
    picked.sort(key=lambda c: float(c.get("priority_score", 0.0)), reverse=True)
    return picked[:top_n]


def _display_title(c: Dict[str, Any]) -> str:
    env = c.get("envelope") or {}
    title = (c.get("in_depth") or {}).get("vulnerability_name") or env.get("Title") or "Untitled advisory"
    cve = env.get("CVE_ID")
    # Titles like "CVE-2026-1234 - Product Flaw" repeat the CVE shown on the line above
    if cve and title.upper().startswith(cve.upper()):
        title = title[len(cve):].lstrip(" -–—:") or title
    return title


def _summary(c: Dict[str, Any]) -> str:
    in_depth = c.get("in_depth") or {}
    return (
        in_depth.get("brief_summary")
        or in_depth.get("full_description")
        or (c.get("ai_assessment") or {}).get("reasoning")
        or ""
    )


def format_digest_item(c: Dict[str, Any], rank: int) -> str:
    """One short message per incident: title, tag, score, 1-2 line summary, link to its page."""
    env = c.get("envelope") or {}
    item_id = env.get("Item_ID", "")
    category = (c.get("pre_filter") or {}).get("category", "")
    tag = {"WEB": "🌐 Web", "MOBILE": "📱 Mobile"}.get(category, category.title())
    score = float(c.get("priority_score", 0.0))
    heading = env.get("CVE_ID") or "Advisory"

    flags = []
    if env.get("KEV_Status"):
        flags.append("🔥 Actively exploited")
    if env.get("PoC_URLs"):
        flags.append("🧪 Public PoC")

    def build(summary_limit: int) -> str:
        lines = [
            f"<b>#{rank} · {esc(heading)}</b>",
            f"<b>{esc(_truncate(_display_title(c), 200))}</b>",
            f"{tag} · Priority {score:.0f}/100 · {esc(c.get('recency_label') or 'Monitored')}",
        ]
        summary = _truncate(_summary(c), summary_limit)
        if summary:
            lines += ["", esc(summary)]
        if flags:
            lines += ["", " · ".join(flags)]
        lines += ["", f'<a href="{esc(incident_url(item_id))}">Read full details →</a>']
        return "\n".join(lines)

    limit = SUMMARY_CHARS
    msg = build(limit)
    while len(msg) > MAX_MESSAGE_CHARS and limit > 0:
        limit = max(0, limit - 50)
        msg = build(limit)
    return msg


def format_digest_header(items: List[Dict[str, Any]], days: int = 7) -> str:
    web = sum(1 for c in items if (c.get("pre_filter") or {}).get("category") == "WEB")
    mobile = sum(1 for c in items if (c.get("pre_filter") or {}).get("category") == "MOBILE")
    period = "this week" if days == 7 else f"in the last {days} days"
    lines = ["🛡️ <b>Grounded Threat News · Weekly Brief</b>", ""]
    if items:
        lines.append(
            f"{len(items)} top incident{'s' if len(items) != 1 else ''} {period}: "
            f"{web} Web, {mobile} Mobile."
        )
        lines.append("Tap <i>Read full details</i> under each one for the full write-up.")
    else:
        lines.append(f"No new Web or Mobile incidents {period}.")
    lines += ["", f'<a href="{esc(base_url())}/">Open the dashboard</a>']
    return "\n".join(lines)


def build_weekly_digest(candidates: List[Dict[str, Any]], days: int = 7, top_n: int = 10) -> List[str]:
    """Header message followed by one message per selected incident."""
    items = select_digest_items(candidates, days=days, top_n=top_n)
    return [format_digest_header(items, days)] + [format_digest_item(c, i) for i, c in enumerate(items, 1)]


class TelegramService:
    def __init__(self):
        self._ensure_config()

    def _ensure_config(self):
        """Initializes default channel configuration if not exists."""
        if not CONFIG_FILE.exists():
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            default_config = {
                "primary_channel": {
                    "type": "web_dashboard",
                    "name": "GroundedCVE Executive Dashboard",
                    "status": "active",
                    "url": DEFAULT_BASE_URL,
                    "description": "Primary delivery channel and interactive intelligence dashboard.",
                },
                "secondary_channel": {
                    "type": "telegram",
                    "name": "Telegram Alert Bot",
                    "enabled": False,
                    "chat_id": "",
                    "min_score_threshold": 70.0,
                    "notify_on_kev_only": False,
                    "status": "standby",
                    "description": "Secondary push notification channel for high-priority or KEV advisories.",
                },
                "delivery_policy": {
                    "mode": "dashboard_primary",
                    "auto_dispatch_secondary": False,
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                },
            }
            try:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(default_config, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to create default channel config: {e}")

    def _read_config(self) -> Dict[str, Any]:
        if not CONFIG_FILE.exists():
            self._ensure_config()
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            logger.error(f"Error reading channel config: {e}")
            return {}
        for field in ENV_ONLY_FIELDS:
            cfg.get("secondary_channel", {}).pop(field, None)
        return cfg

    def chat_id(self) -> str:
        """TELEGRAM_CHAT_ID from .env, else the chat id saved in Channel Settings."""
        return os.getenv("TELEGRAM_CHAT_ID", "").strip() or self._read_config().get("secondary_channel", {}).get("chat_id", "")

    def get_config(self) -> Dict[str, Any]:
        """Returns the channel configuration; reports whether a token is set, never the token."""
        cfg = self._read_config()
        sec = cfg.setdefault("secondary_channel", {})
        sec["bot_token_set"] = bool(bot_token())
        sec["chat_id"] = self.chat_id()
        cfg.setdefault("primary_channel", {})["url"] = base_url()
        return cfg

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Updates channel configuration. A bot token in the update is ignored; it belongs in .env."""
        config = self._read_config()
        if "secondary_channel" in updates:
            sec_updates = {k: v for k, v in updates["secondary_channel"].items() if k not in ENV_ONLY_FIELDS}
            config["secondary_channel"].update(sec_updates)
        if "delivery_policy" in updates:
            config["delivery_policy"].update(updates["delivery_policy"])

        config["delivery_policy"]["last_updated"] = datetime.now(timezone.utc).isoformat()

        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save channel config: {e}")

        return self.get_config()

    def format_alert_message(self, candidate: Dict[str, Any]) -> str:
        """Formats a candidate into an executive alert card."""
        env = candidate.get("envelope", {})
        pf = candidate.get("pre_filter", {})
        ai = candidate.get("ai_assessment") or {}
        score = candidate.get("priority_score", 0.0)
        cve = env.get("CVE_ID") or env.get("Item_ID", "UNKNOWN")
        title = env.get("Title", "No title")
        impact = ai.get("offensive_impact", "Exploit Advisory")
        ai_sev = ai.get("severity_score", 0.0)
        cvss = env.get("CVSS", "N/A")
        is_kev = env.get("KEV_Status", False)
        poc_urls = env.get("PoC_URLs") or []

        msg = (
            f"🚨 <b>[GroundedCVE Secondary Alert]</b>\n\n"
            f"<b>{esc(cve)}</b> — <i>{esc(pf.get('category', 'PENTEST'))}</i>\n"
            f"<b>Title:</b> {esc(title)}\n"
            f"<b>Priority Score:</b> <code>{esc(score)}/100.0</code>\n"
            f"<b>AI Practical Severity:</b> <code>{esc(ai_sev)}/10.0</code> (CVSS: <code>{esc(cvss)}</code>)\n"
            f"<b>Offensive Impact:</b> {esc(impact)}\n"
            f"<b>Weaponization:</b> {'🔥 Active CISA KEV Exploitation' if is_kev else '⚠️ Tracked Advisory'}\n"
        )

        if poc_urls:
            msg += f"<b>PoC Exploit:</b> <a href=\"{esc(poc_urls[0])}\">GitHub PoC Repository</a>\n"

        if ai.get("reasoning"):
            msg += f"\n<b>AI Assessment:</b>\n<i>{esc(_truncate(ai['reasoning'], 200))}</i>\n"

        msg += (
            f"\n📄 <a href=\"{esc(incident_url(env.get('Item_ID', '')))}\">Read full details</a>\n"
            f"🌐 <b>Primary Channel:</b> <a href=\"{esc(base_url())}/\">Open GroundedCVE Dashboard</a>"
        )
        return msg

    def send_test_message(self, chat_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends a test ping message using the token from .env.
        Without a token it returns a simulated result so the demo still runs.
        """
        token = bot_token()
        cid = chat_id or self.chat_id()

        test_text = (
            "🔔 <b>[GroundedCVE Secondary Channel Test]</b>\n\n"
            "This is a verification test ping from GroundedCVE.\n"
            "• <b>Primary Channel:</b> Web Dashboard (Active)\n"
            "• <b>Secondary Channel:</b> Telegram Bot (Verified)\n"
            f"• <b>Timestamp:</b> <code>{datetime.now(timezone.utc).isoformat()}</code>\n\n"
            "All threat intelligence cards and weekly digests are accessible via the primary dashboard."
        )

        if not token:
            return {
                "success": True,
                "mode": "simulated",
                "note": "No TELEGRAM_BOT_TOKEN in .env. Simulated test completed for the local demo.",
                "preview": test_text,
            }
        if not cid:
            return {"success": False, "mode": "live", "error": "No chat id: set TELEGRAM_CHAT_ID in .env or in Channel Settings."}

        result = send_message(token, cid, test_text)
        if result["ok"]:
            return {"success": True, "mode": "live", "message": "Test alert dispatched to Telegram successfully!"}
        return {"success": False, "mode": "live", "error": result["error"]}

    def dispatch_alert(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an alert for a specific candidate to Telegram secondary channel."""
        config = self._read_config().get("secondary_channel", {})
        if not config.get("enabled", False):
            return {
                "dispatched": False,
                "reason": "Telegram secondary channel is currently disabled. Enable it in Channel Settings if desired.",
            }

        score = candidate.get("priority_score", 0.0)
        min_threshold = config.get("min_score_threshold", 70.0)
        is_kev = candidate.get("envelope", {}).get("KEV_Status", False)

        if config.get("notify_on_kev_only", False) and not is_kev:
            return {
                "dispatched": False,
                "reason": f"Item filtered out: Notification policy set to KEV items only.",
            }

        if score < min_threshold and not is_kev:
            return {
                "dispatched": False,
                "reason": f"Item score ({score}) below threshold ({min_threshold}).",
            }

        text = self.format_alert_message(candidate)
        token = bot_token()
        cid = self.chat_id()

        if not (token and cid):
            return {
                "dispatched": True,
                "mode": "simulated",
                "note": "Dispatched in simulated secondary mode (no TELEGRAM_BOT_TOKEN or chat id set).",
                "preview": text,
            }

        result = send_message(token, cid, text)
        if result["ok"]:
            return {"dispatched": True, "mode": "live", "status": "sent"}
        return {"dispatched": False, "mode": "live", "error": result["error"]}

    def send_digest(self, messages: List[str], chat_id: Optional[str] = None) -> Dict[str, Any]:
        """Sends the digest messages in order, pausing between each; stops at the first failure."""
        token = bot_token()
        cid = chat_id or self.chat_id()
        if not token:
            return {"sent": 0, "total": len(messages), "error": "TELEGRAM_BOT_TOKEN is not set in .env"}
        if not cid:
            return {"sent": 0, "total": len(messages), "error": "No chat id: set TELEGRAM_CHAT_ID in .env"}

        for i, text in enumerate(messages):
            if i:
                time.sleep(SEND_PAUSE_SECONDS)
            result = send_message(token, cid, text)
            if not result["ok"]:
                return {"sent": i, "total": len(messages), "error": result["error"]}
        return {"sent": len(messages), "total": len(messages), "error": None}


telegram_service = TelegramService()
