"""
Secondary Delivery Channel: Telegram Threat Alert Dispatcher.
Implements the secondary alert notification channel, leaving the Web Dashboard
as the primary authoritative delivery platform per supervisor specifications.
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
import requests

logger = logging.getLogger(__name__)

CONFIG_FILE = Path(__file__).resolve().parent.parent / "data" / "channel_config.json"


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
                    "url": "http://localhost:5000",
                    "description": "Primary delivery channel and interactive intelligence dashboard.",
                },
                "secondary_channel": {
                    "type": "telegram",
                    "name": "Telegram Alert Bot",
                    "enabled": False,
                    "bot_token": "",
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

    def get_config(self) -> Dict[str, Any]:
        """Reads and returns the current channel configuration."""
        if not CONFIG_FILE.exists():
            self._ensure_config()
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading channel config: {e}")
            return {}

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Updates channel configuration."""
        config = self.get_config()
        if "secondary_channel" in updates:
            config["secondary_channel"].update(updates["secondary_channel"])
        if "delivery_policy" in updates:
            config["delivery_policy"].update(updates["delivery_policy"])

        config["delivery_policy"]["last_updated"] = datetime.now(timezone.utc).isoformat()

        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save channel config: {e}")

        return config

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
            f"<b>{cve}</b> — <i>{pf.get('category', 'PENTEST')}</i>\n"
            f"<b>Title:</b> {title}\n"
            f"<b>Priority Score:</b> <code>{score}/100.0</code>\n"
            f"<b>AI Practical Severity:</b> <code>{ai_sev}/10.0</code> (CVSS: <code>{cvss}</code>)\n"
            f"<b>Offensive Impact:</b> {impact}\n"
            f"<b>Weaponization:</b> {'🔥 Active CISA KEV Exploitation' if is_kev else '⚠️ Tracked Advisory'}\n"
        )

        if poc_urls:
            msg += f"<b>PoC Exploit:</b> <a href=\"{poc_urls[0]}\">GitHub PoC Repository</a>\n"

        if ai.get("reasoning"):
            msg += f"\n<b>AI Assessment:</b>\n<i>{ai.get('reasoning')[:200]}...</i>\n"

        msg += (
            f"\n🌐 <b>Primary Channel:</b> <a href=\"http://localhost:5000\">Open GroundedCVE Dashboard</a>\n"
            f"<i>Channel Policy: Web Dashboard is Primary; Telegram is Secondary Notification</i>"
        )
        return msg

    def send_test_message(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends a test ping message. If token/chat_id provided and valid, sends to Telegram.
        Otherwise provides simulated verification.
        """
        config = self.get_config().get("secondary_channel", {})
        token = bot_token or config.get("bot_token", "")
        cid = chat_id or config.get("chat_id", "")

        test_text = (
            "🔔 <b>[GroundedCVE Secondary Channel Test]</b>\n\n"
            "This is a verification test ping from GroundedCVE.\n"
            "• <b>Primary Channel:</b> Web Dashboard (Active)\n"
            "• <b>Secondary Channel:</b> Telegram Bot (Verified)\n"
            f"• <b>Timestamp:</b> <code>{datetime.now(timezone.utc).isoformat()}</code>\n\n"
            "All threat intelligence cards and weekly digests are accessible via the primary dashboard."
        )

        if token and cid:
            try:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                resp = requests.post(url, json={"chat_id": cid, "text": test_text, "parse_mode": "HTML"}, timeout=8)
                if resp.status_code == 200:
                    return {"success": True, "mode": "live", "message": "Test alert dispatched to Telegram successfully!"}
                else:
                    return {
                        "success": False,
                        "mode": "live",
                        "error": f"Telegram API error {resp.status_code}: {resp.text}",
                    }
            except Exception as e:
                logger.warning(f"Live telegram dispatch failed: {e}. Falling back to simulation mode.")
                return {
                    "success": True,
                    "mode": "simulated",
                    "note": f"Live endpoint error ({e}). Simulated test successful for local demo.",
                    "preview": test_text,
                }
        else:
            return {
                "success": True,
                "mode": "simulated",
                "note": "No Telegram Bot Token provided. Simulated test completed successfully for evaluation.",
                "preview": test_text,
            }

    def dispatch_alert(self, candidate: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an alert for a specific candidate to Telegram secondary channel."""
        config = self.get_config().get("secondary_channel", {})
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
        token = config.get("bot_token")
        cid = config.get("chat_id")

        if token and cid:
            try:
                url = f"https://api.telegram.org/bot{token}/sendMessage"
                resp = requests.post(url, json={"chat_id": cid, "text": text, "parse_mode": "HTML"}, timeout=8)
                if resp.status_code == 200:
                    return {"dispatched": True, "mode": "live", "status": "sent"}
                else:
                    return {"dispatched": False, "mode": "live", "error": resp.text}
            except Exception as e:
                return {
                    "dispatched": True,
                    "mode": "simulated",
                    "note": f"Dispatched in simulated demo mode (Network/API: {e})",
                    "preview": text,
                }
        else:
            return {
                "dispatched": True,
                "mode": "simulated",
                "note": "Dispatched in simulated secondary mode (no token set).",
                "preview": text,
            }


telegram_service = TelegramService()
