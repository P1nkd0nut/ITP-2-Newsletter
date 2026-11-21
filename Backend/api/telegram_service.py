"""
Secondary Delivery Channel: Telegram Threat Alert Dispatcher.
Implements the secondary alert notification channel, leaving the Web Dashboard
as the primary authoritative delivery platform per supervisor specifications.

The bot token is read from TELEGRAM_BOT_TOKEN in .env and is never written to
channel_config.json (which is committed to git) or returned by the API.
Messages carry only public links (NVD, the source, the first live PoC); they never
link to the dashboard, which runs on a team PC most readers can't reach.
"""
import html
import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import quote, urlparse
from zoneinfo import ZoneInfo

import requests

from Backend import config  # noqa: F401  (loads .env into os.environ)
from Backend.ingestion.recheck_policy import age_days
from Backend.api.novelty import NoveltyChecker, merge_same_flaw

logger = logging.getLogger(__name__)

CONFIG_FILE = Path(__file__).resolve().parent.parent / "data" / "channel_config.json"

SERVER_PORT = 5000  # matches run_server.py
# 127.0.0.1 rather than localhost: Telegram drops localhost links, so they aren't clickable
DEFAULT_BASE_URL = f"http://127.0.0.1:{SERVER_PORT}"
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


def lan_ip() -> Optional[str]:
    """This PC's address on the local network (e.g. its Wi-Fi IP), or None if offline."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connecting a UDP socket sends nothing; it just picks the outgoing interface
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def base_url() -> str:
    """BASE_URL from .env, or this PC's current Wi-Fi address so phones on the same network can open links."""
    configured = os.getenv("BASE_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    if Path("/.dockerenv").exists():
        # Inside a container the detected address is the container's own, which the host's phones can't reach
        return DEFAULT_BASE_URL
    ip = lan_ip()
    return f"http://{ip}:{SERVER_PORT}" if ip else DEFAULT_BASE_URL


def incident_url(item_id: str) -> str:
    return f"{base_url()}/incident/{quote(item_id, safe='')}"


NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
MAX_SOURCE_LINKS = 4


def _public_url(url: Any) -> Optional[str]:
    """The URL if it is a public http(s) link anyone in the channel can open, else None."""
    if not isinstance(url, str):
        return None
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.hostname in LOOPBACK_HOSTS:
        return None
    return url.strip()


def live_or_archived(url: str) -> Optional[str]:
    """
    The URL to post. If the link checker found it dead or redirected to a
    homepage, its archive.org copy is used instead, or the link is dropped.
    Links never checked are posted as they are.
    """
    from Backend.api.link_validator import DEAD, MOVED, link_validator

    record = link_validator.cached_record(url)
    if record and record.get("state") in (DEAD, MOVED):
        return record.get("archive_url") or None
    return url


def source_links(c: Dict[str, Any]) -> List[tuple]:
    """
    (label, url) pairs for a digest card, all public: the NVD record, the item's
    own source, other sources reporting the same CVE, and the first public PoC.
    Only URLs from the staging envelope are used, never model-written ones, and
    links the link checker found dead are swapped for an archived copy or left out.
    """
    env = c.get("envelope") or {}
    links: List[tuple] = []
    seen = set()

    def add(label: str, url: Any) -> bool:
        url = _public_url(url)
        if url:
            url = live_or_archived(url)
        if url and url not in seen and len(links) < MAX_SOURCE_LINKS:
            seen.add(url)
            links.append((label, url))
            return True
        return False

    cve = (env.get("CVE_ID") or "").upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        add("NVD", NVD_DETAIL_URL.format(cve=cve))
    add("Source", env.get("Source_URL"))
    for url in c.get("also_source_urls") or []:
        add("Source", url)
    for url in env.get("PoC_URLs") or []:
        if add("PoC", url):
            break  # the first PoC that is not known to be dead
    return links


def link_lines(c: Dict[str, Any]) -> List[str]:
    """
    One line per public link with the full URL written out ("🔗 NVD: https://..."),
    so the link is visible and tappable on every Telegram client, including mobile,
    instead of being hidden behind a short label. No dashboard links: the dashboard
    runs on a team PC that most readers can't reach.
    """
    return [f'🔗 {esc(label)}: <a href="{esc(url)}">{esc(url)}</a>' for label, url in source_links(c)]


def dashboard_link_is_public() -> bool:
    """False when BASE_URL points at this PC only (127.0.0.1/localhost), where other readers can't open it."""
    return urlparse(base_url()).hostname not in LOOPBACK_HOSTS


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
            result = {"ok": True}
            try:
                message_id = resp.json().get("result", {}).get("message_id")
            except (ValueError, AttributeError):
                message_id = None
            if message_id is not None:
                result["message_id"] = message_id
            return result

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


def _api_call(token: str, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Calls a Bot API method; returns {"ok": True, "result": ...} or {"ok": False, "error": ...}."""
    try:
        resp = requests.post(f"https://api.telegram.org/bot{token}/{method}", json=payload, timeout=10)
        body = resp.json()
    except requests.RequestException as e:
        return {"ok": False, "error": f"Network error: {str(e).replace(token, '<token>')}"}
    except ValueError:
        return {"ok": False, "error": f"Telegram API error {resp.status_code}"}
    if body.get("ok"):
        return {"ok": True, "result": body.get("result")}
    return {"ok": False, "error": f"Telegram API error {resp.status_code}: {body.get('description', '')}"}


# ----------------------------------------------------------------------------
# Weekly edition marker
#
# Every PC with the bot token runs its own scheduler and keeps its own record of
# what it sent, so two PCs could both post the same week's digest. The channel's
# pinned message is the one record they all share: the header of each digest
# carries "Edition <ISO week>", gets pinned after sending, and a digest whose
# edition is already pinned is skipped.
# ----------------------------------------------------------------------------

EDITION_PATTERN = re.compile(r"Edition (\d{4}-W\d{2})")


def edition_label(now: Optional[datetime] = None) -> str:
    """ISO week of `now` in the pipeline's timezone, e.g. "2026-W45"."""
    tz = ZoneInfo(os.getenv("PIPELINE_TIMEZONE", "").strip() or "Asia/Singapore")
    year, week, _ = (now or datetime.now(timezone.utc)).astimezone(tz).isocalendar()
    return f"{year}-W{week:02d}"


def pinned_edition(token: str, chat_id: str) -> Dict[str, Any]:
    """The edition named in the chat's pinned message: {"ok": True, "edition": str|None} or an error."""
    result = _api_call(token, "getChat", {"chat_id": chat_id})
    if not result["ok"]:
        return result
    pinned = (result["result"] or {}).get("pinned_message") or {}
    match = EDITION_PATTERN.search(pinned.get("text") or pinned.get("caption") or "")
    return {"ok": True, "edition": match.group(1) if match else None}


def pin_message(token: str, chat_id: str, message_id: int) -> Dict[str, Any]:
    return _api_call(token, "pinChatMessage",
                     {"chat_id": chat_id, "message_id": message_id, "disable_notification": True})


# ----------------------------------------------------------------------------
# Weekly digest
# ----------------------------------------------------------------------------

def select_digest_items(candidates: List[Dict[str, Any]], days: int = 7, top_n: int = 10,
                        novelty: Optional[NoveltyChecker] = None) -> List[Dict[str, Any]]:
    """
    In-scope (Web/Mobile) incidents published in the last `days` days, highest
    priority first. Only items whose card passed the source-verification gate
    are sent; unverified and quarantined items are left out. The same CVE from
    several sources is sent once, and with a NoveltyChecker, items sent in an
    earlier digest are left out unless something new happened.
    """
    picked = []
    for c in candidates:
        if not (c.get("pre_filter") or {}).get("is_in_scope", False):
            continue
        if not c.get("grounded_card"):
            continue
        age = age_days((c.get("envelope") or {}).get("Published_Date"))
        if age is not None and age <= days:
            picked.append(c)
    picked.sort(key=lambda c: float(c.get("priority_score", 0.0)), reverse=True)
    picked = merge_same_flaw(picked)
    if novelty is not None:
        picked = novelty.filter(picked)
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
        (c.get("grounded_card") or {}).get("mechanism")
        or in_depth.get("brief_summary")
        or in_depth.get("full_description")
        or (c.get("ai_assessment") or {}).get("reasoning")
        or ""
    )


def format_digest_item(c: Dict[str, Any], rank: int) -> str:
    """One short message per incident: title, tag, score, 1-2 line summary, link to its page."""
    env = c.get("envelope") or {}
    category = (c.get("pre_filter") or {}).get("category", "")
    tag = {"WEB": "🌐 Web", "MOBILE": "📱 Mobile"}.get(category, category.title())
    score = float(c.get("priority_score", 0.0))
    heading = env.get("CVE_ID") or "Advisory"

    flags = []
    update = (c.get("novelty") or {})
    if update.get("status") == "UPDATE" and update.get("reasons"):
        flags.append("🔁 Update: " + ", ".join(update["reasons"]))
    points = c.get("score_breakdown") or {}
    # Story scoring: the kept copy may be the NVD record while the KEV entry or PoC came from a sibling
    if env.get("KEV_Status") or points.get("cisa_kev_points"):
        flags.append("🔥 Actively exploited")
    if env.get("PoC_URLs") or points.get("poc_points"):
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
        command = next((x for x in (c.get("grounded_card") or {}).get("testing_syntax") or [] if x), None)
        if command and summary_limit > 0:
            lines += ["", "Test:", f"<pre>{esc(_truncate(command, 300))}</pre>"]
        links = link_lines(c)
        if links:
            lines += [""] + links
        return "\n".join(lines)

    limit = SUMMARY_CHARS
    msg = build(limit)
    while len(msg) > MAX_MESSAGE_CHARS and limit > 0:
        limit = max(0, limit - 50)
        msg = build(limit)
    return msg


def format_digest_header(items: List[Dict[str, Any]], days: int = 7, edition: Optional[str] = None) -> str:
    web = sum(1 for c in items if (c.get("pre_filter") or {}).get("category") == "WEB")
    mobile = sum(1 for c in items if (c.get("pre_filter") or {}).get("category") == "MOBILE")
    period = "this week" if days == 7 else f"in the last {days} days"
    lines = ["🛡️ <b>GroundedCVE · Weekly Brief</b>"]
    if edition:
        lines.append(f"<i>Edition {esc(edition)}</i>")
    lines.append("")
    if items:
        lines.append(
            f"{len(items)} top incident{'s' if len(items) != 1 else ''} {period}: "
            f"{web} Web, {mobile} Mobile."
        )
        lines.append("Each card lists its NVD, source and PoC links.")
    else:
        lines.append(f"No new Web or Mobile incidents {period}.")
    return "\n".join(lines)


def compose_digest(items: List[Dict[str, Any]], days: int = 7, edition: Optional[str] = None) -> List[str]:
    """Header message followed by one message per incident."""
    return [format_digest_header(items, days, edition)] + [format_digest_item(c, i) for i, c in enumerate(items, 1)]


def build_weekly_digest(candidates: List[Dict[str, Any]], days: int = 7, top_n: int = 10,
                        novelty: Optional[NoveltyChecker] = None) -> List[str]:
    return compose_digest(select_digest_items(candidates, days=days, top_n=top_n, novelty=novelty), days)


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

        msg = (
            f"🚨 <b>[GroundedCVE Secondary Alert]</b>\n\n"
            f"<b>{esc(cve)}</b> — <i>{esc(pf.get('category', 'PENTEST'))}</i>\n"
            f"<b>Title:</b> {esc(title)}\n"
            f"<b>Priority Score:</b> <code>{esc(score)}/100.0</code>\n"
            f"<b>AI Practical Severity:</b> <code>{esc(ai_sev)}/10.0</code> (CVSS: <code>{esc(cvss)}</code>)\n"
            f"<b>Offensive Impact:</b> {esc(impact)}\n"
            f"<b>Weaponization:</b> {'🔥 Active CISA KEV Exploitation' if is_kev else '⚠️ Tracked Advisory'}\n"
        )

        if ai.get("reasoning"):
            msg += f"\n<b>AI Assessment:</b>\n<i>{esc(_truncate(ai['reasoning'], 200))}</i>\n"

        links = link_lines(candidate)
        if links:
            msg += "\n" + "\n".join(links)
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

    def send_digest(self, messages: List[str], chat_id: Optional[str] = None, pin: bool = False) -> Dict[str, Any]:
        """
        Sends the digest messages in order, pausing between each; stops at the first failure.
        With pin=True, a fully sent digest's header is pinned so other PCs see this edition was posted.
        """
        token = bot_token()
        cid = chat_id or self.chat_id()
        if not token:
            return {"sent": 0, "total": len(messages), "error": "TELEGRAM_BOT_TOKEN is not set in .env"}
        if not cid:
            return {"sent": 0, "total": len(messages), "error": "No chat id: set TELEGRAM_CHAT_ID in .env"}

        header_id = None
        for i, text in enumerate(messages):
            if i:
                time.sleep(SEND_PAUSE_SECONDS)
            result = send_message(token, cid, text)
            if not result["ok"]:
                return {"sent": i, "total": len(messages), "error": result["error"]}
            if i == 0:
                header_id = result.get("message_id")

        done = {"sent": len(messages), "total": len(messages), "error": None}
        if pin:
            pinned = pin_message(token, cid, header_id) if header_id is not None else {"ok": False, "error": "no message id returned"}
            done["pinned"] = pinned["ok"]
            done["pin_error"] = pinned.get("error")
        return done


telegram_service = TelegramService()
