"""
Concurrent Link Health Verification Engine.
Checks reference links in parallel with per-host limits, retries temporary
errors, detects redirect-to-homepage soft 404s, caches results with
state-dependent TTLs, and looks up archive.org snapshots for dead links.
"""
import concurrent.futures
import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

CACHE_DIR = Path(__file__).resolve().parent.parent / "data" / "cache"
CACHE_FILE = CACHE_DIR / "link_health_cache.json"

MAX_WORKERS = 30
MAX_PER_HOST = 6  # concurrent requests to any single host, to avoid rate limits / bot blocks
REQUEST_TIMEOUT = 8.0  # seconds
RETRY_DELAY_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 10.0
DEAD_AFTER_FAILURES = 2  # temporary errors on this many consecutive runs => dead

# Link states
LIVE = "live"            # 2xx at the expected page
DEAD = "dead"            # 404/410, or repeated failures
MOVED = "moved"          # redirected to a site's homepage; likely a soft 404
BLOCKED = "blocked"      # 401/403; the server refused us, page may or may not exist
TEMPORARY = "temporary"  # timeout, 429, 5xx, connection error; not yet confirmed dead
UNCHECKED = "unchecked"  # never requested

# How long a result stays fresh, by state
TTL_SECONDS = {
    LIVE: 12 * 3600,
    DEAD: 6 * 3600,
    MOVED: 6 * 3600,
    BLOCKED: 12 * 3600,
    TEMPORARY: 30 * 60,
}
DEFAULT_TTL_SECONDS = TTL_SECONDS[LIVE]

IS_WORKING = {LIVE: True, DEAD: False, MOVED: False, BLOCKED: None, TEMPORARY: None, UNCHECKED: None}

HEADERS = {
    "User-Agent": "GroundedCVE-LinkChecker/1.0 (+https://github.com/P1nkd0nut/ITP-2-Newsletter)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

WAYBACK_API = "https://archive.org/wayback/available?url="


def classify_link_type(url: str, explicit_type: Optional[str] = None) -> str:
    """Categorizes a URL into actionable threat intelligence link types."""
    if explicit_type:
        return explicit_type
    u_lower = url.lower()

    # Community forums, discussions, pull requests, issue trackers
    if any(k in u_lower for k in ["/issues/", "/pull/", "/discussions/", "forum", "reddit.com", "seclists.org", "groups.google", "mail-archive", "oss-security"]):
        return "Forum / Community Discussion"

    # Weaponized exploits, templates, and PoC repositories
    if any(k in u_lower for k in ["nuclei-templates", "vulhub", "payloadsallthethings", "exploit", "mastg", "poc", "metasploit", "packetstormsecurity"]):
        return "PoC / Weaponized Exploit"

    # Fixes, diffs, commits, patches
    if any(k in u_lower for k in ["/commit/", "/pull/", "/releases/tag/", "patch", "git-commit"]):
        return "Patch / Remediation Commit"

    # Vendor advisories and security bulletins
    if any(k in u_lower for k in ["support.apple", "source.android", "my.f5.com", "paloaltonetworks", "citrix.com", "advisories", "bulletin", "security."]):
        return "Vendor Security Advisory"

    # Official authority databases
    if any(k in u_lower for k in ["cve.org", "nvd.nist.gov", "cisa.gov"]):
        return "Authoritative Database Record"

    return "Technical Reference Link"


def infer_source_provider(url: str, context_source: Optional[str] = None) -> str:
    """Infers the source authority that published or cataloged this link."""
    if context_source:
        return context_source

    u_lower = url.lower()
    if "nvd.nist.gov" in u_lower or "cve.org" in u_lower:
        return "NVD / CVE Authority"
    if "github.com" in u_lower:
        return "GitHub Community / Research"
    if "cisa.gov" in u_lower:
        return "CISA KEV Catalog"
    if any(d in u_lower for d in ["apple.com", "android.com", "f5.com", "paloaltonetworks.com", "citrix.com", "microsoft.com"]):
        return "Vendor Security Portal"
    if "portswigger.net" in u_lower or "projectzero" in u_lower:
        return "Offensive Threat Lab"

    return "NVD / External Reference"


def title_from_url(url: str) -> str:
    """Builds a readable title from the last path segment of a URL."""
    url_obj = urllib.parse.urlparse(url)
    path_clean = url_obj.path.rstrip("/").split("/")[-1] or url_obj.netloc
    path_clean = urllib.parse.unquote(path_clean).replace("-", " ").replace("_", " ").title()
    return path_clean[:50]


def is_homepage_redirect(original_url: str, final_url: str) -> bool:
    """True when a deep link was redirected to a site root, a common soft-404 pattern."""
    orig = urllib.parse.urlparse(original_url)
    final = urllib.parse.urlparse(final_url)
    orig_path = orig.path.strip("/")
    final_path = final.path.strip("/")
    if not orig_path or original_url.rstrip("/") == final_url.rstrip("/"):
        return False
    # Allow a bare locale prefix like /en-us/ as "root"
    final_is_root = final_path == "" or (len(final_path) <= 5 and "/" not in final_path)
    return final_is_root and final_path != orig_path


def _status_label(state: str, status_code: int) -> str:
    code = f"{status_code} " if status_code else ""
    return {
        LIVE: f"{code}OK (Verified Live)",
        DEAD: f"{code}Dead Link" if status_code else "Dead Link (Unreachable)",
        MOVED: f"{code}Redirected to Homepage (Likely Removed)",
        BLOCKED: f"{code}Blocked by Site (Unverified)",
        TEMPORARY: f"{code}Temporary Error (Will Retry)" if status_code else "Timeout / Connection Error (Will Retry)",
        UNCHECKED: "Not Yet Checked",
    }[state]


class LinkValidator:
    """
    Concurrent link health validation engine with persistent caching.
    """

    def __init__(self, cache_file: Path = CACHE_FILE, archive_lookup: bool = True):
        self.cache_file = cache_file
        self.archive_lookup = archive_lookup
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = threading.Lock()
        self._host_locks: Dict[str, threading.BoundedSemaphore] = {}
        self._host_locks_lock = threading.Lock()
        self._load_cache()

    def _load_cache(self) -> None:
        """Loads verified link health records from persistent disk cache."""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                # Drop entries from older versions (no "state"), which include
                # placeholder "200 OK (Cataloged)" results that never hit the network
                self._cache = {url: rec for url, rec in loaded.items() if rec.get("state")}
            except Exception as e:
                logger.warning(f"Could not load link health cache: {e}")
                self._cache = {}

    def _save_cache(self) -> None:
        """Saves verified link health records to persistent disk cache."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with self._cache_lock:
                snapshot = dict(self._cache)
            tmp = self.cache_file.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
            tmp.replace(self.cache_file)
        except Exception as e:
            logger.warning(f"Could not save link health cache: {e}")

    def is_cache_valid(self, url: str, ttl_seconds: Optional[int] = None) -> bool:
        """Checks if a URL has an unexpired cached health result."""
        cached = self._cache.get(url)
        if not cached:
            return False
        ttl = ttl_seconds if ttl_seconds is not None else TTL_SECONDS.get(cached.get("state"), DEFAULT_TTL_SECONDS)
        return (time.time() - cached.get("last_checked_ts", 0)) < ttl

    def _host_semaphore(self, url: str) -> threading.BoundedSemaphore:
        host = urllib.parse.urlparse(url).netloc.lower()
        with self._host_locks_lock:
            if host not in self._host_locks:
                self._host_locks[host] = threading.BoundedSemaphore(MAX_PER_HOST)
            return self._host_locks[host]

    def _request(self, url: str, method: str) -> Tuple[int, str, Optional[str], Optional[float]]:
        """
        Performs one request. Returns (status_code, final_url, error, retry_after).
        status_code is 0 when no HTTP response was received.
        """
        headers = dict(HEADERS)
        if method == "GET":
            headers["Range"] = "bytes=0-2047"
        req = urllib.request.Request(url, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                if method == "GET":
                    resp.read(2048)
                return resp.getcode(), resp.geturl(), None, None
        except urllib.error.HTTPError as he:
            retry_after = None
            ra = he.headers.get("Retry-After") if he.headers else None
            if ra and ra.strip().isdigit():
                retry_after = float(ra.strip())
            return he.code, he.geturl() or url, str(he), retry_after
        except urllib.error.URLError as ue:
            return 0, url, str(ue.reason), None
        except (socket.timeout, TimeoutError) as te:
            return 0, url, f"timeout: {te}", None
        except Exception as e:
            return 0, url, str(e), None

    def _probe(self, url: str) -> Tuple[str, int, str, Optional[str]]:
        """Checks a URL with HEAD, falling back to GET, retrying temporary errors once."""
        status, final_url, error = 0, url, None
        for attempt in range(2):
            status, final_url, error, retry_after = self._request(url, "HEAD")
            if not (200 <= status < 300):
                # Many servers reject or mishandle HEAD (405, 403, even 404); confirm with a small GET
                status, final_url, error, retry_after = self._request(url, "GET")

            state = self._state_for(status, url, final_url)
            if state != TEMPORARY or attempt == 1:
                return state, status, final_url, error
            delay = min(retry_after or RETRY_DELAY_SECONDS, MAX_RETRY_AFTER_SECONDS)
            time.sleep(delay)
        return TEMPORARY, status, final_url, error

    @staticmethod
    def _state_for(status: int, url: str, final_url: str) -> str:
        if 200 <= status < 300:
            return MOVED if is_homepage_redirect(url, final_url) else LIVE
        if status in (404, 410):
            return DEAD
        if status in (401, 403):
            return BLOCKED
        return TEMPORARY  # 0 (timeout/connection), 429, 5xx, anything unexpected

    def _wayback_snapshot(self, url: str) -> Optional[str]:
        """Returns the closest archive.org snapshot URL for a dead link, if one exists."""
        try:
            req = urllib.request.Request(WAYBACK_API + urllib.parse.quote(url, safe=""), headers=HEADERS)
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            closest = data.get("archived_snapshots", {}).get("closest") or {}
            if closest.get("available") and closest.get("url"):
                return closest["url"].replace("http://", "https://", 1)
        except Exception as e:
            logger.debug(f"Wayback lookup failed for {url}: {e}")
        return None

    def _build_result(
        self,
        url: str,
        state: str,
        status_code: int,
        latency_ms: int,
        source_context: Optional[str],
        explicit_type: Optional[str],
        **extra: Any,
    ) -> Dict[str, Any]:
        result = {
            "url": url,
            "title": title_from_url(url),
            "state": state,
            "status_code": status_code,
            "is_working": IS_WORKING[state],
            "status_label": _status_label(state, status_code),
            "latency_ms": latency_ms,
            "link_type": classify_link_type(url, explicit_type),
            "source_provider": infer_source_provider(url, source_context),
            "final_url": url,
            "archive_url": None,
            "consecutive_failures": 0,
            "last_checked_iso": None,
            "last_checked_ts": 0,
            "error_detail": None,
        }
        result.update(extra)
        return result

    def check_single_link(
        self,
        url: str,
        source_context: Optional[str] = None,
        explicit_type: Optional[str] = None,
        force_refresh: bool = False,
        allow_network: bool = True,
    ) -> Dict[str, Any]:
        """
        Validates a single URL.
        If allow_network is False, returns the last cached result (even if stale) or an
        "unchecked" result, without blocking and without writing to the cache.
        """
        cached = self._cache.get(url)
        if cached and (not allow_network or (not force_refresh and self.is_cache_valid(url))):
            result = dict(cached)
            if source_context:
                result["source_provider"] = source_context
            if explicit_type:
                result["link_type"] = explicit_type
            return result

        if not allow_network:
            return self._build_result(url, UNCHECKED, 0, 0, source_context, explicit_type)

        start_time = time.perf_counter()
        with self._host_semaphore(url):
            state, status_code, final_url, error_msg = self._probe(url)
        elapsed_ms = int((time.perf_counter() - start_time) * 1000)

        failures = 0
        if state in (DEAD, MOVED, TEMPORARY):
            failures = (cached or {}).get("consecutive_failures", 0) + 1
            if state == TEMPORARY and failures >= DEAD_AFTER_FAILURES:
                state = DEAD

        archive_url = (cached or {}).get("archive_url")
        if state in (DEAD, MOVED) and not archive_url and self.archive_lookup:
            archive_url = self._wayback_snapshot(url)

        result = self._build_result(
            url, state, status_code, elapsed_ms, source_context, explicit_type,
            final_url=final_url,
            archive_url=archive_url,
            consecutive_failures=failures,
            last_checked_iso=datetime.now(timezone.utc).isoformat(),
            last_checked_ts=time.time(),
            error_detail=error_msg,
        )

        with self._cache_lock:
            self._cache[url] = result
        return result

    def validate_batch(
        self,
        url_descriptors: List[Dict[str, Any]],
        force_refresh: bool = False,
        max_workers: int = MAX_WORKERS,
    ) -> List[Dict[str, Any]]:
        """
        Validates a collection of URLs concurrently.
        Takes a list of dicts: [{"url": "...", "source": "NVD Reference", "type": "PoC"}]
        """
        if not url_descriptors:
            return []

        # Deduplicate while preserving context
        dedup_map: Dict[str, Dict[str, Any]] = {}
        for item in url_descriptors:
            url = item.get("url")
            if url and url.startswith("http"):
                if url not in dedup_map:
                    dedup_map[url] = item

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {
                executor.submit(
                    self.check_single_link,
                    url=desc["url"],
                    source_context=desc.get("source"),
                    explicit_type=desc.get("type"),
                    force_refresh=force_refresh,
                ): desc["url"]
                for desc in dedup_map.values()
            }

            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    results.append(future.result())
                except Exception as e:
                    url = future_to_url[future]
                    logger.warning(f"Link check crashed for {url}: {e}")
                    results.append(self._build_result(
                        url, TEMPORARY, 0, 0, None, "Unknown", error_detail=str(e),
                    ))

        self._save_cache()
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Returns summary statistics for links in cache."""
        with self._cache_lock:
            records = list(self._cache.values())
        counts = {s: 0 for s in (LIVE, DEAD, MOVED, BLOCKED, TEMPORARY)}
        for r in records:
            counts[r.get("state", TEMPORARY)] = counts.get(r.get("state", TEMPORARY), 0) + 1
        total = len(records)
        confirmed = counts[LIVE] + counts[DEAD] + counts[MOVED]
        latencies = [r.get("latency_ms", 0) for r in records if r.get("latency_ms", 0) > 0]
        avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else 0.0

        return {
            "total_cached": total,
            "active_links": counts[LIVE],
            "dead_links": counts[DEAD] + counts[MOVED],
            "blocked_links": counts[BLOCKED],
            "temporary_errors": counts[TEMPORARY],
            "archived_fallbacks": sum(1 for r in records if r.get("archive_url")),
            # Share of links we could actually confirm one way or the other that are live
            "health_percentage": round((counts[LIVE] / confirmed) * 100, 1) if confirmed else None,
            "avg_latency_ms": avg_latency,
        }

    def dead_links(self) -> List[Dict[str, Any]]:
        """Returns cached records confirmed dead or moved."""
        with self._cache_lock:
            return [dict(r) for r in self._cache.values() if r.get("state") in (DEAD, MOVED)]


# Global singleton instance
link_validator = LinkValidator()
