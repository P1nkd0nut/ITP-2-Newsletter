"""
Utility functions for hashing, date parsing, and robust HTTP fetching.
"""
import hashlib
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any
import urllib.request
import urllib.error
from Backend.config import DEFAULT_USER_AGENT


def compute_content_hash(content: str) -> str:
    """Computes a deterministic SHA-256 hash for raw content."""
    if not content:
        return hashlib.sha256(b"").hexdigest()
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def get_utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def normalize_to_iso(date_input: Any) -> str:
    """
    Normalizes various date formats (strings, time_structs) to ISO 8601 UTC string.
    """
    if not date_input:
        return get_utc_now_iso()

    # Handle time.struct_time (from feedparser)
    if isinstance(date_input, time.struct_time):
        dt = datetime(*date_input[:6], tzinfo=timezone.utc)
        return dt.isoformat()

    # Handle datetime object
    if isinstance(date_input, datetime):
        if date_input.tzinfo is None:
            date_input = date_input.replace(tzinfo=timezone.utc)
        return date_input.isoformat()

    # String date parsing
    s = str(date_input).strip()
    formats_to_try = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%a, %d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S %z",
    ]
    for fmt in formats_to_try:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue

    # Fallback if no format matched
    return s


def fetch_url(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 15,
    max_retries: int = 3,
    retry_delay: float = 2.0,
) -> str:
    """
    Fetches raw text content from a URL with retry logic and polite headers.
    """
    req_headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "*/*"}
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers)
    
    last_exc = None
    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                content_bytes = response.read()
                return content_bytes.decode(charset, errors="replace")
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            last_exc = e
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))
            else:
                raise last_exc
    raise RuntimeError(f"Failed to fetch {url} after {max_retries} attempts.")
