"""
Data access and intelligence curation service for GroundedCVE.
Loads, filters, aggregates, and formats triaged threat intelligence candidates.
"""
import json
import logging
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from Backend.ingestion.recheck_policy import FREEZE_NOTICE, age_days, is_frozen, recency_label
from Backend.summarisation.card_store import load_cards
from Backend.api.novelty import merge_same_flaw
from .link_validator import link_validator

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
STAGING_DIR = ROOT_DIR / "Backend" / "data" / "staging"
TRIAGED_FILE = STAGING_DIR / "triaged_candidates.json"
ENVELOPES_FILE = STAGING_DIR / "latest_envelopes.json"
GROUNDED_CARDS_FILE = STAGING_DIR / "grounded_cards.json"
# Cards from a real run, committed so a fresh clone (no OpenRouter key yet) still
# shows verified summaries. Used only when the live file does not exist.
DEMO_CARDS_FILE = STAGING_DIR.parent / "demo" / "grounded_cards.json"


def _names_cve(cve_id: Optional[str], text: Optional[str]) -> bool:
    """True if text names this exact CVE (CVE-2024-3400 does not match CVE-2024-34001)."""
    if not cve_id or not text:
        return False
    normalized = text.upper().replace("_", "-")
    return re.search(rf"(?<![0-9]){re.escape(cve_id.upper())}(?![0-9])", normalized) is not None


def describe_poc(url: str, cve_id: Optional[str], detail: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Labels a PoC link with where it came from and whether it is specific to this CVE."""
    if detail and detail.get("source"):
        found_via = detail["source"]
        if detail.get("matched_on"):
            found_via += f"; CVE ID matched in {detail['matched_on']}"
        if detail.get("stars"):
            found_via += f"; {detail['stars']} stars"
        return {"source": "PoC Exploit Repository", "type": "PoC / Weaponized Exploit", "found_via": found_via}
    if detail:
        # Saved by an older GitHub search run, before results were checked for the CVE ID
        return {
            "source": "PoC Exploit Repository",
            "type": "PoC / Weaponized Exploit",
            "found_via": "GitHub repository search (older run; CVE match not checked)",
        }
    if _names_cve(cve_id, url):
        return {
            "source": "PoC Exploit Repository",
            "type": "PoC / Weaponized Exploit",
            "found_via": "Listed in the source record (no search record kept)",
        }
    # A link that does not name the CVE is a general tool repo, not proof of a PoC for this CVE
    return {
        "source": "Generic Tool Repository",
        "type": "Not CVE-Specific (Demo Placeholder)",
        "found_via": "Hand-entered in the seed data; this repo does not name this CVE",
    }


def references_provenance(env: Dict[str, Any]) -> str:
    """Says which feed supplied an item's reference list."""
    cve_id = env.get("CVE_ID") or "this item"
    source_type = env.get("Source_Type")
    if source_type == "GITHUB_ADVISORY":
        ghsa_id = (env.get("Extra_Metadata") or {}).get("ghsa_id")
        return f"GitHub Advisory {ghsa_id} reference list" if ghsa_id else "GitHub Advisory reference list"
    if source_type == "NVD":
        return f"NVD reference list for {cve_id}"
    return f"Reference list in the {source_type or 'source'} record"


def date_windows(today: Optional[date] = None) -> Dict[str, str]:
    """ISO dates for the Today / Past 7 Days filters, based on the server's current date."""
    today = today or date.today()
    return {"today": today.isoformat(), "week_start": (today - timedelta(days=7)).isoformat()}


def standard_category_for(ai: Dict[str, Any], title: str) -> str:
    """
    Maps the AI's free-text offensive_impact onto the dashboard's fixed category
    list, so cards never show raw model text such as "File Upload with
    Attacker-Controlled Content | Potential for Chaining...".
    """
    impact = (ai.get("offensive_impact") or "").lower()
    title_low = title.lower()

    def has(text: str, *terms: str) -> bool:
        return any(re.search(rf"\b{re.escape(t)}\b", text) for t in terms)

    if float(ai.get("severity_score") or 0.0) == 0.0 or impact.strip() in ("", "none", "n/a", "not applicable"):
        return "Not a specific vulnerability"
    if has(impact, "remote code execution", "rce", "code execution", "code injection") or has(title_low, "remote code execution"):
        return "Remote Code Execution (RCE)"
    if has(impact, "authentication", "auth bypass", "session", "account takeover") or has(title_low, "auth bypass", "authentication bypass"):
        return "Authentication & Session Bypass"
    if has(impact, "ssrf", "server-side request forgery") or has(title_low, "ssrf"):
        return "Server-Side Request Forgery (SSRF)"
    if has(impact, "sql injection", "sqli", "command injection", "os command") or has(title_low, "sql injection", "command injection"):
        return "Command & SQL Injection"
    if has(impact, "ipc", "intent", "intent hijacking", "component hijacking", "exported component"):
        return "Mobile Component Hijacking"
    if has(impact, "buffer overflow", "memory corruption", "use-after-free", "heap overflow", "out-of-bounds") or has(title_low, "buffer overflow"):
        return "Memory Corruption"
    if has(impact, "desync", "smuggling") or has(title_low, "request smuggling"):
        return "Protocol Desync & Smuggling"
    if has(impact, "frida", "hooking", "crypto", "cryptographic", "certificate pinning") or has(title_low, "cryptographic"):
        return "Mobile Security & Cryptography"
    if has(impact, "privilege escalation"):
        return "Privilege Escalation"
    if has(impact, "denial of service", "dos", "resource exhaustion"):
        return "Denial of Service (DoS)"
    if has(impact, "xss", "cross-site scripting", "path traversal", "directory traversal", "traversal", "file upload", "csrf", "open redirect"):
        return "Web Injection & Traversal"
    if has(impact, "information disclosure", "data exposure", "sensitive information", "data exfiltration"):
        return "Information Disclosure"
    return "Other"


def severity_band(score: float) -> str:
    """Words for an AI practical severity rating, using the bands in the scoring prompt."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def explain_score(in_scope: bool, kev_pts: float, ai_pts: float, poc_pts: float, total: float,
                  ai_sev: float, reasoning: Optional[str], scope_reason: Optional[str]):
    """
    One line per factor of the 100-point score, plus a verdict. The verdict is
    based on the factors, not on the total: an item that is not in CISA KEV and
    has no public PoC can score at most 40, however severe it is, so labelling
    by total alone would call a critical RCE "low risk".
    """
    if kev_pts > 0:
        kev_eval = ("+40 pts: listed in CISA's Known Exploited Vulnerabilities catalogue, "
                    "so attackers have been seen using it.")
    else:
        kev_eval = ("0 pts: not in CISA KEV. This does not rule out exploitation; "
                    "none has been confirmed.")
    if poc_pts > 0:
        poc_eval = ("+20 pts: a public GitHub repository names this CVE as a proof of concept "
                    "(linked below; not run or verified by us).")
    else:
        poc_eval = "0 pts: no public proof-of-concept repository found for this CVE."
    ai_eval = (f"+{ai_pts:.1f} of 40 pts (rated {ai_sev:.1f}/10, {severity_band(ai_sev)}): "
               f"{reasoning or 'Practical attack impact assessed from the advisory text.'}")

    band = f"practical severity {ai_sev:.1f}/10 ({severity_band(ai_sev)})"
    if not in_scope:
        verdict = f"OUT OF SCOPE (0/100): {scope_reason or 'Not a web or mobile testing target.'}"
    elif kev_pts > 0:
        verdict = (f"EXPLOITED IN THE WILD ({total:.1f}/100): in CISA KEV, so it ranks above every item "
                   f"that is not. Among KEV items it is ordered by {band} and public PoC availability.")
    elif poc_pts > 0:
        verdict = (f"PUBLIC POC AVAILABLE ({total:.1f}/100): not in CISA KEV, but public exploit code exists. "
                   f"Ranked by {band}.")
    else:
        verdict = (f"NO KNOWN EXPLOITATION ({total:.1f}/100): not in CISA KEV and no public PoC found, "
                   f"so it is ranked on {band} alone (at most 40 points).")
    return kev_eval, poc_eval, ai_eval, verdict

class DataService:
    def __init__(self):
        self._cache: Optional[List[Dict[str, Any]]] = None
        self._last_loaded: Optional[str] = None
        self._source_stamp: tuple = ()

    @staticmethod
    def _files_stamp() -> tuple:
        """Modification times of the files the cache is built from."""
        return tuple(p.stat().st_mtime_ns if p.exists() else 0
                     for p in (TRIAGED_FILE, ENVELOPES_FILE, GROUNDED_CARDS_FILE))

    def reload(self) -> List[Dict[str, Any]]:
        """Force reloads data from disk."""
        self._cache = None
        return self.get_all_candidates()

    def get_all_candidates(self) -> List[Dict[str, Any]]:
        """
        Returns all candidates from storage, caching in memory. The cache is
        rebuilt when the scheduler rewrites triage output or the grounded cards.
        """
        stamp = self._files_stamp()
        if self._cache is not None and stamp == self._source_stamp:
            return self._cache
        self._source_stamp = stamp

        data: List[Dict[str, Any]] = []
        if TRIAGED_FILE.exists():
            try:
                with open(TRIAGED_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._last_loaded = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                logger.error(f"Error loading triaged candidates: {e}")
        elif ENVELOPES_FILE.exists():
            # Fallback if triage hasn't run yet
            try:
                with open(ENVELOPES_FILE, "r", encoding="utf-8") as f:
                    raw_envelopes = json.load(f)
                    data = [
                        {
                            "envelope": env,
                            "pre_filter": {
                                "category": "WEB",
                                "matched_by": "FALLBACK",
                                "reason": "Pre-triage fallback envelope",
                                "is_in_scope": True,
                            },
                            "ai_assessment": None,
                            "priority_score": 0.0,
                            "score_breakdown": {},
                            "discrepancy": None,
                            "triaged_at": env.get("Ingested_At", ""),
                        }
                        for env in raw_envelopes
                    ]
            except Exception as e:
                logger.error(f"Error loading fallback envelopes: {e}")

        # Enrich each candidate with direct CVE links, vendor bulletins, and detailed descriptions
        cards = load_cards(GROUNDED_CARDS_FILE if GROUNDED_CARDS_FILE.exists() else DEMO_CARDS_FILE)
        for c in data:
            self._enrich_candidate(c)
            self._attach_grounded_card(c, cards)

        # Ensure sorted by priority score descending by default
        data.sort(key=lambda x: x.get("priority_score", 0.0), reverse=True)
        self._cache = data
        return self._cache

    def _enrich_candidate(self, c: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enriches a candidate with direct authoritative CVE links, extracted vendor bulletins,
        and structured vulnerability explanations for the in-depth modal.
        """
        env = c.get("envelope", {})
        cve_id = env.get("CVE_ID")
        raw_content = env.get("Raw_Content", "")

        # Direct authoritative CVE link (cve.org) and NIST NVD link
        if cve_id:
            env["cve_url"] = f"https://www.cve.org/CVERecord?id={cve_id}"
            env["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            # If Source_URL points to a generic CISA search page, redirect primary source to direct CVE record
            src_url = env.get("Source_URL", "")
            if "cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=" in src_url:
                env["Source_URL"] = f"https://www.cve.org/CVERecord?id={cve_id}"

        # Extract direct vendor bulletins and advisory links from Extra_Metadata or Raw_Content
        vendor_urls = []
        extra_meta = env.get("Extra_Metadata") or {}
        source_type = env.get("Source_Type", "Feed")
        # No collector writes vendor_bulletins, so these were entered by hand in the seed data
        vendor_provenance = "Hand-entered in the seed data (not fetched by a collector)"
        if extra_meta.get("vendor_bulletins"):
            vendor_urls.extend(extra_meta.get("vendor_bulletins"))

        # Fallback to Raw_Content extraction with strict filtering against namespaces and noise
        if not vendor_urls and raw_content:
            urls = re.findall(r'https?://[^\s"\'<>]+', raw_content)
            for u in urls:
                clean_u = u.rstrip(';.,)')
                if any(bad in clean_u.lower() for bad in ["cisa.gov", "w3.org", "ogp.me", "googleapis.com", "gstatic.com", "vuldb.com", "supportmetrics"]):
                    continue
                if clean_u not in vendor_urls:
                    vendor_urls.append(clean_u)
            vendor_provenance = f"Found in the text of the {source_type} record"

        # Parse structured attributes if raw_content is JSON (e.g. CISA KEV or NVD)
        parsed_json = {}
        if raw_content and raw_content.strip().startswith("{"):
            try:
                parsed_json = json.loads(raw_content)
            except Exception:
                pass

        short_desc = parsed_json.get("shortDescription")
        vuln_name = parsed_json.get("vulnerabilityName")
        req_action = parsed_json.get("requiredAction")
        notes = parsed_json.get("notes")
        cwes = parsed_json.get("cwes") or env.get("CWE")

        ai = c.get("ai_assessment") or {}
        pf = c.get("pre_filter") or {}

        # Standardize category
        standard_category = standard_category_for(ai, env.get("Title") or "")

        c["standard_category"] = standard_category

        # Publication date is kept only for filtering/sorting; users see a relative label
        pub_date_raw = env.get("Published_Date", "")
        pub_date_iso = pub_date_raw[:10]
        try:
            pub_date_iso = datetime.fromisoformat(pub_date_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d")
        except ValueError:
            pass
        pub_date_fmt = recency_label(pub_date_raw)
        c["published_date_iso"] = pub_date_iso
        c["published_date_formatted"] = pub_date_fmt
        c["recency_label"] = pub_date_fmt
        c["updates_frozen"] = is_frozen(pub_date_raw)
        c["freeze_notice"] = FREEZE_NOTICE if c["updates_frozen"] else None
        last_checked = env.get("Last_Checked") or env.get("Last_Seen")
        checked_age = age_days(last_checked)
        c["checked_label"] = (
            None if checked_age is None
            else "Checked today" if checked_age == 0
            else f"Checked {checked_age} day{'s' if checked_age != 1 else ''} ago"
        )

        # Structured AI evaluation breakdown for why it is rated high/low
        score_bd = c.get("score_breakdown") or {}
        kev_pts = float(score_bd.get("cisa_kev_points", 0.0))
        ai_pts = float(score_bd.get("ai_severity_points", 0.0))
        poc_pts = float(score_bd.get("poc_points", 0.0))
        total_score = float(c.get("priority_score", 0.0))
        ai_sev = float(ai.get("severity_score", 0.0))

        kev_eval, poc_eval, ai_eval, ai_verdict = explain_score(
            pf.get("is_in_scope", False), kev_pts, ai_pts, poc_pts, total_score, ai_sev,
            ai.get("reasoning"), pf.get("reason"),
        )

        c["ai_evaluation_breakdown"] = {
            "total_score": total_score,
            "cisa_kev_points": kev_pts,
            "cisa_kev_evaluation": kev_eval,
            "ai_severity_points": ai_pts,
            "ai_severity_rating": ai_sev,
            "ai_severity_evaluation": ai_eval,
            "poc_points": poc_pts,
            "poc_evaluation": poc_eval,
            "ai_verdict": ai_verdict,
            "evaluated_by": ai.get("evaluated_by", "Qwen 2.5 72B"),
            "offensive_impact": ai.get("offensive_impact", standard_category),
        }

        # Synthesize a clean 1-2 sentence brief for the card
        brief_summary = short_desc or ai.get("reasoning") or pf.get("reason") or env.get("Title", "")
        # Truncate clean first sentence if too long
        if len(brief_summary) > 220:
            brief_summary = brief_summary[:217] + "..."

        # Build comprehensive verified external references (NVD, CVE, PoCs, Forums, Bulletins)
        refs_to_check = []
        seen_urls = set()

        # 1. Authoritative Database Records (cve.org and nvd.nist.gov)
        if cve_id:
            cve_rec_url = f"https://www.cve.org/CVERecord?id={cve_id}"
            nvd_rec_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            refs_to_check.append({
                "url": cve_rec_url,
                "source": "CVE.org Official",
                "type": "Authoritative Database Record",
                "found_via": f"Built from the CVE ID ({cve_id})",
            })
            seen_urls.add(cve_rec_url)
            refs_to_check.append({
                "url": nvd_rec_url,
                "source": "NVD NIST Official",
                "type": "Authoritative Database Record",
                "found_via": f"Built from the CVE ID ({cve_id})",
            })
            seen_urls.add(nvd_rec_url)

        # 2. PoC exploit repositories, labelled with where each one was found
        poc_details = {d.get("url"): d for d in (env.get("PoC_Details") or []) if isinstance(d, dict)}
        for poc_url in (env.get("PoC_URLs") or []):
            if poc_url and poc_url not in seen_urls:
                refs_to_check.append({"url": poc_url, **describe_poc(poc_url, cve_id, poc_details.get(poc_url))})
                seen_urls.add(poc_url)

        # 3. NVD / CVE references (including community forums, issues, commits, advisories)
        for ref_url in (extra_meta.get("references") or []):
            if ref_url and ref_url not in seen_urls:
                refs_to_check.append({
                    "url": ref_url,
                    "source": "NVD / CVE Reference",
                    "type": None,  # Will be classified by validator
                    "found_via": references_provenance(env),
                })
                seen_urls.add(ref_url)

        # 4. Vendor Bulletins & Security Portals
        for vb_url in vendor_urls:
            if vb_url and vb_url not in seen_urls:
                refs_to_check.append({
                    "url": vb_url,
                    "source": "Vendor Advisory Portal",
                    "type": "Vendor Security Advisory",
                    "found_via": vendor_provenance,
                })
                seen_urls.add(vb_url)

        # 5. Primary feed source if unique
        primary_src = env.get("Source_URL")
        if primary_src and primary_src not in seen_urls:
            refs_to_check.append({
                "url": primary_src,
                "source": f"{env.get('Source_Type', 'Feed')} Primary Source",
                "type": "Primary Feed Source",
                "found_via": f"Source URL of the {source_type} feed item",
            })
            seen_urls.add(primary_src)

        # Validate with fast cache-backed LinkValidator
        verified_refs = []
        for r_desc in refs_to_check:
            verified = link_validator.check_single_link(
                url=r_desc["url"],
                source_context=r_desc.get("source"),
                explicit_type=r_desc.get("type"),
                force_refresh=False,
                allow_network=False,
            )
            verified["found_via"] = r_desc.get("found_via")
            verified_refs.append(verified)

        c["external_references"] = verified_refs

        # Facts shown beside the verified card: affected versions (from the NVD
        # record) and the public PoC repositories with their link state. These come
        # from structured fields, not from the model, so the gate doesn't check them.
        versions = env.get("Affected_Versions") or []
        if isinstance(versions, str):
            versions = [versions]
        if versions and source_type == "NVD":
            versions_from = f"NVD record for {cve_id}" if cve_id else "NVD record"
        elif versions:
            versions_from = extra_meta.get("affected_versions_from") or f"{source_type} record"
        else:
            versions_from = None
        poc_urls = set(env.get("PoC_URLs") or [])
        pocs = [
            {k: r.get(k) for k in ("url", "found_via", "state", "status_label", "archive_url")}
            for r in verified_refs
            if r.get("url") in poc_urls and r.get("state") not in ("dead", "moved")
        ]
        c["source_facts"] = {"affected_versions": list(versions)[:12], "versions_from": versions_from, "pocs": pocs[:2]}

        c["in_depth"] = {
            "brief_summary": brief_summary,
            "vulnerability_name": vuln_name,
            "full_description": short_desc or ai.get("reasoning") or env.get("Title", ""),
            "required_action": req_action,
            "notes": notes,
            "cwes": cwes,
            "vendor_bulletins": vendor_urls[:4],
            "cve_url": env.get("cve_url"),
            "nvd_url": env.get("nvd_url"),
            "standard_category": standard_category,
            "published_date_formatted": pub_date_fmt,
            "published_date_iso": pub_date_iso,
            "updates_frozen": c["updates_frozen"],
            "freeze_notice": c["freeze_notice"],
            "checked_label": c["checked_label"],
            "ai_evaluation_breakdown": c["ai_evaluation_breakdown"],
            "external_references": verified_refs,
        }
        return c

    @staticmethod
    def _attach_grounded_card(c: Dict[str, Any], cards: Dict[str, Dict[str, Any]]) -> None:
        """
        Attach the item's gate-PASSED card (grounded_cards.json only holds passed
        cards). A card written from an older version of the source is ignored.
        Items without one get grounded_card = None and are left out of digests.
        """
        env = c.get("envelope", {})
        rec = cards.get(env.get("Item_ID"))
        if not rec or rec.get("Content_Hash") != env.get("Content_Hash"):
            c["grounded_card"] = None
            return

        card = rec["card"]
        c["grounded_card"] = {
            **card,
            "checks_run": (rec.get("verification") or {}).get("checks_run", 0),
            "attempts": (rec.get("verification") or {}).get("attempts", 1),
            "chunk_ids": rec.get("chunk_ids", []),
            "model": rec.get("model"),
            "generated_at": rec.get("generated_at"),
        }
        in_depth = c.setdefault("in_depth", {})
        brief = card.get("mechanism", "")
        in_depth["brief_summary"] = brief if len(brief) <= 220 else brief[:217] + "..."
        in_depth["full_description"] = " ".join(x for x in (card.get("mechanism"), card.get("impact")) if x)
        in_depth["grounded_card"] = c["grounded_card"]

    def get_candidate_by_id(self, item_id: str) -> Optional[Dict[str, Any]]:
        """Lookup a candidate by Item_ID or CVE_ID."""
        item_id_lower = item_id.strip().lower()
        candidates = self.get_all_candidates()
        for c in candidates:
            env = c.get("envelope", {})
            cve = (env.get("CVE_ID") or "").lower()
            iid = (env.get("Item_ID") or "").lower()
            if iid == item_id_lower or cve == item_id_lower:
                return c
        return None

    def query_candidates(
        self,
        scope: Optional[str] = None,
        search: Optional[str] = None,
        discrepancy_only: bool = False,
        source: Optional[str] = None,
        category: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        date_preset: Optional[str] = None,
        min_score: Optional[float] = None,
        sort_by: str = "priority_score",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 20,
    ) -> Dict[str, Any]:
        """
        Query candidates with rich filtering, searching, sorting, and pagination.
        """
        items = list(self.get_all_candidates())

        # 1. Scope filter
        if scope:
            scope_upper = scope.strip().upper()
            if scope_upper == "IN_SCOPE":
                items = [x for x in items if x.get("pre_filter", {}).get("is_in_scope", False)]
            elif scope_upper in ["WEB", "MOBILE", "OUT_OF_SCOPE"]:
                items = [x for x in items if x.get("pre_filter", {}).get("category") == scope_upper]

        # 2. Source filter
        if source:
            src_upper = source.strip().upper()
            items = [x for x in items if (x.get("envelope", {}).get("Source_Type") or "").upper() == src_upper]

        # 3. Discrepancy only
        if discrepancy_only:
            items = [x for x in items if (x.get("discrepancy") or {}).get("is_discrepancy", False)]

        # 4. Category filter
        if category and category.upper() != "ALL":
            cat_lower = category.strip().lower()
            items = [
                x for x in items
                if cat_lower in (x.get("standard_category") or "").lower()
                or cat_lower in ((x.get("ai_assessment") or {}).get("offensive_impact") or "").lower()
            ]

        # 5. Date filter (presets & range)
        if date_preset:
            dp_lower = date_preset.strip().lower()
            win = date_windows()
            if dp_lower in ["today", "today_oct19", "oct19", "19oct"]:
                items = [
                    x for x in items
                    if (x.get("published_date_iso") or "") == win["today"]
                ]
            elif dp_lower in ["week", "week_oct12", "7days"]:
                items = [
                    x for x in items
                    if win["week_start"] <= (x.get("published_date_iso") or "") <= win["today"]
                ]
            elif dp_lower in ["oct12", "12oct"]:
                items = [
                    x for x in items
                    if (x.get("published_date_iso") or "") == "2026-10-12"
                ]

        if start_date:
            items = [x for x in items if (x.get("published_date_iso") or "") >= start_date]
        if end_date:
            items = [x for x in items if (x.get("published_date_iso") or "") <= end_date]

        # 6. Minimum score
        if min_score is not None:
            items = [x for x in items if float(x.get("priority_score", 0.0)) >= float(min_score)]

        # 7. Full text search
        if search:
            q = search.strip().lower()
            filtered = []
            for item in items:
                env = item.get("envelope", {})
                pf = item.get("pre_filter", {})
                ai = (item.get("ai_assessment") or {})
                std_cat = item.get("standard_category", "")
                search_blob = " ".join([
                    str(env.get("CVE_ID") or ""),
                    str(env.get("Title") or ""),
                    str(env.get("Vendor_Product") or ""),
                    str(env.get("Source_Type") or ""),
                    str(env.get("CWE") or ""),
                    str(std_cat),
                    str(pf.get("reason") or ""),
                    str(ai.get("offensive_impact") or ""),
                    str(ai.get("reasoning") or ""),
                ]).lower()
                if q in search_blob:
                    filtered.append(item)
            items = filtered

        # 8. Sorting
        reverse = sort_order.lower() == "desc"
        if sort_by == "timeline":
            win = date_windows()

            def timeline_key(x):
                dt_iso = x.get("published_date_iso") or ""
                p_score = float(x.get("priority_score", 0.0))
                if dt_iso >= win["today"]:
                    tier = 0
                elif dt_iso >= win["week_start"]:
                    tier = 1
                else:
                    tier = 2
                return (tier, -p_score if reverse else p_score)
            items.sort(key=timeline_key)
        elif sort_by in ["published_date", "date"]:
            items.sort(key=lambda x: x.get("envelope", {}).get("Published_Date", "") or "", reverse=reverse)
        elif sort_by == "priority_score":
            items.sort(key=lambda x: float(x.get("priority_score", 0.0)), reverse=reverse)
        elif sort_by == "ai_severity":
            items.sort(
                key=lambda x: float((x.get("ai_assessment") or {}).get("severity_score", 0.0)),
                reverse=reverse,
            )
        elif sort_by == "cvss":
            items.sort(
                key=lambda x: float(x.get("envelope", {}).get("CVSS") or 0.0),
                reverse=reverse,
            )
        elif sort_by == "title":
            items.sort(key=lambda x: (x.get("envelope", {}).get("Title") or "").lower(), reverse=reverse)

        total_count = len(items)
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 1

        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        paged_items = items[start_idx:end_idx]

        return {
            "total": total_count,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "items": paged_items,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Calculates executive KPI analytics, charts data, and anomaly summaries."""
        candidates = self.get_all_candidates()
        total = len(candidates)
        in_scope = [x for x in candidates if x.get("pre_filter", {}).get("is_in_scope", False)]
        out_scope = [x for x in candidates if not x.get("pre_filter", {}).get("is_in_scope", False)]
        web = [x for x in candidates if x.get("pre_filter", {}).get("category") == "WEB"]
        mobile = [x for x in candidates if x.get("pre_filter", {}).get("category") == "MOBILE"]
        anomalies = [x for x in candidates if (x.get("discrepancy") or {}).get("is_discrepancy", False)]
        kev_items = [
            x for x in in_scope
            if x.get("envelope", {}).get("KEV_Status")
            or x.get("score_breakdown", {}).get("cisa_kev_points", 0.0) > 0
        ]
        poc_items = [
            x for x in in_scope
            if x.get("envelope", {}).get("PoC_URLs")
            or x.get("score_breakdown", {}).get("poc_points", 0.0) > 0
        ]

        # Score calculations
        in_scope_scores = [float(x.get("priority_score", 0.0)) for x in in_scope]
        avg_score = round(sum(in_scope_scores) / len(in_scope_scores), 1) if in_scope_scores else 0.0
        max_score = round(max(in_scope_scores), 1) if in_scope_scores else 0.0

        # Score Distribution Bands
        critical_band = [s for s in in_scope_scores if s >= 80.0]
        high_band = [s for s in in_scope_scores if 60.0 <= s < 80.0]
        medium_band = [s for s in in_scope_scores if 40.0 <= s < 60.0]
        low_band = [s for s in in_scope_scores if s < 40.0]

        # Source breakdown
        sources: Dict[str, int] = {}
        for c in candidates:
            st = c.get("envelope", {}).get("Source_Type", "OTHER")
            sources[st] = sources.get(st, 0) + 1

        # Offensive impact distribution
        impacts: Dict[str, int] = {}
        for c in in_scope:
            imp = (c.get("ai_assessment") or {}).get("offensive_impact")
            if imp:
                impacts[imp] = impacts.get(imp, 0) + 1

        # Anomalies detail
        anomaly_list = []
        for a in anomalies:
            env = a.get("envelope", {})
            disc = (a.get("discrepancy") or {})
            anomaly_list.append({
                "item_id": env.get("Item_ID"),
                "cve_id": env.get("CVE_ID"),
                "title": env.get("Title"),
                "cvss": disc.get("cvss_score"),
                "ai_severity": disc.get("ai_severity"),
                "delta": disc.get("delta"),
                "troubleshoot_note": disc.get("troubleshoot_note"),
            })

        # Top 5 ranked
        top_ranked = []
        for x in candidates[:5]:
            env = x.get("envelope", {})
            pf = x.get("pre_filter", {})
            ai = (x.get("ai_assessment") or {})
            top_ranked.append({
                "item_id": env.get("Item_ID"),
                "cve_id": env.get("CVE_ID") or env.get("Item_ID"),
                "title": env.get("Title"),
                "category": pf.get("category"),
                "priority_score": x.get("priority_score"),
                "ai_severity": (ai or {}).get("severity_score"),
                "impact": (ai or {}).get("offensive_impact"),
                "has_poc": bool(env.get("PoC_URLs")),
                "is_kev": bool(env.get("KEV_Status")),
            })

        return {
            "total_evaluated": total,
            "in_scope_count": len(in_scope),
            "in_scope_percentage": round((len(in_scope) / total * 100), 1) if total else 0.0,
            "out_of_scope_count": len(out_scope),
            "web_count": len(web),
            "mobile_count": len(mobile),
            "anomalies_count": len(anomalies),
            "kev_count": len(kev_items),
            "poc_count": len(poc_items),
            "avg_priority_score": avg_score,
            "max_priority_score": max_score,
            "score_distribution": {
                "critical": len(critical_band),
                "high": len(high_band),
                "medium": len(medium_band),
                "low": len(low_band),
            },
            "source_breakdown": sources,
            "scope_breakdown": {
                "WEB": len(web),
                "MOBILE": len(mobile),
                "OUT_OF_SCOPE": len(out_scope),
            },
            "impact_breakdown": impacts,
            "anomalies": anomaly_list,
            "top_ranked": top_ranked,
            "last_loaded": self._last_loaded,
        }

    def generate_newsletter_digest(self, issue_title: Optional[str] = None, top_n: int = 5) -> Dict[str, Any]:
        """
        Generates a curated Weekly Threat Intelligence Newsletter Digest
        with executive analysis, top threats, and exportable Markdown/HTML.
        """
        all_items = self.get_all_candidates()
        in_scope = [x for x in all_items if x.get("pre_filter", {}).get("is_in_scope", False)]
        # Only cards that passed the source-verification gate are published
        verified = merge_same_flaw([x for x in in_scope if x.get("grounded_card")])
        top_items = verified[:top_n]

        now = datetime.now(timezone.utc)
        date_str = now.strftime("%B %d, %Y")
        title = issue_title or f"GroundedCVE Weekly Threat Digest — {now.strftime('Week %U, %Y')}"

        web_top = [x for x in verified if x.get("pre_filter", {}).get("category") == "WEB"][:3]
        mobile_top = [x for x in verified if x.get("pre_filter", {}).get("category") == "MOBILE"][:2]

        # Markdown synthesis
        md_lines = [
            f"# {title}",
            f"**Published**: {date_str}  ",
            f"**Platform**: GroundedCVE Automated Threat Curation | SIT Team 4  ",
            "**Primary Channel**: Web Executive Dashboard",
            "",
            "---",
            "",
            "## 1. Executive Summary & Weekly Threat Landscape",
            f"During this monitoring cycle, GroundedCVE evaluated **{len(all_items)}** total security advisories across NVD, CISA KEV, PortSwigger, Google Project Zero, and GitHub ecosystems. "
            f"The Pentest Scope Pre-Filter isolated **{len(in_scope)}** actionable Web & Mobile vulnerabilities, "
            f"of which **{len(verified)}** have a write-up that passed source verification, flagging **{len([x for x in in_scope if x.get('envelope', {}).get('KEV_Status')])}** active in-the-wild exploitations cataloged by CISA.",
            "",
            "### Key Weekly Insights",
            f"- **Top Priority Score Recorded**: `{top_items[0].get('priority_score')}/100.0` ({top_items[0].get('envelope', {}).get('CVE_ID', 'N/A')})" if top_items else "- No critical threats scored.",
            f"- **Active Weaponization Rate**: {len([x for x in in_scope if x.get('envelope', {}).get('KEV_Status')])} confirmed zero-day / active exploit items.",
            f"- **Public PoCs Tracked**: {len([x for x in in_scope if x.get('envelope', {}).get('PoC_URLs')])} disclosures accompanied by verified exploit code.",
            "",
            "---",
            "",
            "## 2. Top Priority Security Advisories",
        ]

        curated_threats = []
        for idx, item in enumerate(top_items, 1):
            env = item.get("envelope", {})
            pf = item.get("pre_filter", {})
            ai = item.get("ai_assessment", {}) or {}
            bd = item.get("score_breakdown", {})
            disc = item.get("discrepancy", {}) or {}

            cve_id = env.get("CVE_ID") or env.get("Item_ID")
            score = item.get("priority_score", 0.0)
            impact = ai.get("offensive_impact", "Vulnerability Disclosure")
            severity = ai.get("severity_score", 0.0)
            cvss = env.get("CVSS")
            poc_urls = env.get("PoC_URLs") or []
            source_url = env.get("Source_URL", "")
            card = item["grounded_card"]

            curated_threats.append({
                "rank": idx,
                "cve_id": cve_id,
                "title": env.get("Title"),
                "category": pf.get("category"),
                "priority_score": score,
                "ai_severity": severity,
                "cvss": cvss,
                "offensive_impact": impact,
                "reasoning": ai.get("reasoning", pf.get("reason", "")),
                "is_kev": bool(env.get("KEV_Status")),
                "poc_urls": poc_urls,
                "source_url": source_url,
                "breakdown": bd,
                "is_discrepancy": disc.get("is_discrepancy", False),
                "troubleshoot_note": disc.get("troubleshoot_note"),
                "grounded_card": card,
            })

            md_lines.extend([
                f"### #{idx}. [{cve_id}] {env.get('Title')}",
                f"- **Priority Score**: `{score}/100.0` (KEV: {bd.get('cisa_kev_points', 0)} pts | AI Severity: {bd.get('ai_severity_points', 0)} pts | PoC: {bd.get('poc_points', 0)} pts)",
                f"- **Domain**: `[{pf.get('category')}]` | **Impact**: **{impact}** | **AI Severity**: `{severity}/10.0` (CVSS: `{cvss if cvss is not None else 'N/A'}`)",
                f"- **Weaponization**: {'🔥 Active CISA KEV Exploitation' if env.get('KEV_Status') else '⚠️ Monitored Advisory'} | Public PoC: {'✅ Yes' if poc_urls else '❌ None detected'}",
                f"- **What it is**: {card.get('mechanism')}",
                f"- **Impact**: {card.get('impact')}",
            ])
            if card.get("remediation"):
                md_lines.append(f"- **Fix**: {card['remediation']}")
            if card.get("testing_syntax"):
                md_lines.append("- **Testing**: " + "; ".join(f"`{cmd}`" for cmd in card["testing_syntax"]))
            if disc.get("is_discrepancy"):
                md_lines.append(f"- **[!] CVSS Anomaly Alert**: {disc.get('troubleshoot_note')}")
            if poc_urls:
                md_lines.append(f"- **PoC Exploit Links**: {', '.join(poc_urls[:2])}")
            md_lines.append(f"- **Canonical Source**: [{env.get('Source_Type')}]({source_url})")
            md_lines.append("")

        md_lines.extend([
            "---",
            "",
            "## 3. Web Application Security Focus",
        ])
        for w in web_top:
            w_env = w.get("envelope", {})
            w_ai = w.get("ai_assessment", {}) or {}
            md_lines.append(
                f"- **{w_env.get('CVE_ID') or w_env.get('Item_ID')}** ({w.get('priority_score')} pts): "
                f"{w_env.get('Title')} — *Impact*: {w_ai.get('offensive_impact', 'Web Exploit')}"
            )

        md_lines.extend([
            "",
            "## 4. Mobile Application Security Focus",
        ])
        for m in mobile_top:
            m_env = m.get("envelope", {})
            m_ai = m.get("ai_assessment", {}) or {}
            md_lines.append(
                f"- **{m_env.get('CVE_ID') or m_env.get('Item_ID')}** ({m.get('priority_score')} pts): "
                f"{m_env.get('Title')} — *Impact*: {m_ai.get('offensive_impact', 'Mobile Exploit')}"
            )

        md_lines.extend([
            "",
            "---",
            f"*Generated automatically by GroundedCVE Threat Intelligence Platform. Lead DevOps: Tan De Ye (SIT Team 4)*"
        ])

        markdown_content = "\n".join(md_lines)

        return {
            "title": title,
            "generated_at": date_str,
            "total_evaluated": len(all_items),
            "in_scope_count": len(in_scope),
            "verified_count": len(verified),
            "curated_count": len(curated_threats),
            "curated_threats": curated_threats,
            "web_highlights": [
                {
                    "cve_id": w.get("envelope", {}).get("CVE_ID"),
                    "title": w.get("envelope", {}).get("Title"),
                    "score": w.get("priority_score"),
                    "impact": (w.get("ai_assessment") or {}).get("offensive_impact"),
                } for w in web_top
            ],
            "mobile_highlights": [
                {
                    "cve_id": m.get("envelope", {}).get("CVE_ID"),
                    "title": m.get("envelope", {}).get("Title"),
                    "score": m.get("priority_score"),
                    "impact": (m.get("ai_assessment") or {}).get("offensive_impact"),
                } for m in mobile_top
            ],
            "markdown": markdown_content,
        }


# Global singleton instance
data_service = DataService()
