"""
Dedicated Pentest Scope Pre-Filter Gate (Task 1.2).
Evaluates incoming threat disclosures BEFORE scoring to determine whether
an item belongs to Web Application Security, Mobile Security, or is Out of Scope.
"""
import re
from typing import Set, Tuple
from Backend.ingestion.models import StagingEnvelope, SourceType
from Backend.triage.models import ScopeCategory, PreFilterDecision

# Task 1.2 Reference Vulnerability Taxonomy Mappings
WEB_CWES: Set[str] = {
    "CWE-74",   # Injection
    "CWE-89",   # SQL Injection
    "CWE-78",   # OS Command Injection
    "CWE-79",   # Cross-site Scripting (XSS)
    "CWE-918",  # Server-Side Request Forgery (SSRF)
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-22",   # Path Traversal
    "CWE-287",  # Improper Authentication
    "CWE-862",  # Missing Authorization
    "CWE-639",  # IDOR / Broken Object Level Authorization
    "CWE-444",  # HTTP Request Smuggling / Desync
    "CWE-113",  # HTTP Header Injection / CRLF
    "CWE-352",  # Cross-Site Request Forgery (CSRF)
}

MOBILE_CWES: Set[str] = {
    "CWE-926",  # Improper Export of Android Application Components (IPC)
    "CWE-927",  # Use of Implicit Intent for Sensitive Communication
    "CWE-311",  # Missing Encryption of Sensitive Data
    "CWE-312",  # Cleartext Storage of Sensitive Information
    "CWE-295",  # Improper Certificate Validation (Pinning Bypass)
    "CWE-939",  # Insecure Custom URL Scheme / Deep Links
    "CWE-749",  # Exposed Dangerous Method in WebView
}

# Technical Heuristic Keyword Sets
WEB_KEYWORDS = [
    "http", "https", "cookie", "cookies", "jwt", "oauth", "openid", "sql injection", "sqli", "xss",
    "cross-site", "ssrf", "graphql", "cors", "web application", "deserialization",
    "csrf", "rest api", "endpoint", "endpoints", "url parameter", "request smuggling",
    "web cache", "authentication bypass", "session token", "session tokens",
    "gateway", "ssl-vpn", "web service", "web portal"
]

MOBILE_KEYWORDS = [
    "android", "ios", "ipados", "apk", "ipa", "ipc", "intent", "intents", "webview",
    "frida", "aosp", "keychain", "keystore", "smali", "dalvik", "jailbreak",
    "root detection", "deep link", "safari", "webkit", "mobile", "bluetooth"
]

OUT_OF_SCOPE_INDICATORS = [
    "printer", "print spooler", "scada", "modbus", "plc", "programmable logic controller",
    "bios", "uefi", "automotive", "ecu", "can bus", "firmware update", "industrial control",
    "iot", "router firmware", "smart home", "industrial router"
]


class PentestPreFilter:
    """Pre-filter gate that strictly isolates Web and Mobile attack surfaces."""

    def evaluate(self, envelope: StagingEnvelope) -> PreFilterDecision:
        """
        Determines if an ingested envelope is WEB, MOBILE, or OUT_OF_SCOPE
        before priority scoring occurs.
        """
        # 1. Evaluate by Source Origin (Unambiguous sources)
        origin_decision = self._check_source_origin(envelope.Source_Type)
        if origin_decision:
            return origin_decision

        # 2. Evaluate by Task 1.2 CWE Taxonomy Mapping (for NVD / CISA KEV)
        cwe_decision = self._check_cwe_taxonomy(envelope)
        if cwe_decision:
            return cwe_decision

        # 3. Check for Out-of-Scope Negative Indicators
        content_lower = (
            f"{envelope.Title} {envelope.Vendor_Product or ''} {envelope.Raw_Content}"
        ).lower()

        for neg in OUT_OF_SCOPE_INDICATORS:
            if re.search(rf"\b{re.escape(neg)}\b", content_lower):
                return PreFilterDecision(
                    category=ScopeCategory.OUT_OF_SCOPE,
                    matched_by="NEGATIVE_HEURISTIC",
                    reason=f"Matched out-of-scope non-web/mobile indicator: '{neg}'",
                    is_in_scope=False,
                )

        # 4. Evaluate by Contextual Technical Keywords
        keyword_decision = self._check_keywords(content_lower)
        if keyword_decision:
            return keyword_decision

        # 5. Default Fallback for Unclassified General Registry Records
        return PreFilterDecision(
            category=ScopeCategory.OUT_OF_SCOPE,
            matched_by="DEFAULT_FILTER",
            reason="Lacks definitive Web or Mobile pentesting indicators in raw metadata.",
            is_in_scope=False,
        )

    def _check_source_origin(self, source_type: SourceType) -> PreFilterDecision | None:
        if source_type in (SourceType.PORTSWIGGER, SourceType.GITHUB_ADVISORY):
            return PreFilterDecision(
                category=ScopeCategory.WEB,
                matched_by="SOURCE_ORIGIN",
                reason=f"Source '{source_type.value}' is inherently dedicated to Web & package ecosystems.",
                is_in_scope=True,
            )
        if source_type in (SourceType.FRIDA, SourceType.ANDROID_BULLETIN, SourceType.APPLE_SECURITY):
            return PreFilterDecision(
                category=ScopeCategory.MOBILE,
                matched_by="SOURCE_ORIGIN",
                reason=f"Source '{source_type.value}' is inherently dedicated to Mobile platforms & tooling.",
                is_in_scope=True,
            )
        return None

    def _check_cwe_taxonomy(self, envelope: StagingEnvelope) -> PreFilterDecision | None:
        raw_cwes = envelope.CWE or []
        if isinstance(raw_cwes, str):
            raw_cwes = [raw_cwes]

        cwe_set = set(raw_cwes)
        matched_web = cwe_set.intersection(WEB_CWES)
        matched_mobile = cwe_set.intersection(MOBILE_CWES)

        if matched_web and not matched_mobile:
            return PreFilterDecision(
                category=ScopeCategory.WEB,
                matched_by="CWE_TAXONOMY",
                reason=f"Matches Task 1.2 Web Vulnerability Taxonomy: {', '.join(matched_web)}",
                is_in_scope=True,
            )
        if matched_mobile and not matched_web:
            return PreFilterDecision(
                category=ScopeCategory.MOBILE,
                matched_by="CWE_TAXONOMY",
                reason=f"Matches Task 1.2 Mobile Vulnerability Taxonomy: {', '.join(matched_mobile)}",
                is_in_scope=True,
            )
        if matched_web and matched_mobile:
            return PreFilterDecision(
                category=ScopeCategory.WEB,
                matched_by="CWE_TAXONOMY",
                reason=f"Dual match (Web & Mobile CWEs): {', '.join(matched_web | matched_mobile)}",
                is_in_scope=True,
            )
        return None

    def _check_keywords(self, content_lower: str) -> PreFilterDecision | None:
        web_hits = sum(1 for kw in WEB_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", content_lower))
        mobile_hits = sum(1 for kw in MOBILE_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", content_lower))

        if web_hits > 0 and web_hits >= mobile_hits:
            return PreFilterDecision(
                category=ScopeCategory.WEB,
                matched_by="KEYWORDS",
                reason=f"Matched {web_hits} Web offensive indicators in advisory content.",
                is_in_scope=True,
            )
        if mobile_hits > 0 and mobile_hits > web_hits:
            return PreFilterDecision(
                category=ScopeCategory.MOBILE,
                matched_by="KEYWORDS",
                reason=f"Matched {mobile_hits} Mobile offensive indicators in advisory content.",
                is_in_scope=True,
            )
        return None
