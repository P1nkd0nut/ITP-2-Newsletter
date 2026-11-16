"""
Deterministic Source-Verification Gate (Task 3.2).

A plain Python checker with no LLM calls. Every CVE ID, version, CVSS score,
CWE, vendor/product name, command, impact claim and URL in an AI-written draft
card must be traceable to the item's source text, or the card is quarantined.
"""
import re
from typing import Callable, List, Optional, Tuple

from Backend.ingestion.models import StagingEnvelope
from Backend.verification.models import CheckFailure, DraftCard, VerificationResult

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
CVSS_RE = re.compile(r"\bCVSS[^0-9]{0,20}(\d{1,2}\.\d)\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\b\d+(?:\.\d+)+(?:-[0-9][\w.]*)?\b")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
FLAG_RE = re.compile(r"(?<!\S)--?[A-Za-z][\w-]*")

# If the draft claims an impact, the source must contain at least one of its phrases.
IMPACT_TERMS = {
    "remote code execution": ["remote code execution", "rce", "arbitrary code", "code execution", "command execution", "command injection"],
    "privilege escalation": ["privilege escalation", "escalate privileges", "elevation of privilege", "root privileges", "kernel privileges"],
    "authentication bypass": ["authentication bypass", "auth bypass", "bypass authentication", "bypassing multi-factor", "bypassing authentication"],
    "account takeover": ["account takeover", "take over accounts", "hijack accounts"],
    "sql injection": ["sql injection", "sqli"],
    "denial of service": ["denial of service", "dos"],
}

# Vendor/product check: any of these names the draft mentions must appear in the
# source text or in the envelope's Vendor_Product field. The list is the vendors
# and products that show up across our Web and Mobile sources; a name outside
# it is not checked (the gate can't tell a product name from an ordinary word),
# which is also why names that double as ordinary words ("Edge", "Spring") are
# listed only in their full form.
KNOWN_VENDOR_PRODUCTS = [
    # Mobile platforms and chipsets
    "Apple", "iOS", "iPadOS", "macOS", "watchOS", "tvOS", "visionOS", "Safari", "WebKit",
    "Google", "Android", "AOSP", "Google Pixel", "Chrome", "Chromium", "Samsung", "Qualcomm", "MediaTek",
    "Huawei", "Xiaomi", "Frida",
    # Browsers, OS and big vendors
    "Microsoft", "Windows", "Microsoft Edge", "Mozilla", "Firefox", "Oracle", "Adobe", "Cisco", "Fortinet",
    "FortiOS", "Palo Alto", "PAN-OS", "Ivanti", "Citrix", "VMware", "Atlassian", "Confluence", "Jira",
    "SAP", "IBM", "Juniper", "SonicWall", "F5", "Zyxel", "Linux",
    # Web frameworks, servers and package ecosystems
    "Apache", "Tomcat", "Struts", "Log4j", "nginx", "WordPress", "Drupal", "Joomla", "Jenkins",
    "GitLab", "GitHub", "Spring Framework", "Spring Boot", "Django", "Flask", "Laravel", "Ruby on Rails",
    "Express.js", "Next.js", "Node.js", "Angular", "Vue.js", "PHP", "OpenSSL", "Kubernetes", "Docker",
]


def _name_pattern(name: str) -> "re.Pattern[str]":
    # Letters/digits either side end the match, so "php" is found in "...-php-object-injection"
    # (a URL slug in the source) but "apple" is not found in "pineapple".
    return re.compile(rf"(?<![a-z0-9]){re.escape(name.lower())}(?![a-z0-9])")


KNOWN_NAME_PATTERNS = [(name, _name_pattern(name)) for name in KNOWN_VENDOR_PRODUCTS]


def _norm(text: str) -> str:
    """Lowercase and collapse whitespace so formatting differences don't cause false failures."""
    return re.sub(r"\s+", " ", text).strip().lower()


def _has_number(source: str, number: str) -> bool:
    """True if `number` appears as a whole number in source ("7.0" must not match inside "17.0.8")."""
    return re.search(rf"(?<![\d.]){re.escape(number.lower())}(?![\d.]*\d)", source) is not None


class VerificationGate:
    """Audits a DraftCard against its StagingEnvelope's source text."""

    def verify(
        self,
        card: DraftCard,
        envelope: StagingEnvelope,
        evidence: Optional[List[str]] = None,
    ) -> VerificationResult:
        """
        evidence = extra source text retrieved for this item (e.g. PoC write-ups,
        later the Tier 2 chunks from Qdrant). Raw_Content is always included.
        """
        source = _norm(" ".join([envelope.Raw_Content, *(evidence or [])]))
        prose = " ".join([card.mechanism, card.impact, card.remediation])
        all_text = " ".join([prose, *card.testing_syntax, *card.references])

        failures: List[CheckFailure] = []
        checks_run = 0

        for check in (
            self._check_cve_ids,
            self._check_cvss,
            self._check_cwes,
            self._check_versions,
            self._check_vendor_products,
            self._check_commands,
            self._check_impact_terms,
            self._check_urls,
        ):
            n, found = check(card, envelope, source, prose, all_text)
            checks_run += n
            failures.extend(found)

        passed = not failures
        return VerificationResult(
            passed=passed,
            status="PASSED" if passed else "QUARANTINED",
            checks_run=checks_run,
            failures=failures,
        )

    def verify_with_retry(
        self,
        generate: Callable[[Optional[List[CheckFailure]]], DraftCard],
        envelope: StagingEnvelope,
        evidence: Optional[List[str]] = None,
    ) -> Tuple[DraftCard, VerificationResult]:
        """
        Plan rule: on failure, regenerate once with the failure reasons.
        If it still fails, the card is quarantined (not published).
        generate(None) makes the first draft; generate(failures) makes the retry.
        """
        card = generate(None)
        result = self.verify(card, envelope, evidence)
        if result.passed:
            return card, result

        card = generate(result.failures)
        result = self.verify(card, envelope, evidence)
        result.attempts = 2
        return card, result

    # ------------------------------------------------------------------ checks
    # Each returns (number_of_facts_checked, list_of_failures).

    def _check_cve_ids(self, card, env, source, prose, all_text):
        own = (env.CVE_ID or "").upper()
        found = {m.upper() for m in CVE_RE.findall(all_text)}
        failures = [
            CheckFailure(check="CVE_ID", value=cve, reason="Not the item's own CVE and not in the source")
            for cve in found
            if cve != own and cve.lower() not in source
        ]
        return len(found), failures

    def _check_cvss(self, card, env, source, prose, all_text):
        found = CVSS_RE.findall(all_text)
        failures = []
        for score in found:
            if env.CVSS is not None and float(score) == float(env.CVSS):
                continue
            if _has_number(source, score):
                continue
            failures.append(CheckFailure(check="CVSS", value=score, reason=f"Does not match the envelope CVSS ({env.CVSS}) or the source"))
        return len(found), failures

    def _check_cwes(self, card, env, source, prose, all_text):
        env_cwes = env.CWE or []
        if isinstance(env_cwes, str):
            env_cwes = [env_cwes]
        env_cwes = {c.upper() for c in env_cwes}
        found = {m.upper() for m in CWE_RE.findall(all_text)}
        failures = [
            CheckFailure(check="CWE", value=cwe, reason="Not on the envelope and not in the source")
            for cwe in found
            if cwe not in env_cwes and cwe.lower() not in source
        ]
        return len(found), failures

    def _check_versions(self, card, env, source, prose, all_text):
        # Only prose is checked: commands contain IPs/ports that look like versions.
        text = CVSS_RE.sub(" ", CVE_RE.sub(" ", prose))
        found = set(VERSION_RE.findall(text))
        failures = [
            CheckFailure(check="VERSION", value=v, reason="Version number does not appear in the source")
            for v in found
            if not _has_number(source, v)
        ]
        return len(found), failures

    def _check_vendor_products(self, card, env, source, prose, all_text):
        text = _norm(prose)
        allowed = source + " " + _norm(env.Vendor_Product or "") + " " + _norm(env.Title or "")
        checked, failures = 0, []
        for name, pattern in KNOWN_NAME_PATTERNS:
            if not pattern.search(text):
                continue
            checked += 1
            if not pattern.search(allowed):
                failures.append(CheckFailure(
                    check="VENDOR_PRODUCT", value=name,
                    reason="Vendor/product named in the draft but not in the source or the envelope's Vendor_Product",
                ))
        return checked, failures

    def _check_commands(self, card, env, source, prose, all_text):
        failures = []
        for cmd in card.testing_syntax:
            if _norm(cmd) in source:
                continue
            bad_flags = [f for f in FLAG_RE.findall(cmd) if f.lower() not in source]
            detail = f" Flags not in source: {', '.join(bad_flags)}" if bad_flags else ""
            failures.append(CheckFailure(check="COMMAND", value=cmd, reason="Not copied verbatim from the source." + detail))
        return len(card.testing_syntax), failures

    def _check_impact_terms(self, card, env, source, prose, all_text):
        text = _norm(prose)
        checked, failures = 0, []
        for impact, phrases in IMPACT_TERMS.items():
            if not any(re.search(rf"\b{re.escape(p)}\b", text) for p in phrases):
                continue
            checked += 1
            if not any(re.search(rf"\b{re.escape(p)}\b", source) for p in phrases):
                failures.append(CheckFailure(check="IMPACT", value=impact, reason="Draft claims this impact but the source never states it"))
        return checked, failures

    def _check_urls(self, card, env, source, prose, all_text):
        allowed = {_norm(env.Source_URL), *(_norm(u) for u in (env.PoC_URLs or []))}
        found = {u.rstrip(".,;:") for u in URL_RE.findall(all_text)}
        failures = [
            CheckFailure(check="URL", value=u, reason="Not the item's source URL and not in the source text")
            for u in found
            if _norm(u) not in allowed and _norm(u) not in source
        ]
        return len(found), failures
