"""
Unit tests for the Deterministic Source-Verification Gate (Task 3.2).

Every test uses the Citrix Bleed source text below and one "AI-written" card.
An honest card must PASS; a card with one planted fake must be QUARANTINED
with the right check name.

Run:
    python -m unittest Testing.test_verification -v
"""
import sys
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.ingestion.models import SourceType, StagingEnvelope
from Backend.verification.gate import VerificationGate
from Backend.verification.models import DraftCard

RAW = (
    "CVE-2023-4966: Sensitive information disclosure in NetScaler ADC and NetScaler Gateway "
    "when configured as a Gateway or AAA virtual server across versions 13.0 before 13.0-92.21, "
    "13.1 before 13.1-49.15, and 14.1 before 14.1-8.50. Unauthenticated remote attackers can "
    "extract session tokens from uninitialized memory buffers via buffer over-read in OpenID "
    "configuration endpoints, completely bypassing multi-factor authentication (MFA). "
    "Actively exploited in the wild."
)
POC = 'curl -k -s -H "Host: aaaa" https://target-gateway.com/oauth/idp/.well-known/openid-configuration'


def make_envelope(raw: str = RAW, cvss: float = 9.4) -> StagingEnvelope:
    return StagingEnvelope(
        Item_ID="test-citrix",
        Source_Type=SourceType.NVD,
        Title="Citrix Bleed",
        Source_URL="https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
        Published_Date="2023-10-10T00:00:00Z",
        Ingested_At="2026-10-15T00:00:00Z",
        Content_Hash="abc",
        Raw_Content=raw,
        CVE_ID="CVE-2023-4966",
        CVSS=cvss,
        CWE=["CWE-119", "CWE-200"],
    )


def make_card(**changes) -> DraftCard:
    """An honest card. Pass keyword arguments to replace a field with a faulty one."""
    fields = dict(
        mechanism="CVE-2023-4966 (CVSS 9.4, CWE-119): Buffer over-read in NetScaler ADC and "
                  "NetScaler Gateway OpenID configuration endpoints.",
        impact="Unauthenticated remote attackers can extract session tokens, bypassing "
               "multi-factor authentication. Affects 13.1 before 13.1-49.15.",
        testing_syntax=[POC],
        remediation="Upgrade to a fixed build.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
    )
    fields.update(changes)
    return DraftCard(**fields)


class TestVerificationGate(unittest.TestCase):

    def setUp(self):
        self.gate = VerificationGate()
        self.env = make_envelope()

    def check(self, card):
        return self.gate.verify(card, self.env, evidence=[POC])

    def assertCaught(self, card, check_name, value):
        result = self.check(card)
        self.assertEqual(result.status, "QUARANTINED")
        self.assertIn((check_name, value), [(f.check, f.value) for f in result.failures])

    # ---- honest cards
    def test_01_honest_card_passes(self):
        result = self.check(make_card())
        self.assertEqual(result.status, "PASSED", result.failures)
        self.assertGreater(result.checks_run, 0)

    def test_02_ordinary_wording_change_still_passes(self):
        result = self.check(make_card(remediation="Please patch quickly."))
        self.assertEqual(result.status, "PASSED", result.failures)

    def test_03_spacing_and_case_differences_still_pass(self):
        messy = POC.upper().replace(" ", "   ")
        result = self.check(make_card(testing_syntax=[messy]))
        self.assertEqual(result.status, "PASSED", result.failures)

    # ---- one planted fake per test
    def test_04_fake_cve_id(self):
        card = make_card(mechanism="CVE-2023-4967 (CVSS 9.4, CWE-119): Buffer over-read.")
        self.assertCaught(card, "CVE_ID", "CVE-2023-4967")

    def test_05_altered_version(self):
        card = make_card(impact="Affects 13.1 before 13.1-49.19.")
        self.assertCaught(card, "VERSION", "13.1-49.19")

    def test_06_wrong_cvss(self):
        card = make_card(mechanism="CVE-2023-4966 (CVSS 7.5, CWE-119): Buffer over-read.")
        self.assertCaught(card, "CVSS", "7.5")

    def test_07_wrong_cwe(self):
        card = make_card(mechanism="CVE-2023-4966 (CVSS 9.4, CWE-79): Buffer over-read.")
        self.assertCaught(card, "CWE", "CWE-79")

    def test_08_invented_flag(self):
        cmd = POC + " --steal-tokens"
        result = self.check(make_card(testing_syntax=[cmd]))
        self.assertEqual(result.status, "QUARANTINED")
        self.assertEqual(result.failures[0].check, "COMMAND")
        self.assertIn("--steal-tokens", result.failures[0].reason)

    def test_09_invented_command(self):
        card = make_card(testing_syntax=["nmap -sV target.com"])
        self.assertCaught(card, "COMMAND", "nmap -sV target.com")

    def test_10_made_up_impact(self):
        card = make_card(impact="Attackers gain remote code execution on the gateway.")
        self.assertCaught(card, "IMPACT", "remote code execution")

    def test_11_fake_url(self):
        card = make_card(references=["https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
                                     "https://fake-site.com/exploit"])
        self.assertCaught(card, "URL", "https://fake-site.com/exploit")

    def test_11b_wrong_vendor(self):
        card = make_card(impact="Unauthenticated remote attackers can extract session tokens from Fortinet devices.")
        self.assertCaught(card, "VENDOR_PRODUCT", "Fortinet")

    def test_11c_vendor_from_envelope_is_allowed(self):
        # "Citrix" is only in the envelope title, not the raw text: still grounded
        card = make_card(mechanism="CVE-2023-4966 (CVSS 9.4, CWE-119): Buffer over-read in Citrix NetScaler ADC.")
        self.assertEqual(self.check(card).status, "PASSED")

    def test_11d_unknown_word_is_not_treated_as_vendor(self):
        card = make_card(remediation="Rotate every session token after patching the appliance.")
        self.assertEqual(self.check(card).status, "PASSED")

    def test_12_several_fakes_all_reported(self):
        card = make_card(
            impact="Affects 13.1-49.19. This leads to remote code execution.",
            references=["https://fake-site.com/exploit"],
        )
        checks = {f.check for f in self.check(card).failures}
        self.assertEqual(checks, {"VERSION", "IMPACT", "URL"})

    # ---- tricky edge cases
    def test_13_number_inside_bigger_number_is_not_a_match(self):
        # "7.0" must NOT count as found just because "17.0.8" is in the source
        env = make_envelope(raw="Affects versions before 17.0.8.", cvss=9.8)
        card = make_card(mechanism="CVSS 7.0 issue.", impact="", testing_syntax=[], references=[])
        result = self.gate.verify(card, env)
        self.assertIn(("CVSS", "7.0"), [(f.check, f.value) for f in result.failures])

    def test_13b_cve_id_inside_longer_cve_id_is_not_a_match(self):
        # "CVE-2024-3400" must NOT count as found just because "CVE-2024-34001" is in the source
        env = make_envelope(raw=RAW + " See also CVE-2024-34001.")
        card = make_card(mechanism="CVE-2024-3400 (CVSS 9.4, CWE-119): Buffer over-read.")
        result = self.gate.verify(card, env, evidence=[POC])
        self.assertIn(("CVE_ID", "CVE-2024-3400"), [(f.check, f.value) for f in result.failures])

    def test_13c_cwe_inside_longer_cwe_is_not_a_match(self):
        # "CWE-7" must NOT count as found just because "CWE-79" is in the source
        env = make_envelope(raw=RAW + " Related weakness: CWE-79.")
        card = make_card(mechanism="CVE-2023-4966 (CVSS 9.4, CWE-7): Buffer over-read.")
        result = self.gate.verify(card, env, evidence=[POC])
        self.assertIn(("CWE", "CWE-7"), [(f.check, f.value) for f in result.failures])

    def test_13d_cve_and_cwe_in_source_still_pass(self):
        env = make_envelope(raw=RAW + " See also CVE-2024-34001 (CWE-79).")
        card = make_card(mechanism="CVE-2024-34001 (CVSS 9.4, CWE-79): Buffer over-read.")
        result = self.gate.verify(card, env, evidence=[POC])
        self.assertEqual(result.status, "PASSED", result.failures)

    def test_14_synonym_impact_is_accepted(self):
        # Source says "RCE", card says "remote code execution" -> same claim, should pass
        env = make_envelope(raw=RAW + " This is an unauthenticated RCE.")
        card = make_card(impact="Leads to remote code execution.")
        result = self.gate.verify(card, env, evidence=[POC])
        self.assertEqual(result.status, "PASSED", result.failures)

    def test_15_own_source_url_always_allowed(self):
        # The envelope's own Source_URL is never in Raw_Content, but must still pass
        self.assertNotIn("nvd.nist.gov", RAW)
        self.assertEqual(self.check(make_card()).status, "PASSED")

    # ---- retry-then-quarantine rule
    def test_16_retry_fixes_mistake(self):
        bad = make_card(impact="Affects 13.1-49.19.")
        good = make_card()
        card, result = self.gate.verify_with_retry(lambda fb: bad if fb is None else good, self.env, [POC])
        self.assertEqual((result.status, result.attempts), ("PASSED", 2))

    def test_17_retry_repeats_mistake_is_quarantined(self):
        bad = make_card(impact="Affects 13.1-49.19.")
        card, result = self.gate.verify_with_retry(lambda fb: bad, self.env, [POC])
        self.assertEqual((result.status, result.attempts), ("QUARANTINED", 2))

    def test_18_retry_receives_failure_reasons(self):
        seen = []
        bad = make_card(impact="Affects 13.1-49.19.")

        def generate(feedback):
            seen.append(feedback)
            return bad

        self.gate.verify_with_retry(generate, self.env, [POC])
        self.assertIsNone(seen[0])
        self.assertEqual(seen[1][0].value, "13.1-49.19")


if __name__ == "__main__":
    unittest.main(verbosity=2)
