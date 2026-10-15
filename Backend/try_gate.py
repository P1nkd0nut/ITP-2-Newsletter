"""
Verification Gate playground.

Edit the CARD below (pretend you are the AI), then run:
    python Backend/try_gate.py

The gate compares every fact in your card against the Citrix Bleed source text
(printed at the top when you run it) and tells you PASSED or QUARANTINED.
"""
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.run_benchmark import load_ground_truth_dataset, convert_gt_to_envelope
from Backend.verification.gate import VerificationGate
from Backend.verification.models import DraftCard

# ---------------------------------------------------------------- the source
item = load_ground_truth_dataset()[0]      # item 0 = Citrix Bleed (CVE-2023-4966)
envelope = convert_gt_to_envelope(item)
evidence = item["poc_commands"]            # the known exploit command also counts as source

# ---------------------------------------------------------------- EDIT ME
CARD = DraftCard(
    mechanism="CVE-2023-4966 (CVSS 9.4, CWE-119): Buffer over-read in NetScaler ADC and "
              "NetScaler Gateway OpenID configuration endpoints.",
    impact="Unauthenticated remote attackers can extract session tokens, bypassing "
           "multi-factor authentication. Affects 13.1 before 13.1-49.15.",
    testing_syntax=[item["poc_commands"][0]],
    remediation="Upgrade to a fixed build.",
    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
)
# ---------------------------------------------------------------- EDIT ME END

print("=" * 70)
print("SOURCE TEXT (the answer key):")
print(envelope.Raw_Content)
print(f"\nEnvelope facts: CVE={envelope.CVE_ID}  CVSS={envelope.CVSS}  CWE={envelope.CWE}")
print(f"Source URL: {envelope.Source_URL}")
print("=" * 70)

result = VerificationGate().verify(CARD, envelope, evidence)

print(f"\nRESULT: {result.status}   ({result.checks_run} facts checked, {len(result.failures)} failed)")
for f in result.failures:
    print(f"  [{f.check}] {f.value[:70]}")
    print(f"      -> {f.reason}")
