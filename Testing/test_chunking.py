"""
Tests for GroundedCVE Task 2.2: cleaning + two-tier heading-aware chunking.

Envelopes are plain dicts with the StagingEnvelope keys (the chunker accepts
either), so these tests need no pydantic or network access.

Run:  python -m unittest Testing.test_chunking -v
  or: python -m unittest discover -s Testing -p "test_chunking.py" -v
"""
import copy
import hashlib
import json
import re
import unittest
from pathlib import Path

from bs4 import BeautifulSoup

from Backend.chunking import chunk_envelope, clean_content, detect_format, evidence_texts
from Backend.config import CHUNK_TIER1_MAX_CHARS, CHUNK_TIER2_MAX_CHARS, STAGING_DIR


def make_env(raw, source_type="GITHUB_ADVISORY", item_id="item-1", **extra):
    env = {
        "Item_ID": item_id,
        "Source_Type": source_type,
        "Title": "Test item",
        "Source_URL": "https://example.com/advisory",
        "Published_Date": "2026-09-01T00:00:00Z",
        "Ingested_At": "2026-09-28T12:00:00Z",
        "Content_Hash": hashlib.sha256(raw.encode()).hexdigest(),
        "Raw_Content": raw,
        "CVE_ID": "CVE-2026-0001",
    }
    env.update(extra)
    return env


def norm(s):
    return re.sub(r"\s+", " ", s).strip().lower()


def tier(chunks, n):
    return [c for c in chunks if c.Tier == n]


MARKDOWN_DOC = """---
title: advisory
---
## Overview

A path traversal flaw in the docs tool allows arbitrary file read outside the sandbox.

## Impact

Attackers can read and delete files. ![badge](https://img.shields.io/x.svg)

## Proof of Concept

Send the following request:

```bash
curl -X POST "http://target/api?path=../../etc/passwd" -H "X-Test: a && b" --data '<script>alert(1)</script>'
```

## Remediation

Upgrade to version 1.2.3.
"""


class TestCleaning(unittest.TestCase):
    def test_format_detection(self):
        self.assertEqual(detect_format("NVD", '{"id": "CVE-1"}'), "json")
        self.assertEqual(detect_format("X", "<!doctype html><html></html>"), "html")
        self.assertEqual(detect_format("X", "<p>a</p><p>b</p><pre>c</pre>"), "html")
        self.assertEqual(detect_format("X", "## Title\n\ntext"), "markdown")
        self.assertEqual(detect_format("X", "just some words"), "text")

    def test_markdown_frontmatter_and_images_removed_code_untouched(self):
        cleaned, fmt = clean_content("GITHUB_ADVISORY", MARKDOWN_DOC)
        self.assertEqual(fmt, "markdown")
        self.assertNotIn("title: advisory", cleaned)
        self.assertNotIn("shields.io", cleaned)
        self.assertIn("""-H "X-Test: a && b" --data '<script>alert(1)</script>'""", cleaned)

    def test_html_boilerplate_stripped_and_entities_decoded(self):
        html = """<html><head><title>t</title><script>track()</script></head><body>
        <nav>Home | About</nav>
        <main><h1>Bypass</h1><p>Attackers abuse <code>run-as</code> to read data.
        See <a href="https://example.com/x">the writeup</a>.</p>
        <h2>Reproduction</h2><pre><code class="language-bash">adb shell run-as app &amp;&amp; cat f &lt; in.txt</code></pre>
        <ul><li>step one</li><li>step two<ul><li>nested</li></ul></li></ul>
        <table><tr><th>CVE</th><th>Severity</th></tr><tr><td>CVE-2026-1</td><td>High</td></tr></table>
        </main><footer>Cookie policy</footer></body></html>"""
        cleaned, fmt = clean_content("PROJECT_ZERO", html)
        self.assertEqual(fmt, "html")
        for junk in ("track()", "Home | About", "Cookie policy"):
            self.assertNotIn(junk, cleaned)
        self.assertIn("# Bypass", cleaned)
        self.assertIn("## Reproduction", cleaned)
        self.assertIn("`run-as`", cleaned)
        self.assertIn("[the writeup](https://example.com/x)", cleaned)
        self.assertIn("```bash\nadb shell run-as app && cat f < in.txt\n```", cleaned)
        self.assertIn("- step one", cleaned)
        self.assertIn("  - nested", cleaned)
        self.assertIn("CVE-2026-1 | High", cleaned)

    def test_html_unclosed_void_tag_does_not_swallow_page(self):
        html = "<html><head><link rel='x' href='y'><body><main><p>real content here</p></main></body></html>"
        cleaned, _ = clean_content("APPLE_SECURITY", html)
        self.assertIn("real content here", cleaned)

    def test_nvd_json_rendered_readably(self):
        raw = json.dumps({
            "id": "CVE-2026-0001", "published": "2026-09-21T04:17:36.393", "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "Buffer overflow in foo."}],
            "affected": [{"affectedData": [{"vendor": "Acme", "product": "Foo",
                                            "versions": [{"version": "1.0", "status": "affected"}]}]}],
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-120"}]}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 9.8,
                                                         "baseSeverity": "CRITICAL",
                                                         "vectorString": "CVSS:3.1/AV:N"}}]},
            "references": [{"url": "https://acme.example/advisory"}],
        })
        cleaned, fmt = clean_content("NVD", raw)
        self.assertEqual(fmt, "json")
        for needle in ("CVE-2026-0001", "Buffer overflow in foo.", "Acme Foo", "1.0 [affected]",
                       "CWE-120", "9.8", "https://acme.example/advisory"):
            self.assertIn(needle, cleaned)

    def test_raw_content_never_mutated(self):
        env = make_env(MARKDOWN_DOC)
        before = copy.deepcopy(env)
        chunk_envelope(env)
        self.assertEqual(env, before)
        self.assertEqual(hashlib.sha256(env["Raw_Content"].encode()).hexdigest(), env["Content_Hash"])


class TestTiering(unittest.TestCase):
    def setUp(self):
        self.chunks = chunk_envelope(make_env(MARKDOWN_DOC))

    def test_prose_is_tier1_and_poc_is_tier2(self):
        t1 = "\n".join(c.Text for c in tier(self.chunks, 1))
        t2 = "\n".join(c.Text for c in tier(self.chunks, 2))
        self.assertIn("path traversal flaw", t1)
        self.assertIn("Upgrade to version 1.2.3.", t1)
        self.assertNotIn("curl -X POST", t1)
        self.assertIn("curl -X POST", t2)
        self.assertTrue(all(c.Has_Code for c in tier(self.chunks, 2)))

    def test_command_is_verbatim_in_tier2(self):
        cmd = """curl -X POST "http://target/api?path=../../etc/passwd" -H "X-Test: a && b" --data '<script>alert(1)</script>'"""
        self.assertIn(cmd, evidence_texts(self.chunks, "item-1")[0])

    def test_lead_in_glued_to_command_and_heading_carried(self):
        t2 = tier(self.chunks, 2)[0]
        self.assertIn("Send the following request:", t2.Text)
        self.assertIn("## Proof of Concept", t2.Text)
        self.assertEqual(t2.Heading_Path, ["Proof of Concept"])

    def test_lead_in_outside_poc_section_still_goes_with_code(self):
        raw = "## Details\n\nThe flaw is in the parser.\n\nRun this to trigger it:\n\n```\nfrida -U -f app\n```\n"
        chunks = chunk_envelope(make_env(raw))
        self.assertTrue(any("Run this to trigger it:" in c.Text and "frida -U -f app" in c.Text
                            for c in tier(chunks, 2)))
        self.assertFalse(any("frida -U" in c.Text for c in tier(chunks, 1)))

    def test_unfenced_dollar_commands_become_tier2(self):
        raw = "## Notes\n\nSome intro text.\n\n$ pm install -i x fake.apk\n$ run-as victim.app\n"
        chunks = chunk_envelope(make_env(raw))
        self.assertTrue(any("pm install -i x fake.apk" in c.Text and "run-as victim.app" in c.Text
                            for c in tier(chunks, 2)))

    def test_nvd_and_kev_are_single_tier1_chunk(self):
        for st, raw in (("NVD", json.dumps({"id": "CVE-1", "descriptions": [{"lang": "en", "value": "x " * 50}]})),
                        ("CISA_KEV", json.dumps({"cveID": "CVE-2", "shortDescription": "y " * 40}))):
            chunks = chunk_envelope(make_env(raw, st))
            self.assertEqual((len(tier(chunks, 1)), len(tier(chunks, 2))), (1, 0))

    def test_thin_source_flagged(self):
        chunks = chunk_envelope(make_env("See https://frida.re/news/ for details.", "FRIDA"))
        self.assertEqual(len(chunks), 1)
        self.assertIn("thin_source", chunks[0].Flags)

    def test_empty_content_yields_no_chunks(self):
        self.assertEqual(chunk_envelope(make_env("   \n  ")), [])


class TestCapsAndNoTruncation(unittest.TestCase):
    def test_long_prose_split_within_cap_and_nothing_lost(self):
        words = [f"word{i}" for i in range(2000)]
        raw = "## Overview\n\n" + " ".join(words) + ".\n"
        chunks = chunk_envelope(make_env(raw))
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(c.Char_Count <= CHUNK_TIER1_MAX_CHARS for c in chunks))
        joined = " ".join(c.Text for c in chunks)
        self.assertTrue(all(w in joined for w in words))
        self.assertTrue(all("oversize_split" in c.Flags for c in chunks))

    def test_oversize_code_block_split_at_lines_each_part_fenced(self):
        lines = [f"payload_line_{i} = 'AAAA{i}'" for i in range(600)]
        raw = "## PoC\n\n```python\n" + "\n".join(lines) + "\n```\n"
        chunks = tier(chunk_envelope(make_env(raw)), 2)
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(c.Char_Count, CHUNK_TIER2_MAX_CHARS)
            self.assertIn("oversize_split", c.Flags)
            self.assertIn("```python", c.Text)
            self.assertTrue(c.Text.rstrip().endswith("```"))
        recovered = [ln for c in chunks for ln in c.Text.split("\n") if ln.startswith("payload_line_")]
        self.assertEqual(recovered, lines)                       # order preserved, nothing dropped
        self.assertNotIn("hard_split", {f for c in chunks for f in c.Flags})

    def test_small_code_block_never_split(self):
        code = "\n".join(f"line {i}" for i in range(30))
        raw = f"## PoC\n\n```\n{code}\n```\n\n## Other\n\n```\nsecond\n```\n"
        chunks = tier(chunk_envelope(make_env(raw)), 2)
        self.assertTrue(any(code in c.Text for c in chunks))

    def test_single_giant_token_hard_split_is_flagged(self):
        raw = "## Overview\n\n" + "A" * 6000 + "\n"
        chunks = chunk_envelope(make_env(raw))
        self.assertTrue(all(c.Char_Count <= CHUNK_TIER1_MAX_CHARS for c in chunks))
        self.assertTrue(any("hard_split" in c.Flags for c in chunks))
        self.assertEqual(sum(c.Text.count("A") for c in chunks), 6000)

    def test_adjacent_small_sections_merged_but_new_major_section_after_min_size(self):
        small = "## A\n\nshort.\n\n## B\n\nalso short.\n"
        self.assertEqual(len(tier(chunk_envelope(make_env(small)), 1)), 1)
        big = "## A\n\n" + ("alpha beta gamma. " * 40) + "\n\n## B\n\nsecond section text.\n"
        chunks = tier(chunk_envelope(make_env(big)), 1)
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[1].Heading_Path, ["B"])


class TestMetadataAndDeterminism(unittest.TestCase):
    def test_every_chunk_carries_traceability_metadata(self):
        env = make_env(MARKDOWN_DOC)
        for c in chunk_envelope(env):
            self.assertEqual(c.Item_ID, "item-1")
            self.assertEqual(c.CVE_ID, "CVE-2026-0001")
            self.assertEqual(c.Source_URL, "https://example.com/advisory")
            self.assertEqual(c.Source_Type, "GITHUB_ADVISORY")
            self.assertEqual(c.Parent_Content_Hash, env["Content_Hash"])
            self.assertRegex(c.Chunk_ID, r"^item-1::t[12]::\d{3}$")

    def test_ids_hashes_and_point_ids_deterministic_and_unique(self):
        a = chunk_envelope(make_env(MARKDOWN_DOC))
        b = chunk_envelope(make_env(MARKDOWN_DOC))
        self.assertEqual([c.to_dict() for c in a], [c.to_dict() for c in b])
        self.assertEqual(len({c.Chunk_ID for c in a}), len(a))
        self.assertEqual(len({c.point_id for c in a}), len(a))

    def test_enum_source_type_accepted(self):
        from enum import Enum

        class ST(str, Enum):
            NVD = "NVD"
        env = make_env(json.dumps({"id": "CVE-1", "descriptions": [{"lang": "en", "value": "d"}]}), ST.NVD)
        self.assertEqual(chunk_envelope(env)[0].Source_Type, "NVD")


STAGING_FILE = STAGING_DIR / "latest_envelopes.json"


@unittest.skipUnless(STAGING_FILE.exists(), "staging envelopes not present")
class TestRealStagingData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = json.loads(STAGING_FILE.read_text(encoding="utf-8"))
        cls.envs = data["envelopes"] if isinstance(data, dict) else data

    def test_all_chunks_within_caps_with_no_over_cap_flag(self):
        for env in self.envs:
            for c in chunk_envelope(env):
                cap = CHUNK_TIER1_MAX_CHARS if c.Tier == 1 else CHUNK_TIER2_MAX_CHARS
                self.assertLessEqual(c.Char_Count, cap, c.Chunk_ID)
                self.assertNotIn("over_cap", c.Flags)

    def test_every_nonempty_item_produces_chunks(self):
        for env in self.envs:
            if env["Raw_Content"].strip():
                self.assertTrue(chunk_envelope(env), env["Item_ID"])

    def test_html_pages_are_cleaned_of_page_chrome(self):
        for env in self.envs:
            if env["Source_Type"] in ("ANDROID_BULLETIN", "APPLE_SECURITY"):
                text = "\n".join(c.Text for c in chunk_envelope(env))
                self.assertNotIn("<html", text)
                self.assertNotIn("google-signin", text)
                self.assertLess(len(text), len(env["Raw_Content"]) * 0.5)

    def test_project_zero_code_blocks_survive_verbatim_in_tier2(self):
        for env in self.envs:
            if env["Source_Type"] != "PROJECT_ZERO":
                continue
            t2 = norm("\n".join(c.Text for c in chunk_envelope(env) if c.Tier == 2))
            soup = BeautifulSoup(env["Raw_Content"], "html.parser")
            for pre in soup.find_all("pre"):
                code = norm(pre.get_text())
                if code:
                    self.assertIn(code, t2, env["Item_ID"])

    def test_github_advisory_code_fences_survive_in_tier2(self):
        for env in self.envs:
            if env["Source_Type"] != "GITHUB_ADVISORY":
                continue
            t2 = norm("\n".join(c.Text for c in chunk_envelope(env) if c.Tier == 2))
            for block in re.findall(r"```[^\n]*\n(.*?)```", env["Raw_Content"], re.S):
                if block.strip() and len(block) < CHUNK_TIER2_MAX_CHARS - 200:
                    self.assertIn(norm(block), t2, env["Item_ID"])


if __name__ == "__main__":
    unittest.main()
