# Manual spot-check: 10 verified items (22 November 2026)

The automated tests and the verification gate check that every fact on a card
appears in its source. This hand check asks a different question: does the page a
tester reads match the official advisory? One reviewer checked 10 published
(Verified) items against their NVD, GitHub or Apple source, fixed what the check
found, and checked the affected items again.

## How to demo it

1. Start the stack with `docker compose up -d` and open http://localhost:5000.
2. Pick any row below. Open the **Card** link (the item's reader page) and the
   **Source** link side by side.
3. Walk through the four questions for that item and compare with the result in
   the table.

## The four questions

| | Question | Mark Y when |
|---|---|---|
| A | Right thing? | The CVE ID and product (for Apple, the OS and release) match the source. |
| B | Versions and fix right? | The affected versions and the fix match the source. |
| C | Right category? | It really is a Web or Mobile issue, as labelled. |
| D | Badges right? | The KEV and PoC badges are correct. |

## The 10 items

5 CISA KEV items (the highest priority), 3 other web items and 2 Apple bulletins.

| # | Item | Card | Source | First pass (A B C D) | Re-check (A B C D) |
|---|---|---|---|---|---|
| 1 | Apache Roller, CVE-2026-129448 | [card](http://localhost:5000/incident/cisa-kev-cve-2026-129448) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-129448) | Y Y Y Y | not needed |
| 2 | VMware vCenter, CVE-2026-123890 | [card](http://localhost:5000/incident/cisa-kev-cve-2026-123890) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-123890) | Y Y Y Y | not needed |
| 3 | LiteLLM, CVE-2026-40217 | [card](http://localhost:5000/incident/cisa-kev-cve-2026-40217) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-40217) | Y Y Y Y | not needed |
| 4 | REDCap, CVE-2026-90817 | [card](http://localhost:5000/incident/cisa-kev-cve-2026-90817) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90817) | Y Y Y Y | not needed |
| 5 | Apache Axis, CVE-2026-90436 | [card](http://localhost:5000/incident/cisa-kev-cve-2026-90436) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-90436) | Y Y Y Y | not needed |
| 6 | Keycloak JWT, CVE-2026-11800 | [card](http://localhost:5000/incident/ghsa-ghsa-j97h-3f8r-mrjr) | [GitHub advisory](https://github.com/advisories/GHSA-j97h-3f8r-mrjr) | Y **N** Y Y | Y Y Y Y |
| 7 | Plague Inc: Evolved, CVE-2026-116230 | [card](http://localhost:5000/incident/nvd-cve-2026-116230) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-116230) | Y **N** **N** Y | Y Y **N** Y |
| 8 | Ultimate Member (WordPress), CVE-2026-115968 | [card](http://localhost:5000/incident/nvd-cve-2026-115968) | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-115968) | Y **N** Y Y | Y Y Y Y |
| 9 | Apple iOS / iPadOS 18.7.11 | [card](http://localhost:5000/incident/apple-149225) | [Apple](https://support.apple.com/en-us/149225) | Y **N** Y Y | Y Y Y Y |
| 10 | Apple tvOS 27.2.1 | [card](http://localhost:5000/incident/apple-149721) | [Apple](https://support.apple.com/en-us/149721) | Y **N** **N** Y | Y Y **N** Y |

## Scores

| Question | First pass | After the fix |
|---|---|---|
| A. Right thing | 10/10 | 10/10 |
| B. Versions and fix | 5/10 | 10/10 |
| C. Category | 8/10 | 8/10 |
| D. Badges | 10/10 | 10/10 |

All five CISA KEV items were fully correct in both passes.

## What the check found

**1. The reader page hid the verified card's fix (B on #6, #7, #8).**
The reader page showed only fields taken straight from the source. Its "How to fix"
box used CISA's required action, which only KEV items have, so every other item said
"No fix information in the source yet" even when its verified card gave a fix (for
example "Upgrade to version 1.24.0.4" for #7). The cards themselves were right.
Fixed in commit `de7905d`: the reader page now shows the verified card (what it is,
impact, test commands and fix) and adds a "Verified against the source" badge.

**2. Apple releases were shown as the affected product (B on #9, #10).**
An Apple bulletin is named after the release that fixes its flaws, but the page
listed that release under "Affected". Fixed in `de7905d`: Apple items now show a
"Fixed in" section ("Earlier versions are affected") and a fix line of the form
"Update to tvOS 27.2.1 or later". Commit `a565eb6` also stopped Apple pages listing
about 40 navigation and locale-copy links as sources.

**3. Two category labels are wrong (C on #7, #10). Not fixed.**
- #7 is a desktop game but is labelled Web. The scope filter tags any item whose CWE
  is on the web list, and CWE-502 (deserialization) is on it.
- #10 is tvOS but is labelled Mobile. The scope filter treats every Apple bulletin
  as Mobile by source, which is right for iOS and iPadOS but not for tvOS, watchOS
  or macOS.

The fix is to check the product type as well as the CWE and the source. This is
listed as future work in the report (Section 6.5).

**4. A limit of the gate.**
The tvOS card's impact sentence says the flaws affect devices running tvOS 27.2.1,
which is the fixed release. The gate passes it because that version appears in the
source: it checks that a version is present, not whether it is the affected or the
fixed one.

## Limits of this check

One reviewer and 10 items is a spot check, not an accuracy measurement. The
automated evidence covers scale: the gate caught all 160 planted faults (Section
5.4 of the report) and has checked 105 real drafted cards, quarantining 6.
