# GroundedCVE Demo Guide

> **ICT 2114 Integrative Team Project, IS 24, Team 4**
> A 10 to 15 minute live demo of the whole pipeline, in the order the data flows.
> Each part says what to run, what to point at, and what to say. Numbers in quotes
> are from our own runs; re-run the commands before the demo and use today's figures.

---

## Before the demo (15 minutes before)

1. Start everything: `docker compose up -d --build`, then `docker compose logs -f scheduler` until you see `=== Run metrics ===`.
2. Open **http://localhost:5000** and check that items show the green **✓ Verified** badge.
3. Telegram cards carry only public NVD/source/PoC links (written out in full), so they open on any phone. The dashboard itself is reachable from a phone on the same Wi-Fi at `http://<PC IP>:5000` if Windows Firewall allows port 5000.
4. Make sure the bot is an admin of the channel **with the "Pin Messages" right** (the weekly duplicate guard pins each edition).
5. Have a terminal open in the repo. Outside Docker, prefix commands with `python`; inside, use `docker compose exec app python ...`.

---

## Part 1: The problem (1 minute, slides)

> *"Pentesters have to watch NVD, CISA KEV, vendor bulletins, GitHub, PortSwigger, Project Zero and Frida. Feeds are noisy, and general-purpose AI summaries invent CVE IDs, versions and command flags. GroundedCVE collects, ranks, summarises and then checks every fact against the source before anything is published."*

## Part 2: Collection and the staging envelope (1 to 2 minutes)

```bash
python Backend/run_ingestion.py --limit 3 --poc
```

Point at: one line per source (NVD, CISA KEV, GitHub Advisory, PortSwigger, Project Zero, Android, Apple, Frida, GitHub PoC). Open an item in the dashboard and show `Raw_Content` and `Content_Hash`.

> *"Every source becomes the same JSON envelope. Raw_Content is never modified, so the verification gate later checks facts against exactly what the source said."*

## Part 3: Triage and ranking (2 minutes)

```bash
python Backend/run_triage.py
```

Point at: the 100-point score (KEV 40 + AI severity 40 + PoC 20), an `[!] ANOMALY` line (CVSS vs AI differ by 4 or more), and the "How items are ranked" popup (📘 in the header), which explains why KEV carries 40 points. Story scoring only shows when the same CVE arrives from two feeds in one run; if none does, show `test_change_tracking.py` (`TestGroupByCve`).

> *"Items that share a CVE ID are scored as one story: the NVD record, its KEV entry and a GitHub PoC all count together, so the NVD copy isn't under-ranked just because NVD doesn't know about the exploit."*

## Part 4: Chunking, hybrid search (2 minutes)

```bash
python Backend/run_chunking.py
python Backend/run_indexing.py
python Backend/run_search_eval.py
```

In the dashboard, search for an exact token (a CVE ID or `frida`) and then a plain-English description.

> *"Two-tier chunks: a summary tier and a PoC/evidence tier that is never cut mid-command. Search fuses BM25 keyword vectors with nomic-embed-text meaning vectors using Reciprocal Rank Fusion, k=60. The eval script prints recall@1, recall@3 and MRR for keyword-only, meaning-only and hybrid."*

## Part 5: Grounded summaries and the verification gate (3 minutes, the core)

```bash
python Backend/run_summarise.py --top 5
python Backend/run_gate_demo.py
python Backend/run_gate_report.py summary
python Backend/run_gate_report.py recheck
```

Point at:
- `run_gate_demo.py`: eight kinds of planted fault (fake CVE, altered version, invented flag, fake URL, made-up impact, wrong CVSS, wrong CWE, wrong vendor) on 20 ground-truth items. "160/160 caught, 0% false quarantine on clean drafts."
- `run_gate_report.py summary`: what happened to the real AI-written cards. "On our 4 Nov run, 29 cards were drafted: 27 passed first time, 2 were fixed after one retry, none were quarantined."
- `run_gate_report.py recheck`: today's gate re-run over every published card. "0 of 27 published cards fail, so the vendor/product check added no false quarantines."

> *"The gate is plain Python with no LLM. Every CVE, version, CVSS, CWE, vendor/product, command, impact claim and URL in the draft must appear in the item's own source. If not, the model gets one retry with the reasons; if it still fails, the card is quarantined and never published."*

## Part 6: Novelty and the weekly Telegram digest (2 minutes)

```bash
python Backend/run_telegram_digest.py --dry-run
```

Then show the real channel on a phone.

Point at:
- The header `Edition 2026-Wnn`, pinned in the channel.
- Each card: rank, CVE, score, verified summary, the first testing command in a code block, and the NVD, Source and PoC links written out in full, which open on any device.
- Run it again without `--dry-run`: "Edition already pinned, no update."

> *"Each teammate's PC runs the scheduler, so without a guard the channel got the same week twice. Now the header is pinned and any PC that sees this week's edition pinned skips. Items already sent are only re-sent when something changed, like a new KEV listing or a new PoC."*

If asked about the novelty threshold:

```bash
python Backend/run_novelty_eval.py
```

> *"The similarity cut-off for write-ups without a CVE ID is tuned on labelled duplicate/distinct pairs and checked on a held-out half, which reports the suppression and false-suppression rates."*

## Part 7: Automation, cost and quality (1 minute)

```bash
docker compose logs scheduler | tail -20
python -m pytest -q Testing
```

Point at the `=== Run metrics ===` block: time per stage, end-to-end time, LLM calls, tokens and cost for the run. Then the test count.

> *"One `docker compose up` runs the whole pipeline daily at 08:00 Singapore time and the digest weekly. CI runs the test suite on every pull request."*

---

## Cheat sheet

| Step | Command |
| :--- | :--- |
| Everything | `docker compose up -d --build` |
| Run pipeline once now | `docker compose run --rm scheduler python Backend/run_pipeline.py` |
| Ingest | `python Backend/run_ingestion.py --limit 3 --poc` |
| Triage | `python Backend/run_triage.py` |
| Chunk + index | `python Backend/run_chunking.py && python Backend/run_indexing.py` |
| Search eval | `python Backend/run_search_eval.py` |
| Summaries + gate | `python Backend/run_summarise.py` |
| Gate fault injection | `python Backend/run_gate_demo.py` |
| Gate on real cards | `python Backend/run_gate_report.py summary` / `recheck` |
| Manual card review | `python Backend/run_gate_report.py worksheet` then `score <csv>` |
| Novelty threshold | `python Backend/run_novelty_eval.py` |
| Extraction benchmark | `python Backend/run_benchmark.py` |
| Digest preview | `python Backend/run_telegram_digest.py --dry-run` |
| Tests | `python -m pytest -q Testing` |

---

## Likely questions

**Why not just trust the LLM with a good prompt?** The prompt asks for source-only facts, but models still slip. The gate is the guarantee: it is deterministic, cheap, and its catches are shown in `run_gate_demo.py` and `run_gate_report.py`.

**What can the gate not catch?** A wrong statement made only of words that are in the source, such as overstating who can exploit a flaw. That's why `run_gate_report.py worksheet` exists: people review a sample of published cards and we report the manual error rate.

**Why is the digest weekly but the pipeline daily?** Daily ingestion keeps the dashboard and search fresh; the weekly digest is the curated newsletter the proposal promised.

**Why HTML and not MarkdownV2 in Telegram?** HTML only needs `<`, `>` and `&` escaped, which is safer with raw command text than MarkdownV2's long list of reserved characters.

**How do you avoid sending the same thing twice?** Same-CVE items are merged; sent items are recorded and only re-sent when something new happened; near-identical write-ups are caught by embedding similarity; and the pinned edition stops a second PC posting the same week.

**What does a run cost?** See the `Run metrics` block. OpenRouter reports the cost of every call and the pipeline adds them up per run.
