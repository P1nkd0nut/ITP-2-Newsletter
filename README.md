# GroundedCVE: AI-Powered CVE Newsletter & Threat Intelligence Engine
[![CI](https://github.com/P1nkd0nut/ITP-2-Newsletter/actions/workflows/ci.yml/badge.svg)](https://github.com/P1nkd0nut/ITP-2-Newsletter/actions/workflows/ci.yml)
> **ICT 2114 Integrative Team Project — IS 24 | Team 4 (Singapore Institute of Technology)**

GroundedCVE is an automated threat intelligence retrieval and curation platform designed to bridge the discovery gap for Web and Mobile application security engineers and penetration testers. The platform systematically collects, structures, ranks, verifies, and synthesises actionable vulnerability disclosures with strict source grounding.

---

## Quick start (Docker, one command)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) running and an [OpenRouter API key](https://openrouter.ai/keys).

```bash
git clone https://github.com/P1nkd0nut/ITP-2-Newsletter.git
cd ITP-2-Newsletter
cp .env.example .env          # then put your OPENROUTER_API_KEY in .env (Telegram optional)
docker compose up -d --build
```

Open **http://localhost:5000**. That's it. Docker starts:

| Container | What it does |
|---|---|
| `app` | Dashboard + API on port 5000 |
| `scheduler` | Runs the full pipeline at start and then every day at 08:00 Singapore time (`PIPELINE_RUN_TIME` / `PIPELINE_TIMEZONE` in `.env`): ingest → triage → chunk → embed into Qdrant → write grounded summaries → verification gate → weekly Telegram digest |
| `qdrant` | Vector database (port 6333) |
| `ollama` | Embeddings (`nomic-embed-text`, downloaded automatically by `ollama-pull` on first start). Internal only, so it doesn't clash with an Ollama you already run on port 11434 |

Watch the first run with `docker compose logs -f scheduler` (the first start downloads the ~270 MB embedding model). The dashboard shows a green **✓ Verified** badge on items whose summary passed the gate, and only those go into the digest. If `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are set, the digest is sent on the first run and then once every 7 days.

Stop everything with `docker compose down`. Data stays in `Backend/data`, `qdrant_storage` and `ollama_data`.

---

## Phase 1: Source Collection & Knowledge Ingestion (Task 1.3)

This repository contains the completed **Stage 1 (Knowledge Ingestion & Staging Standardization)** pipeline. It collects unstructured vulnerability disclosures, proof-of-concept repositories, and offensive security research across Web and Mobile ecosystems, outputting to a standardized JSON staging envelope without data corruption.

### Monitored Threat Intelligence Feeds
- **CISA KEV**: Actively exploited vulnerabilities catalog (flagged with `KEV_Status = True`).
- **NIST NVD 2.0 REST API**: Comprehensive CVE feeds filtered by the latest 7-day publication window (`pubStartDate`/`pubEndDate`), extracting CVSS v3.1/v4.0, CWEs, and affected CPE products.
- **PortSwigger Web Security Research**: Novel protocol desynchronisation, request smuggling, cache poisoning, and authentication primitives.
- **Google Project Zero**: In-depth mobile, OS kernel, and memory exploitation research.
- **GitHub Advisory Database**: Package-level advisories across Web ecosystems (`npm`, `pip`, `go`, `maven`).
- **Frida Dynamic Instrumentation**: Hooking primitives, bypass techniques, and framework release notes.
- **Android & Apple Security Bulletins**: Authoritative OEM/OS patch bulletins.
- **GitHub PoC Detection**: Public repository discovery referencing discovered CVEs with star and reliability metrics.

---

## Standardised JSON Staging Envelope Specification

Every ingested item is wrapped into a strictly validated Pydantic envelope (`Backend/ingestion/models.py`):

| Field | Type | Description |
| :--- | :--- | :--- |
| `Item_ID` | `str` | Globally unique deterministic item identifier |
| `Source_Type` | `SourceType` | Category: `NVD`, `CISA_KEV`, `PORTSWIGGER`, `PROJECT_ZERO`, `GITHUB_ADVISORY`, `FRIDA`, `ANDROID_BULLETIN`, `APPLE_SECURITY` |
| `Title` | `str` | Title of advisory, CVE, or research article |
| `Source_URL` | `str` | Canonical source link |
| `Published_Date` | `str` | ISO 8601 publication timestamp |
| `Ingested_At` | `str` | ISO 8601 ingestion timestamp |
| `Content_Hash` | `str` | Deterministic SHA-256 hash of `Raw_Content` |
| `Raw_Content` | `str` | Verbatim unmodified source text (preserved for verification gate) |
| `CVE_ID` | `Optional[str]` | Primary CVE ID if applicable (e.g. `CVE-2026-88772`) |
| `Vendor_Product` | `Optional[str]` | Affected software/vendor string |
| `CVSS` | `Optional[float]` | Base score |
| `CVSS_Version` | `Optional[str]` | Metric version (`3.1` or `4.0`) |
| `CWE` | `Optional[list]` | Associated CWE identifiers |
| `KEV_Status` | `Optional[bool]` | True if present in CISA KEV |
| `PoC_URLs` | `Optional[list]` | Public PoC repository URLs |

---

## Project Structure

```
ITP2/
├── Backend/
│   ├── config.py                              # Central configuration & API endpoints
│   ├── run_ingestion.py                       # CLI runner with rich summary tables & envelope previews
│   ├── run_triage.py                          # CLI runner for Scope Pre-Filter, AI Scoring, & Anomaly Gate
│   ├── run_benchmark.py                       # Empirical Performance & Fact Extraction Benchmark (Task 4.1)
│   ├── run_chunking.py                        # CLI runner that cleans envelopes and writes chunked output
│   ├── run_indexing.py                        # Embeds chunks with nomic-embed-text and upserts them into Qdrant
│   ├── run_summarise.py                       # Writes grounded cards and gates them before publishing
│   ├── run_pipeline.py                        # All stages in order; the Docker scheduler runs this
│   ├── run_gate_report.py                     # Gate results on real cards, re-check, manual review sheet
│   ├── run_novelty_eval.py                    # Tunes the novelty similarity threshold on labelled pairs
│   ├── llm_usage.py                           # Logs OpenRouter tokens and cost per call
│   ├── export_triage_dashboard.py             # Generative UI artifact exporter
│   ├── data/
│   │   ├── ground_truth_20.json               # 20-sample human-verified Web & Mobile extraction set
│   │   └── staging/
│   │       ├── latest_envelopes.json          # Persisted raw staging envelopes
│   │       └── triaged_candidates.json        # 100-pt scored candidates & anomaly records
│   └── ingestion/
│       ├── models.py                          # Pydantic schema for StagingEnvelope
│       ├── utils.py                           # SHA-256 hashing, ISO dates, HTTP with retry
│       ├── pipeline.py                        # Multi-source pipeline orchestrator & deduplication
│       └── collectors/                        # Modular feed collectors
│           ├── cisa_kev.py
│           ├── nvd.py
│           ├── rss_feeds.py
│           ├── github_advisory.py
│           ├── mobile_sources.py
│           └── github_poc.py
│   ├── triage/
│   │   ├── models.py                          # Pydantic models for PreFilterDecision, AISeverityAssessment, CVSSDiscrepancy
│   │   ├── pre_filter.py                      # Dedicated Pentest Pre-Filter (Web vs Mobile isolation)
│   │   ├── ai_evaluator.py                    # Practical Severity Assessor (OpenRouter Qwen 2.5 72B / Ollama)
│   │   └── priority_scorer.py                 # 100-pt AI Priority Scoring + CVSS Discrepancy Gate
│   ├── chunking/
│   │   ├── cleaner.py                         # Normalises JSON/HTML/Markdown/text raw content
│   │   ├── chunker.py                         # Splits cleaned content into traceable chunks
│   │   └── models.py                          # Chunk data model
│   ├── summarisation/
│   │   ├── summariser.py                      # Writes each card from the item's own retrieved chunks
│   │   └── card_store.py                      # Passed cards (grounded_cards.json) & quarantine log
│   └── storage/
│       ├── vector_db.py                       # Qdrant client helper
│       ├── init_qdrant.py                     # Creates the Qdrant collections (Task 2.1)
│       ├── embedder.py                        # Ollama nomic-embed-text client
│       └── indexer.py                         # Chunk upsert & per-item retrieval (Qdrant, file fallback)
├── Frontend/
│   ├── dashboard/                             # Dashboard served at / (index.html, app.js, styles.css, prebuilt tailwind.css)
│   ├── reader/                                # Reader page for one item (/incident/<id>)
│   ├── index.html                             # Fallback page, served only if dashboard/ is missing
│   ├── data.js                                # Auto-synced envelopes data for instant loading
│   └── run_dashboard.py                       # 1-command local dashboard server
├── Testing/
│   ├── test_ingestion.py                      # Phase 1 test suite (10 unit & integration tests)
│   ├── test_nvd_collector.py                  # NVD collector: newest CVEs first, CVSS choice, affected versions (10 tests)
│   ├── test_triage.py                         # Phase 2 test suite (9 pre-filter, scoring, & OpenRouter tests)
│   ├── test_benchmark.py                      # Task 4.1 benchmark test suite (8 validation tests)
│   ├── test_verification.py                   # Verification gate test suite (24 grounding & retry tests)
│   ├── test_dashboard_api.py                  # REST API, channel dispatcher & score explanation tests (13 tests)
│   ├── test_link_validator.py                 # Link health validator tests (13 tests)
│   ├── test_chunking.py                       # Content cleaning & chunking tests (27 tests)
│   ├── test_change_tracking.py                # Change tracking between runs & AI-score reuse (14 tests)
│   ├── test_recheck_policy.py                 # Age-based re-check tiers, 1-year freeze, recency labels (13 tests)
│   ├── test_poc_provenance.py                 # CVE-specific PoC links & reference provenance (6 tests)
│   ├── test_reader_and_telegram.py            # Incident reader page, Telegram weekly digest & dead-link handling (32 tests)
│   ├── test_manual_check.py                   # Manual spot-check sampler & scorer (4 tests)
│   ├── test_grounded_summaries.py             # Qdrant indexing, grounded cards, publish gate & scheduler (22 tests)
│   ├── test_novelty.py                        # Digest novelty check: one item per CVE, no repeats (10 tests)
│   ├── test_apple_collector.py                # One item per Apple advisory with real dates (7 tests)
│   ├── test_gate_report.py                    # Gate stats on real cards, re-check, manual review sheet (5 tests)
│   ├── test_novelty_eval.py                   # Novelty threshold tuning and labelled pairs (6 tests)
│   ├── test_run_metrics.py                    # Per-stage latency and LLM cost reporting (4 tests)
│   └── MANUAL_CHECKS.md                       # How the team hand-checks the automated results
├── DEMO_GUIDE.md                              # Presentation script & step-by-step cheatsheet for demo
├── HANDOVER.md                                # Setup, configuration, quarantine review, adding a source, limitations
└── docker-compose.yml                         # app, scheduler, Qdrant (vector DB), Ollama (embeddings)
```

---

## Quickstart Guide

### 1. Installation
Clone repository and install dependencies:
```bash
git clone https://github.com/P1nkd0nut/ITP-2-Newsletter.git
cd ITP-2-Newsletter
pip install -r requirements.txt  # (pydantic, feedparser, rich, qdrant-client)
```

### 2. Start the Vector Database Infrastructure (Task 2.1)
Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

Start the self-hosted Qdrant vector database and local Ollama embedding server:
```bash
docker compose up -d
```
This provisions:
- **Qdrant** (`localhost:6333`) — persisted to `./qdrant_storage`
- **Ollama** (`localhost:11434`) — persisted to `./ollama_data`, used to serve `nomic-embed-text` for local embeddings

Then initialise the two Qdrant collections (`groundedcve_items`, `groundedcve_published`):
```bash
python Backend/storage/init_qdrant.py
```

Pull the embedding model into Ollama (one-time, ~274MB):
```bash
docker exec groundedcve-ollama ollama pull nomic-embed-text
```

Check everything is healthy:
```bash
docker compose ps
```

### 3. Run Data Ingestion
Execute the multi-source collection pipeline:
```bash
# Ingest 3 items per source across all feeds
python Backend/run_ingestion.py --limit 3

# Or ingest specific feeds (e.g. CISA KEV and PortSwigger)
python Backend/run_ingestion.py --sources cisa_kev,portswigger --limit 2

# Enable public GitHub PoC detection for CVEs
python Backend/run_ingestion.py --sources cisa_kev --poc --limit 2
```

### 4. Run Pentest Scope Pre-Filter & AI Priority Scoring (Phase 2, Task 1.2 & 2.4)
Execute the Pre-Filter Gate and 100-point AI practical severity ranking:
```bash
python Backend/run_triage.py
```
This runs:
1. **Scope Pre-Filter Gate**: Isolates `[WEB]` and `[MOBILE]` threats via feed origin, Task 1.2 CWE taxonomy, and technical keywords. Non-web/mobile items (print spoolers, firmwares) bypass the weekly scoring queue.
2. **AI Practical Severity Assessment (Qwen 2.5)**: Evaluates real-world offensive impact (RCE vs DoS) with Qwen 2.5 72B on OpenRouter, falling back to a local Ollama model and then to keyword rules.
3. **100-Point Scoring Engine**:
   - Active exploitation (in CISA KEV): **40 pts**
   - AI practical severity (0-10 × 4): **up to 40 pts**
   - Public PoC available: **20 pts**
4. **CVSS Discrepancy Flag**: Flags any item where `|AI_Severity - CVSS| >= 4.0` for a person to review. It does not change the score.

**Why 40 / 40 / 20.** The weights follow SSVC's three exploitation states: none, public PoC, active. Active exploitation (a CISA KEV listing) carries the most weight because it is confirmed evidence that attackers use the flaw. A public PoC carries half as much: it lowers the barrier but does not prove use. Practical severity carries the remaining 40, so within each exploitation state items are ordered by what an attacker gains. As a result KEV works almost as a tier: a KEV item with severity above 5 outranks every non-KEV item (at most 60 with a PoC, 40 without). This is intended, since exploited issues should come first. Official CVSS is left out of the score because new records often have none or a worst-case default; it is kept for the discrepancy flag. The weights are round numbers so each card can explain its score in one line; they were not fitted to data. Items sharing a CVE ID are scored as one story (`group_by_cve`).

### 4b. Write Grounded Summaries (Task 2.3, 3.1 & 3.2)
Chunk the staged items, embed the chunks into Qdrant, then write and gate the cards:
```bash
python Backend/run_chunking.py
python Backend/run_indexing.py      # needs Qdrant + Ollama with nomic-embed-text
python Backend/run_summarise.py     # top 10 in-scope items from the last 7 days
```
Each card is written by the LLM (OpenRouter Qwen 2.5 72B, or `--ollama-model` for a local model) using only that item's own chunks, then checked by the source-verification gate: every CVE ID, version, CVSS score, CWE, known vendor/product name, command, impact claim and URL must appear in the source. A failing card is regenerated once with the gate's reasons; if it still fails it is quarantined.

Measure the gate on the cards it actually saw with `python Backend/run_gate_report.py summary` (first-try pass, passed after retry, quarantined, failures by check) and `recheck` (today's gate over every published card). `worksheet` / `score` produce and score a manual review sheet of published cards, for errors token checks can't catch. See [HANDOVER.md](HANDOVER.md).

- Passed cards go to `Backend/data/staging/grounded_cards.json`. The dashboard digest, the newsletter export and the Telegram weekly digest only include items with a passed card.
- Quarantined cards and generation errors are appended to `Backend/data/staging/quarantine_log.jsonl` with the failing facts.
- If Qdrant is not running, chunks are read straight from `latest_chunks.json`.
- Cards are only rewritten when the item's source changes (`--force` to rewrite all).

**Novelty check (weekly digest).** The newsletter never repeats itself:
- The same CVE reported by several sources (NVD, CISA KEV, GitHub Advisory) is sent once, as the highest-priority version.
- Every incident a digest sends is recorded in `Backend/data/staging/published_ledger.json` and in the Qdrant `groundedcve_published` collection. It is only sent again when something new happened (added to CISA KEV, a new public PoC, or a CVSS change), marked "🔁 Update: …".
- Write-ups with no CVE ID (PortSwigger, Project Zero) are compared with published cards by embedding; a near-identical one is skipped. The cosine threshold is tuned by `python Backend/run_novelty_eval.py` on labelled duplicate/distinct pairs (`Backend/data/novelty_pairs.json`, tuning half + held-out half) and saved to `Backend/data/novelty_threshold.json`; until then it is 0.92. `NOVELTY_SIMILARITY` in `.env` overrides it.
- `python Backend/run_telegram_digest.py --include-sent` turns this off for one run.

**Run metrics.** Every `run_pipeline.py` run ends with a `Run metrics` block: seconds per stage, end-to-end time, and LLM calls, tokens and cost (as reported by OpenRouter) per stage. Each run is also appended to `Backend/data/staging/run_metrics.jsonl`.

### 5. Run Task 4.1 Ground-Truth Benchmark & Validation Suite
Execute empirical validation across the 20-sample ground-truth Web & Mobile dataset:
```bash
python Backend/run_benchmark.py
```
This computes and reports:
- **Fact Extraction Precision (FEP %)** (Target $\ge 95.0\%$, Observed: **100.0%**)
- **Hallucination Rate (HR %)** (Target $\le 5.0\%$, Observed: **0.0%**)
- **Scope Pre-Filter Accuracy** (Observed: **100.0%**). The 20 items are all web or mobile, so this measures Web vs Mobile labelling, not rejection of out-of-scope items.
- **CVSS Discrepancy Flag Accuracy** (Observed: **100%** with the model). Only 1 of the 20 items is labelled as a real discrepancy, so this is a small check.
- **AI Severity Error**: mean absolute difference between the AI rating and the labelled `expected_ai_severity`, in points out of 10.

### 6. Launch the GroundedCVE dashboard (Primary Delivery Channel)
Start the unified Flask REST API and Executive Web Dashboard:
```bash
python run_server.py
```
*(Automatically opens `http://localhost:5000` in your browser).*

Alternatively, start via the frontend runner on port 8080:
```bash
python Frontend/run_dashboard.py
```

#### Channel Architecture
- **Primary Delivery Channel (Web Dashboard)**: The authoritative home for weekly newsletter digests, 100-point priority rankings with a per-item score explanation, gate-verified cards, hybrid search, and raw envelope verification.
- **Secondary Delivery Channel (Telegram Bot)**: The weekly digest: a pinned header ("Edition 2026-Wnn") and one message per verified incident with its summary, the first testing command in a code block, and links to the NVD record, the source advisory and a public PoC. Each link is written out in full on its own line, so it shows and opens on any device, including phones. Telegram cards never link to the dashboard, because it runs on a team PC most readers can't reach. The bot needs the "Pin Messages" admin right so other PCs can see the week was already posted.

#### REST API Endpoints Reference
| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/health` | GET | Health status and channel policy |
| `/api/stats` | GET | Aggregated KPI metrics, distribution bands, and anomaly counts |
| `/api/newsletters` | GET | Query candidates with scope filtering (`WEB`, `MOBILE`), search, and sorting |
| `/api/newsletters/<id>` | GET | Deep-dive detail for a specific disclosure |
| `/api/newsletter/digest` | GET | Curated weekly threat intelligence edition |
| `/api/newsletter/export` | GET | Export issue in Markdown (`?format=markdown`) or HTML (`?format=html`) |
| `/api/refresh` | POST | Live reload of staged threat candidate dataset |
| `/api/links/stats` | GET | Cached link health, active ratio, and average latency statistics |
| `/api/links/verify` | GET/POST | Fast concurrent verification of all cataloged reference links |
| `/api/channels` | GET | Channel hierarchy status (Primary vs Secondary) |
| `/api/channels/telegram` | PUT | Configure Telegram secondary notification settings |
| `/api/channels/telegram/test`| POST | Verify secondary Telegram bot integration (live or simulated) |

#### Keeping older CVEs up to date
Ingestion re-checks CVEs that dropped out of the feeds, less often as they age (`Backend/ingestion/recheck_policy.py`):

| CVE age | Re-checked |
| :--- | :--- |
| Under 1 month | every daily run |
| 1–6 months | monthly |
| 6–12 months | quarterly |
| Over 1 year | never (frozen, shown with a "Not updated" disclaimer) |

NVD records are fetched again and PoC searches repeated; anything that changed is flagged `UPDATED` with a summary. Use `--no-recheck` to skip this. The dashboard never shows exact dates: cards say how recent an item is ("Recent", "Past month", "Over a year ago") and the filters are Recent / Past month / All.

Why these cut-offs: most change happens early. Mandiant measured an average time-to-exploit of 5 days in 2023 ([source](https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023?hl=en)), and VulnCheck found about a quarter of known-exploited CVEs were exploited on or before their publication day ([source](https://www.vulncheck.com/blog/state-of-exploitation-1h-2026)), so the first month is checked daily. Later changes still happen (VulnCheck reports a median of 80 to 120 days from publication to a CISA KEV listing), so checks continue monthly and then quarterly for the first year. An old CVE that CISA newly adds to KEV is not missed by the freeze: it arrives as a new item from the daily KEV pull.

### 6b. Run in Docker
```bash
docker compose up -d --build                  # dashboard + daily pipeline (see Quick start above)
docker compose run --rm scheduler python Backend/run_pipeline.py   # run the pipeline once more now
```
Keys go in a `.env` file (see `.env.example`); `Backend/data` is mounted so data persists. Outside Docker, `python Backend/run_pipeline.py` runs the same stages once.

### 7. Run Test Suite
Verify all collector parsers, pre-filters, AI scoring, anomaly detection gates, verification gates, REST API endpoints, link validation, chunking, change tracking, grounded summaries, and channel dispatchers (268 automated tests in 21 modules):
```bash
python -m unittest discover -s Testing -p "test_*.py" -v
```
Seven of these (`TestCollectorsLive` and `TestIngestionPipeline` in `test_ingestion.py`) call real feeds and need internet access; they skip automatically when the feeds can't be reached. CI runs the other 261 on every push to `main` and every pull request, and runs the live ones in a separate step that is allowed to fail. No API keys are needed for the tests.

### 8. Presentation & Demo Guide
For full presentation instructions, talking points, and cheat-sheet commands for project reviews, see:
[`DEMO_GUIDE.md`](DEMO_GUIDE.md)
