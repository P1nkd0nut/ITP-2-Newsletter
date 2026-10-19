# GroundedCVE: AI-Powered CVE Newsletter & Threat Intelligence Engine
> **ICT 2114 Integrative Team Project — IS 24 | Team 4 (Singapore Institute of Technology)**

GroundedCVE is an automated threat intelligence retrieval and curation platform designed to bridge the discovery gap for Web and Mobile application security engineers and penetration testers. The platform systematically collects, structures, ranks, verifies, and synthesises actionable vulnerability disclosures with strict source grounding.

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
│   ├── run_chunking.py                        # CLI runner for cleaning + two-tier chunking (Task 2.2)
│   ├── run_benchmark.py                       # Empirical Performance & Fact Extraction Benchmark (Task 4.1)
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
│   │   ├── models.py                          # Chunk dataclass (IDs, tier, heading path, traceability metadata)
│   │   ├── cleaner.py                         # Per-format cleaning (JSON / HTML / Markdown / text) -> cleaned copy
│   │   └── chunker.py                         # Heading-aware Tier 1 / Tier 2 chunking + gate evidence helper
│   └── storage/
│       ├── vector_db.py                       # Qdrant client helper
│       └── init_qdrant.py                     # Creates the Qdrant collections (Task 2.1)
├── Frontend/
│   ├── index.html                             # Cyber-themed interactive dashboard
│   ├── data.js                                # Auto-synced envelopes data for instant loading
│   └── run_dashboard.py                       # 1-command local dashboard server
├── Testing/
│   ├── test_ingestion.py                      # Phase 1 test suite (10 unit & integration tests)
│   ├── test_chunking.py                       # Task 2.2 chunking test suite (27 tests)
│   ├── test_triage.py                         # Phase 2 test suite (9 pre-filter, scoring, & OpenRouter tests)
│   └── test_benchmark.py                      # Task 4.1 benchmark test suite (6 validation tests)
├── DEMO_GUIDE.md                              # Presentation script & step-by-step cheatsheet for demo
└── docker-compose.yml                         # Qdrant (vector DB) + Ollama (local embeddings)
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
2. **AI Practical Severity Assessment (Qwen 2.5)**: Evaluates real-world offensive impact (RCE vs DoS) using local Ollama.
3. **100-Point Scoring Engine**:
   - Active Weaponization (CISA KEV): **40 pts**
   - AI Practical Severity: **40 pts**
   - Public PoC Availability: **20 pts**
4. **CVSS Anomaly Discrepancy Gate**: Flags any item where `|AI_Severity - CVSS| >= 4.0` for automated diagnosis of inflated Day-0 ratings or underestimated flaws.

### 4b. Clean & Chunk Staged Envelopes (Task 2.2)
```bash
python Backend/run_chunking.py            # writes Backend/data/staging/latest_chunks.json
python Backend/run_chunking.py --show 2   # also print the first 2 chunks of each item
```
- `Raw_Content` is never modified; a cleaned copy is chunked (HTML boilerplate, tracking tags, front-matter and badges removed; fenced code kept verbatim).
- **Tier 1** (Executive Summary, <= 2,500 chars): prose. **Tier 2** (Technical PoC / Evidence, <= 5,000 chars): code blocks, commands, reproduction steps. Oversize content is split at logical boundaries and flagged (`oversize_split`), never truncated.
- Every chunk carries `Item_ID`, `CVE_ID`, `Source_URL`, `Source_Type`, heading path and a deterministic `Chunk_ID`/`Point_ID`.
- Pass `evidence_texts(chunks, item_id)` as the `evidence` argument of `VerificationGate.verify()`; chunk text is entity-decoded, so correct commands that are HTML-encoded in `Raw_Content` are not flagged.
- Embedding and Qdrant indexing are Task 2.3 (not part of this step).

### 5. Run Task 4.1 Ground-Truth Benchmark & Validation Suite
Execute empirical validation across the 20-sample ground-truth Web & Mobile dataset:
```bash
python Backend/run_benchmark.py
```
This computes and reports:
- **Fact Extraction Precision (FEP %)** (Target $\ge 95.0\%$, Observed: **100.0%**)
- **Hallucination Rate (HR %)** (Target $\le 5.0\%$, Observed: **0.0%**)
- **Scope Pre-Filter Accuracy** (Observed: **100.0%**)
- **CVSS Discrepancy Gate Accuracy** (100% anomaly alert trigger on real-world Day-0 gaps)

### 6. Launch Executive Threat Intelligence & Newsletter Hub (Primary Delivery Channel)
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
- **Primary Delivery Channel (Web Dashboard)**: The authoritative home for weekly newsletter digests, 100-point priority rankings, interactive Chart.js analytics, and raw envelope verification.
- **Secondary Delivery Channel (Telegram Bot)**: Optional, opt-in push notifications for critical zero-days (`priority_score >= 70` or CISA KEV active weaponizations). Configurable live or in simulation mode via the **Channel Config** tab in the dashboard.

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

### 7. Run Test Suite
Verify all collector parsers, pre-filters, AI scoring, anomaly detection gates, verification gates, REST API endpoints, link validation, and channel dispatchers (53 automated tests):
```bash
python -m unittest discover -s Testing -p "test_*.py" -v
```

### 8. Presentation & Demo Guide
For full presentation instructions, talking points, and cheat-sheet commands for project reviews, see:
[`DEMO_GUIDE.md`](DEMO_GUIDE.md)
