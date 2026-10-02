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
│   ├── data/
│   │   └── staging/
│   │       └── latest_envelopes.json          # Persisted raw staging envelopes
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
│   └── storage/
│       ├── vector_db.py                       # Qdrant client helper
│       └── init_qdrant.py                     # Creates the Qdrant collections (Task 2.1)
├── Frontend/
│   ├── index.html                             # Cyber-themed interactive dashboard
│   ├── data.js                                # Auto-synced envelopes data for instant loading
│   └── run_dashboard.py                       # 1-command local dashboard server
├── Testing/
│   └── test_ingestion.py                      # Automated test suite (10 unit & integration tests)
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

### 4. Launch Frontend Dashboard
Start the visual threat intelligence viewer:
```bash
python Frontend/run_dashboard.py
```
*(Automatically opens `http://localhost:8080/index.html` in your browser).*

### 5. Run Test Suite
Verify all collector parsers, schema constraints, and hash calculations:
```bash
python -m unittest discover -s Testing -p "test_*.py" -v
```
