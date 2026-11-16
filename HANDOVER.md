# GroundedCVE Handover Guide

For whoever runs or extends GroundedCVE after the team. The README covers the
architecture; this covers running it, changing it, and what to do when it breaks.

---

## 1. Setup and deployment

**Requirements:** Docker Desktop, an OpenRouter API key. Optional: a Telegram bot token, NVD and GitHub API keys (higher rate limits).

```bash
git clone https://github.com/P1nkd0nut/ITP-2-Newsletter.git
cd ITP-2-Newsletter
cp .env.example .env      # fill in the keys (see section 2)
docker compose up -d --build
```

| Container | Role |
|---|---|
| `app` | Dashboard and REST API on port 5000 |
| `scheduler` | Full pipeline at start, then daily at `PIPELINE_RUN_TIME`; Telegram digest every `DIGEST_INTERVAL_DAYS` |
| `qdrant` | Vector database, data in `qdrant_storage/` |
| `ollama` | `nomic-embed-text` embeddings, data in `ollama_data/` |

Run the pipeline once now: `docker compose run --rm scheduler python Backend/run_pipeline.py`.
Outside Docker: `pip install -r requirements.txt`, start Qdrant and Ollama yourself, then `python run_server.py` and `python Backend/run_pipeline.py`.

**Only one machine should run the scheduler with the Telegram token.** If several do, the pinned-edition guard (section 6) stops duplicate weekly digests, but each machine keeps its own record of sent items, so a later week can repeat items another machine already sent.

**Security.** The dashboard has no login and listens on all interfaces (`run_server.py`, `0.0.0.0:5000`). Anyone who can reach port 5000 can change the Telegram settings and make the bot post. Run it on a trusted network only, or put it behind a reverse proxy with authentication before exposing it.

---

## 2. Configuration

All settings live in `.env` (template: `.env.example`). Secrets never go in the repository.

| Setting | Default | What it does |
|---|---|---|
| `OPENROUTER_API_KEY` | (none) | Needed for AI triage and card writing. Without it, triage falls back to Ollama/heuristics and no cards are written |
| `OPENROUTER_MODEL` | `qwen/qwen-2.5-72b-instruct` | Model for triage and summaries |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | (none) | Weekly digest. Channel IDs start with `-100` |
| `BASE_URL` | `http://127.0.0.1:5000` | Where "Full details" links point. With 127.0.0.1/localhost, Telegram cards carry only public NVD/source/PoC links |
| `NVD_API_KEY`, `GITHUB_TOKEN` | (none) | Higher API rate limits |
| `INGEST_LIMIT` | 5 | Items per source per run |
| `SUMMARY_TOP` | 10 | Cards written per run |
| `PIPELINE_RUN_TIME`, `PIPELINE_TIMEZONE` | 08:00, Asia/Singapore | Daily run time |
| `DIGEST_INTERVAL_DAYS` | 7 | Days between digests |
| `NOVELTY_SIMILARITY` | blank | Override the tuned near-duplicate threshold (section 5) |

**Ranking weights** are in `Backend/triage/priority_scorer.py`, `_calculate_100pt_score`: CISA KEV 40, AI severity 40, public PoC 20. Items sharing a CVE ID are scored as one story (`group_by_cve`).

**Other thresholds:**
- CVSS vs AI anomaly: `DISCREPANCY_THRESHOLD = 4.0` in `priority_scorer.py`.
- Scope taxonomy (CWE list, Web/Mobile keywords): `Backend/triage/pre_filter.py`.
- Gate impact phrases and known vendor/product names: `IMPACT_TERMS`, `KNOWN_VENDOR_PRODUCTS` in `Backend/verification/gate.py`.
- Re-check schedule for older CVEs: `Backend/ingestion/recheck_policy.py`.

---

## 3. Reviewing quarantined items

Cards that fail the verification gate twice are never published. They are logged, one JSON object per line, in `Backend/data/staging/quarantine_log.jsonl` with each failing fact (`check`, `value`, `reason`). `status: ERROR` lines are generation failures (for example an OpenRouter 429), not gate failures.

```bash
python Backend/run_gate_report.py summary    # passed first try / after retry / quarantined / errors, failures by check
python Backend/run_gate_report.py recheck    # re-run today's gate over every published card
```

For each quarantined item, open its source (`Source_URL`) and decide:
1. **The model got a fact wrong.** Nothing to do; the gate worked. Note it for the gate-effectiveness figures.
2. **The fact is in the source but the gate missed it** (a false quarantine). Usually a formatting difference. Fix the matching in `gate.py`, add a test to `Testing/test_verification.py`, then `python Backend/run_summarise.py --force` to rewrite the card.
3. **Generation error.** Re-run `python Backend/run_summarise.py`; it retries items without a passed card.

**Manual review of published cards** (catches errors the gate can't, like an overstated impact):

```bash
python Backend/run_gate_report.py worksheet --size 15   # writes Backend/data/manual_checks/card_review_YYYYMMDD.csv
# fill reviewer_* columns with Y / N / NA in Excel
python Backend/run_gate_report.py score Backend/data/manual_checks/card_review_YYYYMMDD.csv
```

---

## 4. Adding a source

1. Add the feed URL to `Backend/config.py`.
2. Add a `SourceType` value in `Backend/ingestion/models.py`.
3. Write a collector in `Backend/ingestion/collectors/`, subclassing `BaseCollector` (`base.py`). `collect(limit)` returns `StagingEnvelope`s with at least `Item_ID`, `Source_Type`, `Title`, `Source_URL`, `Published_Date`, `Ingested_At`, `Content_Hash`, `Raw_Content`. Keep `Raw_Content` unmodified; the gate checks against it. For an RSS/Atom feed, reuse `rss_feeds.py` (see `create_portswigger_collector`).
4. Register it in `Backend/ingestion/pipeline.py` (`self.registry`) and export it from `collectors/__init__.py`.
5. Tell the scope filter which stream it belongs to: `Backend/triage/pre_filter.py`, the `SourceType` checks around the Web and Mobile source lists.
6. Add a parser test with a saved sample response to `Testing/test_ingestion.py` (don't depend on the live feed).
7. Check: `python Backend/run_ingestion.py --sources <name> --limit 3`.

---

## 5. Evaluations and how to re-run them

| What | Command | Output |
|---|---|---|
| Fact extraction (FEP %, HR %) on 20 ground-truth items | `python Backend/run_benchmark.py` | console |
| Gate fault injection (8 fault types) | `python Backend/run_gate_demo.py` | console |
| Gate on real cards | `python Backend/run_gate_report.py summary` / `recheck` | console |
| Retrieval recall@k (keyword / meaning / hybrid) | `python Backend/run_search_eval.py` | console |
| Novelty threshold | `python Backend/run_novelty_eval.py` | `Backend/data/novelty_threshold.json` |
| Per-stage latency and LLM cost | every pipeline run | `Run metrics` in the log, `Backend/data/staging/run_metrics.jsonl` |

**Novelty threshold.** `run_novelty_eval.py` embeds the labelled pairs in `Backend/data/novelty_pairs.json` with Ollama, picks the threshold on the `tune` half and reports suppression and false-suppression rates on the `heldout` half. It saves the threshold to `novelty_threshold.json`, which the digest uses unless `NOVELTY_SIMILARITY` is set. The pair labels are marked DRAFT until two team members confirm them; add more pairs from real digests over time.

---

## 6. Known limitations

- **The AI can under-rank an important item.** Accepted in the proposal. All items stay searchable in the dashboard and Qdrant.
- **The gate checks tokens, not meaning.** A false statement built only from words in the source passes. Manual review (section 3) measures this.
- **The vendor/product check only knows the names in `KNOWN_VENDOR_PRODUCTS`.** Other names aren't checked.
- **One scheduler per Telegram channel.** See section 1. The pinned-edition guard needs the bot to have the "Pin Messages" admin right, and reads only the latest pinned message.
- **No `/search` command or inline buttons in Telegram.** Search is in the dashboard (`/api/search`). Cards use HTML links rather than buttons.
- **NVD changes after publication** are picked up by the age-based re-check policy, not by polling `lastModStartDate`.
- **Research write-ups without a CVE ID use one card format** (the CVE card), not a separate Technique card.
- **No authentication on the dashboard/API** (section 1).

---

## 7. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Digest is empty | No cards passed the gate: check `OPENROUTER_API_KEY`, then `run_gate_report.py summary`. Or nothing in scope was published in the last `DIGEST_INTERVAL_DAYS` |
| "Edition … is already pinned … No update" | This week's digest was already posted (maybe by another PC). `--force` sends anyway |
| "Could not pin the header" | Give the bot the "Pin Messages" admin right in the channel |
| Telegram links not clickable | `BASE_URL` uses `localhost`; Telegram drops those. Use `127.0.0.1` or a real address |
| `OpenRouter returned 429` in the quarantine log | Rate limit. Re-run `run_summarise.py` later; it only retries items without a passed card |
| "Qdrant not reachable … reading chunks from latest_chunks.json" | Qdrant container is down: `docker compose up -d qdrant`. Summaries still work from the file |
| Search has no meaning results | Ollama or `nomic-embed-text` missing: `docker compose up -d ollama ollama-pull` |
| Live ingestion tests fail | They need internet. CI allows them to fail; the other tests must pass |
| Windows console shows `?` instead of emoji | Use Windows Terminal, or set `PYTHONIOENCODING=utf-8` |
