"""
GroundedCVE full pipeline runner (used by the Docker scheduler).

Runs every stage in order:
  ingest -> triage -> chunk -> index (Qdrant) -> summarise + gate -> weekly Telegram digest

A failed stage is reported and the run carries on with the data already on disk,
so one flaky feed never stops the newsletter. The Telegram digest is sent at most
once every DIGEST_INTERVAL_DAYS, and only when TELEGRAM_BOT_TOKEN and
TELEGRAM_CHAT_ID are set.

Settings (all optional, from .env):
  INGEST_LIMIT              items per source per run          (default 5)
  SUMMARY_TOP               cards to write per run            (default 10)
  SUMMARY_OLLAMA_MODEL      local model to use if OPENROUTER_API_KEY is empty
  PIPELINE_INTERVAL_HOURS   hours between runs with --loop    (default 24)
  DIGEST_INTERVAL_DAYS      days between Telegram digests     (default 7)

Usage:
    python Backend/run_pipeline.py            # one run
    python Backend/run_pipeline.py --loop     # run forever (Docker scheduler)
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import OPENROUTER_API_KEY, STAGING_DIR

DIGEST_STATE_FILE = STAGING_DIR / "last_digest_sent.json"


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def run_stage(name: str, script: str, *args: str) -> bool:
    print(f"\n=== {name} ===", flush=True)
    cmd = [sys.executable, str(ROOT_DIR / "Backend" / script), *args]
    code = subprocess.run(cmd, cwd=ROOT_DIR).returncode
    if code != 0:
        print(f"[!] {name} exited with code {code}; continuing with existing data", flush=True)
    return code == 0


def last_digest_sent(path: Path = DIGEST_STATE_FILE) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(json.loads(path.read_text(encoding="utf-8"))["sent_at"])
    except (OSError, ValueError, KeyError):
        return None


def digest_due(now: datetime, interval_days: int, path: Path = DIGEST_STATE_FILE) -> bool:
    last = last_digest_sent(path)
    return last is None or now - last >= timedelta(days=interval_days)


def run_once() -> None:
    started = datetime.now(timezone.utc)
    print(f"GroundedCVE pipeline run started {started.isoformat()}", flush=True)

    run_stage("Ingestion", "run_ingestion.py", "--poc", "--limit", str(env_int("INGEST_LIMIT", 5)))
    run_stage("Triage", "run_triage.py")
    run_stage("Chunking", "run_chunking.py")
    run_stage("Indexing", "run_indexing.py")

    summary_args: List[str] = ["--top", str(env_int("SUMMARY_TOP", 10))]
    ollama_model = os.getenv("SUMMARY_OLLAMA_MODEL", "").strip()
    if OPENROUTER_API_KEY or ollama_model:
        if not OPENROUTER_API_KEY:
            summary_args += ["--ollama-model", ollama_model]
        run_stage("Grounded summaries", "run_summarise.py", *summary_args)
    else:
        print("\n=== Grounded summaries ===\n[!] Skipped: set OPENROUTER_API_KEY in .env. "
              "Without summaries nothing passes the gate, so the digest stays empty.", flush=True)

    interval = env_int("DIGEST_INTERVAL_DAYS", 7)
    if not (os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID")):
        print("\n=== Telegram digest ===\nSkipped: TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set.", flush=True)
    elif not digest_due(started, interval):
        print(f"\n=== Telegram digest ===\nNot due yet (last sent {last_digest_sent().isoformat()}).", flush=True)
    elif run_stage("Telegram digest", "run_telegram_digest.py", "--yes", "--days", str(interval)):
        DIGEST_STATE_FILE.write_text(json.dumps({"sent_at": started.isoformat()}), encoding="utf-8")

    print(f"\nRun finished in {(datetime.now(timezone.utc) - started).seconds}s", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the whole GroundedCVE pipeline")
    ap.add_argument("--loop", action="store_true", help="repeat every PIPELINE_INTERVAL_HOURS")
    args = ap.parse_args()

    while True:
        run_once()
        if not args.loop:
            return
        hours = env_int("PIPELINE_INTERVAL_HOURS", 24)
        print(f"Sleeping {hours}h until the next run", flush=True)
        time.sleep(hours * 3600)


if __name__ == "__main__":
    main()
