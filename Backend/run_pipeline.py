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
  NVD_LIMIT                 newest NVD CVEs per run, if more than INGEST_LIMIT (default: INGEST_LIMIT)
  SUMMARY_TOP               cards to write per run            (default 10)
  SUMMARY_OLLAMA_MODEL      local model to use if OPENROUTER_API_KEY is empty
  PIPELINE_RUN_TIME         daily run time with --loop, HH:MM  (default 08:00)
  PIPELINE_TIMEZONE         timezone for PIPELINE_RUN_TIME    (default Asia/Singapore)
  DIGEST_INTERVAL_DAYS      days between Telegram digests     (default 7)

Usage:
    python Backend/run_pipeline.py            # one run
    python Backend/run_pipeline.py --loop     # run now, then every day at PIPELINE_RUN_TIME (Docker scheduler)
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend import llm_usage
from Backend.config import OPENROUTER_API_KEY, STAGING_DIR

DIGEST_STATE_FILE = STAGING_DIR / "last_digest_sent.json"


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


# Per-stage timings of the current run (plan Task 4.1: per-stage and end-to-end latency)
STAGE_TIMES: List[Dict[str, Any]] = []
RUN_METRICS_FILE = STAGING_DIR / "run_metrics.jsonl"


def run_stage(name: str, script: str, *args: str) -> bool:
    print(f"\n=== {name} ===", flush=True)
    cmd = [sys.executable, str(ROOT_DIR / "Backend" / script), *args]
    t0 = time.monotonic()
    code = subprocess.run(cmd, cwd=ROOT_DIR).returncode
    STAGE_TIMES.append({"stage": name, "seconds": round(time.monotonic() - t0, 1), "ok": code == 0})
    if code != 0:
        print(f"[!] {name} exited with code {code}; continuing with existing data", flush=True)
    return code == 0


def report_run(started: datetime, finished: datetime, path: Path = RUN_METRICS_FILE) -> Dict[str, Any]:
    """Print and save this run's stage timings and LLM usage/cost."""
    usage = llm_usage.totals(since=started)
    metrics = {
        "started_at": started.isoformat(),
        "total_seconds": round((finished - started).total_seconds(), 1),
        "stages": list(STAGE_TIMES),
        "llm": usage,
        "llm_cost_usd": round(sum(u["cost_usd"] for u in usage.values()), 6),
    }
    print("\n=== Run metrics ===", flush=True)
    for st in STAGE_TIMES:
        print(f"  {st['stage']:<20} {st['seconds']:>8.1f}s  {'ok' if st['ok'] else 'FAILED'}", flush=True)
    for stage, u in usage.items():
        print(f"  LLM {stage:<16} {u['calls']:>4} calls  {u['prompt_tokens'] + u['completion_tokens']:>8} tokens  "
              f"${u['cost_usd']:.4f}", flush=True)
    print(f"  End to end           {metrics['total_seconds']:>8.1f}s  LLM cost ${metrics['llm_cost_usd']:.4f}", flush=True)
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(metrics) + "\n")
    except OSError:
        pass
    return metrics


def last_digest_sent(path: Path = DIGEST_STATE_FILE) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(json.loads(path.read_text(encoding="utf-8"))["sent_at"])
    except (OSError, ValueError, KeyError):
        return None


def digest_due(now: datetime, interval_days: int, path: Path = DIGEST_STATE_FILE) -> bool:
    last = last_digest_sent(path)
    # an hour of slack so a run that starts a few seconds early still counts as a week later
    return last is None or now - last >= timedelta(days=interval_days, hours=-1)


def next_run_at(now: datetime, run_time: str, tz_name: str) -> datetime:
    """Next occurrence of run_time ("HH:MM") in tz_name strictly after now."""
    tz = ZoneInfo(tz_name)
    hour, minute = (int(x) for x in run_time.split(":"))
    local_now = now.astimezone(tz)
    candidate = datetime.combine(local_now.date(), dtime(hour, minute), tzinfo=tz)
    if candidate <= local_now:
        candidate = datetime.combine(local_now.date() + timedelta(days=1), dtime(hour, minute), tzinfo=tz)
    return candidate


def run_once() -> None:
    started = datetime.now(timezone.utc)
    STAGE_TIMES.clear()
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

    # Check every reference before the digest, so dead links are swapped for archived copies or left out
    run_stage("Link check", "run_link_check.py")

    interval = env_int("DIGEST_INTERVAL_DAYS", 7)
    if not (os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID")):
        print("\n=== Telegram digest ===\nSkipped: TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set.", flush=True)
    elif not digest_due(started, interval):
        print(f"\n=== Telegram digest ===\nNot due yet (last sent {last_digest_sent().isoformat()}).", flush=True)
    # --jitter: teammates' schedulers all run at the same time, so stagger the check of the channel's pinned edition
    elif run_stage("Telegram digest", "run_telegram_digest.py", "--yes", "--days", str(interval), "--jitter", "300"):
        DIGEST_STATE_FILE.write_text(json.dumps({"sent_at": started.isoformat()}), encoding="utf-8")

    finished = datetime.now(timezone.utc)
    report_run(started, finished)
    print(f"\nRun finished in {(finished - started).seconds}s", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the whole GroundedCVE pipeline")
    ap.add_argument("--loop", action="store_true", help="run now, then every day at PIPELINE_RUN_TIME")
    args = ap.parse_args()
    run_time = os.getenv("PIPELINE_RUN_TIME", "08:00").strip() or "08:00"
    tz_name = os.getenv("PIPELINE_TIMEZONE", "Asia/Singapore").strip() or "Asia/Singapore"

    # Run straight away so a fresh install has data, then at the daily time
    while True:
        run_once()
        if not args.loop:
            return
        nxt = next_run_at(datetime.now(timezone.utc), run_time, tz_name)
        print(f"Next run at {nxt.isoformat()} ({tz_name})", flush=True)
        while (wait := (nxt - datetime.now(timezone.utc)).total_seconds()) > 0:
            time.sleep(min(wait, 3600))  # wake hourly so a sleeping laptop doesn't skip a day


if __name__ == "__main__":
    main()
