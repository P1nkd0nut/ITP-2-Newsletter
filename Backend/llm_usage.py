"""
LLM usage and cost log (plan Task 4.1: "LLM cost per run").

Every OpenRouter call appends one line to llm_usage.jsonl with the stage, model,
token counts and the cost OpenRouter reports (usage.cost, in USD credits).
run_pipeline.py adds up the lines written during a run. Logging never breaks a
call: any problem writing the file is ignored.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from Backend.config import STAGING_DIR

USAGE_FILE = STAGING_DIR / "llm_usage.jsonl"

# Add to an OpenRouter request body so the response carries usage.cost
OPENROUTER_USAGE_FIELD = {"usage": {"include": True}}


def record(stage: str, model: str, response_json: Dict[str, Any], path: Path = USAGE_FILE) -> None:
    try:
        usage = response_json.get("usage")
        if not isinstance(usage, dict) or not usage:
            return  # no usage block (e.g. a mocked response in tests): nothing to log
        line = {
            "at": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "model": model,
            "prompt_tokens": int(usage.get("prompt_tokens") or 0),
            "completion_tokens": int(usage.get("completion_tokens") or 0),
            "cost_usd": float(usage.get("cost") or 0.0),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
    except Exception:
        pass


def totals(since: Optional[datetime] = None, path: Path = USAGE_FILE) -> Dict[str, Dict[str, float]]:
    """Per-stage totals of calls, tokens and cost for lines written at or after `since`."""
    out: Dict[str, Dict[str, float]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for raw in lines:
        try:
            line = json.loads(raw)
            if since and datetime.fromisoformat(line["at"]) < since:
                continue
        except (ValueError, KeyError):
            continue
        t = out.setdefault(line.get("stage", "?"), {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0})
        t["calls"] += 1
        t["prompt_tokens"] += line.get("prompt_tokens", 0)
        t["completion_tokens"] += line.get("completion_tokens", 0)
        t["cost_usd"] += line.get("cost_usd", 0.0)
    return out
