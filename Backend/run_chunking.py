"""
GroundedCVE Chunking CLI (Task 2.2).

Reads staged envelopes, cleans them, applies two-tier heading-aware chunking and
writes Backend/data/staging/latest_chunks.json. Embedding and Qdrant indexing are
Task 2.3 and are not performed here.

Usage:
    python Backend/run_chunking.py
    python Backend/run_chunking.py --show 2
    python Backend/run_chunking.py --input path/to/envelopes.json --output path/to/chunks.json
"""
import argparse
import json
import sys
from pathlib import Path

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import (
    CHUNK_TIER1_MAX_CHARS,
    CHUNK_TIER2_MAX_CHARS,
    CHUNKS_FILE,
    STAGING_DIR,
)
from Backend.chunking import chunk_envelope, clean_content

try:
    from rich.console import Console
    from rich.table import Table
    HAVE_RICH = True
except ImportError:  # keep the CLI usable without rich
    HAVE_RICH = False


def load_envelopes(path: Path) -> list:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["envelopes"] if isinstance(data, dict) and "envelopes" in data else data


def main() -> int:
    ap = argparse.ArgumentParser(description="GroundedCVE two-tier chunking (Task 2.2)")
    ap.add_argument("--input", type=Path, default=STAGING_DIR / "latest_envelopes.json")
    ap.add_argument("--output", type=Path, default=CHUNKS_FILE)
    ap.add_argument("--show", type=int, default=0, metavar="N", help="print the first N chunks per item")
    args = ap.parse_args()

    if not args.input.exists():
        print(f"Input not found: {args.input}. Run Backend/run_ingestion.py first.")
        return 2

    envelopes = load_envelopes(args.input)
    all_chunks, rows = [], []
    for env in envelopes:
        chunks = chunk_envelope(env)
        cleaned, fmt = clean_content(str(env.get("Source_Type")), env.get("Raw_Content", ""))
        t1 = [c for c in chunks if c.Tier == 1]
        t2 = [c for c in chunks if c.Tier == 2]
        flags = sorted({f for c in chunks for f in c.Flags})
        rows.append((env["Item_ID"], env["Source_Type"], fmt, len(env.get("Raw_Content", "")),
                     len(cleaned), len(t1), len(t2),
                     max((c.Char_Count for c in t1), default=0), max((c.Char_Count for c in t2), default=0),
                     ",".join(flags)))
        all_chunks.extend(chunks)
        if args.show:
            for c in chunks[: args.show]:
                print(f"\n--- {c.Chunk_ID} | tier {c.Tier} | {c.Char_Count} chars | {c.Heading_Path}\n{c.Text[:600]}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps([c.to_dict() for c in all_chunks], indent=2, ensure_ascii=False),
                           encoding="utf-8")

    violations = [c for c in all_chunks
                  if c.Char_Count > (CHUNK_TIER1_MAX_CHARS if c.Tier == 1 else CHUNK_TIER2_MAX_CHARS)]
    headers = ["Item_ID", "Source", "Format", "Raw", "Clean", "T1", "T2", "Max T1", "Max T2", "Flags"]
    if HAVE_RICH:
        table = Table(title="GroundedCVE chunking (Task 2.2)")
        for h in headers:
            table.add_column(h, overflow="fold")
        for r in rows:
            table.add_row(*[str(x) for x in r])
        Console().print(table)
    else:
        print("\t".join(headers))
        for r in rows:
            print("\t".join(str(x) for x in r))

    print(f"\n{len(envelopes)} envelopes -> {len(all_chunks)} chunks "
          f"(T1 {sum(c.Tier == 1 for c in all_chunks)}, T2 {sum(c.Tier == 2 for c in all_chunks)}); "
          f"cap violations: {len(violations)}; written to {args.output}")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
