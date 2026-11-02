"""
Search Retrieval Evaluation (Task 2.3 / Task 4.1 retrieval quality).

Compares keyword-only (BM25), meaning-only (nomic-embed-text) and hybrid (RRF)
search. The 20 ground-truth Web and Mobile advisories (Backend/data/ground_truth_20.json)
are mixed in with every real item in latest_envelopes.json as distractors, then
searched with the 20 labelled QUERIES below
(exact CVE IDs, product/technique names, and plain-English descriptions that
share few words with the advisory).

Reports recall@1, recall@3 and MRR per search mode, and recall@3 per query type.
Meaning search needs Ollama with nomic-embed-text; without it only keyword
results are reported. Qdrant runs in-process, so the Qdrant container isn't needed.

Usage:
    python Backend/run_search_eval.py                              # keyword only, no Docker
    docker compose exec app python Backend/run_search_eval.py      # all three modes
"""
import hashlib
import json
import sys
import tempfile
import uuid
import warnings
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from qdrant_client import QdrantClient
from rich.console import Console
from rich.table import Table

from Backend.config import DATA_DIR, EMBED_MODEL
from Backend.search_engine import ENVELOPES_FILE, HybridSearcher, _plain_text, RAW_DOC_MAX_CHARS
from Backend.storage.embedder import OllamaEmbedder
from Backend.storage.indexer import index_chunks

GROUND_TRUTH_FILE = DATA_DIR / "ground_truth_20.json"
COLLECTION = "search_eval"

# 20 labelled questions, each with the one ground-truth advisory that answers it
QUERIES = [
    {"query": "CVE-2024-3400", "relevant": "GT-WEB-06", "type": "exact ID"},
    {"query": "CVE-2023-4966", "relevant": "GT-WEB-01", "type": "exact ID"},
    {"query": "CVE-2024-0044", "relevant": "GT-MOB-01", "type": "exact ID"},
    {"query": "CVE-2023-46604", "relevant": "GT-WEB-07", "type": "exact ID"},
    {"query": "MOVEit SQL injection", "relevant": "GT-WEB-03", "type": "product / technique"},
    {"query": "TeamCity authentication bypass", "relevant": "GT-WEB-05", "type": "product / technique"},
    {"query": "GlobalProtect command injection", "relevant": "GT-WEB-06", "type": "product / technique"},
    {"query": "binder use-after-free", "relevant": "GT-MOB-07", "type": "product / technique"},
    {"query": "WebKit type confusion", "relevant": "GT-MOB-06", "type": "product / technique"},
    {"query": "PassKit malicious attachment", "relevant": "GT-MOB-10", "type": "product / technique"},
    {"query": "steal login sessions from a VPN appliance and skip two-factor", "relevant": "GT-WEB-01", "type": "plain-English description"},
    {"query": "attacker creates a new administrator on a team wiki without logging in", "relevant": "GT-WEB-02", "type": "plain-English description"},
    {"query": "zero-click attack through a picture sent in a message", "relevant": "GT-MOB-03", "type": "plain-English description"},
    {"query": "forged single sign-on response lets someone log in as any user", "relevant": "GT-WEB-08", "type": "plain-English description"},
    {"query": "message queue server runs attacker commands after unsafe object loading", "relevant": "GT-WEB-07", "type": "plain-English description"},
    {"query": "take over a phone over a wireless short-range connection with no user interaction", "relevant": "GT-MOB-09", "type": "plain-English description"},
    {"query": "break out of the browser sandbox on iPhone", "relevant": "GT-MOB-08", "type": "plain-English description"},
    {"query": "app opens hidden system settings screens it should not have access to", "relevant": "GT-MOB-05", "type": "plain-English description"},
    {"query": "undocumented chip registers used to defeat kernel memory protection on iPhone", "relevant": "GT-MOB-02", "type": "plain-English description"},
    {"query": "remote support software setup page lets an outsider become admin", "relevant": "GT-WEB-10", "type": "plain-English description"},
]
console = Console()


def _chunk(item_id, title, text, url, cve_id, source_type):
    return {
        "Chunk_ID": f"{item_id}-0", "Item_ID": item_id, "Tier": 1, "Chunk_Index": 0,
        "Text": text, "Title": title, "Source_URL": url, "CVE_ID": cve_id, "Source_Type": source_type,
        "Chunk_Hash": hashlib.sha256(text.encode()).hexdigest(),
        "Point_ID": str(uuid.UUID(hashlib.md5(item_id.encode()).hexdigest())),
    }


def build_corpus():
    """Ground-truth advisories plus every real ingested item as distractors, one chunk each."""
    gt = json.loads(GROUND_TRUTH_FILE.read_text(encoding="utf-8"))
    chunks = [_chunk(i["id"], i["title"], i["raw_content"], i["official_url"], i["cve_id"], i["platform"]) for i in gt]
    gt_cves = {i["cve_id"] for i in gt}
    distractors = 0
    if ENVELOPES_FILE.exists():
        for e in json.loads(ENVELOPES_FILE.read_text(encoding="utf-8")):
            if e.get("CVE_ID") in gt_cves:
                continue  # the same CVE would count as a "wrong" answer
            text = _plain_text(e.get("Raw_Content") or "")[:RAW_DOC_MAX_CHARS]
            if text:
                chunks.append(_chunk(e["Item_ID"], e.get("Title") or "", text, e.get("Source_URL") or "",
                                     e.get("CVE_ID"), str(e.get("Source_Type") or "")))
                distractors += 1
    return chunks, len(gt), distractors


def evaluate(searcher, queries, mode, k=3):
    hits1 = hits_k = 0
    rr_total = 0.0
    by_type = {}
    for q in queries:
        ranked = [r["item_id"] for r in searcher.search(q["query"], limit=20, mode=mode)["results"]]
        rank = ranked.index(q["relevant"]) + 1 if q["relevant"] in ranked else None
        hits1 += rank == 1
        hit = rank is not None and rank <= k
        hits_k += hit
        rr_total += 1 / rank if rank else 0.0
        t = by_type.setdefault(q["type"], [0, 0])
        t[0] += hit
        t[1] += 1
    n = len(queries)
    return {"r1": hits1 / n, "rk": hits_k / n, "mrr": rr_total / n, "by_type": by_type}


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    queries = QUERIES
    chunks, n_gt, n_distractors = build_corpus()
    warnings.filterwarnings("ignore", message="Payload indexes have no effect")

    with tempfile.TemporaryDirectory() as tmp:
        chunks_file = Path(tmp) / "chunks.json"
        chunks_file.write_text(json.dumps(chunks), encoding="utf-8")
        missing = Path(tmp) / "none.json"

        client, embedder = QdrantClient(":memory:"), OllamaEmbedder(timeout=60)
        try:
            index_chunks(chunks, client, embedder, collection=COLLECTION)
            modes = ["keyword", "semantic", "hybrid"]
        except Exception as e:
            console.print(f"[yellow]Meaning search skipped: Ollama/{EMBED_MODEL} not reachable ({type(e).__name__}).\n"
                          f"Ollama is only reachable from inside Docker, so run:\n"
                          f"  docker compose up -d\n"
                          f"  docker compose exec app python Backend/run_search_eval.py[/yellow]\n")
            client = embedder = None
            modes = ["keyword"]

        searcher = HybridSearcher(client=client, embedder=embedder, collection=COLLECTION,
                                  chunks_file=chunks_file, envelopes_file=missing, triaged_file=missing)
        results = {m: evaluate(searcher, queries, m) for m in modes}

    names = {"keyword": "Keyword only (BM25)", "semantic": "Meaning only (nomic-embed-text)", "hybrid": "Hybrid (RRF, k=60)"}
    table = Table(title=f"[bold]Search quality: {len(queries)} queries, {n_gt} target advisories "
                        f"hidden among {n_distractors} real items[/bold]")
    table.add_column("Search mode", style="cyan")
    table.add_column("Right answer #1", justify="right")
    table.add_column("Right answer in top 3", justify="right")
    table.add_column("MRR", justify="right")
    for m in modes:
        r = results[m]
        table.add_row(names[m], f"{r['r1']:.0%}", f"{r['rk']:.0%}", f"{r['mrr']:.2f}",
                      style="bold" if m == "hybrid" else None)
    console.print(table)

    types = list(results[modes[0]]["by_type"])
    by_type = Table(title="[bold]Right answer in top 3, by kind of query[/bold]")
    by_type.add_column("Kind of query", style="cyan")
    for m in modes:
        by_type.add_column(names[m].split(" (")[0], justify="right")
    for t in types:
        by_type.add_row(t, *[f"{results[m]['by_type'][t][0]}/{results[m]['by_type'][t][1]}" for m in modes])
    console.print(by_type)
    console.print("[dim]MRR = mean reciprocal rank: 1.0 means the right answer is always first, 0.5 means second on average.[/dim]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
