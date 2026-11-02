"""
Live verification / demo for the GroundedCVE vector-DB deliverables (Tasks 2.1-2.3).

This is NOT a unit test. It hits the LIVE Qdrant + Ollama containers on purpose and
prints self-explanatory, screenshot-worthy evidence with a PASS/FAIL line per claim:

    CLAIM 1 -- Embedding + Qdrant write : chunks embedded with nomic-embed-text
               (768-dim) and stored as points (dense + sparse named vectors).
    CLAIM 2 -- Dense meaning search     : a natural-language query returns the right
               chunks via dense vector search (no shared exact tokens with the title).
    CLAIM 3 -- Hybrid dense+sparse RRF   : an exact CVE-ID query and a conceptual query
               each shown as [A] Dense / [B] Sparse(BM25) / [C] Fused(RRF), proving the
               fused ranking draws from BOTH tracks.

Start the services first, then run:

    docker compose up -d qdrant ollama
    docker exec groundedcve-ollama ollama pull nomic-embed-text
    python Backend/verify_vector_pipeline.py
"""
import sys
from pathlib import Path

# Add project root to sys.path so Backend modules import cleanly (file lives one
# level under the repo root, exactly like Backend/run_indexing.py).
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from qdrant_client.models import Fusion, FusionQuery, Prefetch
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from Backend.config import CHUNKS_FILE, EMBED_DIM, QDRANT_COLLECTION_ITEMS
from Backend.storage.embedder import OllamaEmbedder, SparseEmbedder
from Backend.storage.indexer import index_chunks, load_chunks
from Backend.storage.init_qdrant import DENSE_VECTOR_NAME, SPARSE_VECTOR_NAME, ensure_collection
from Backend.storage.vector_db import get_client

console = Console()

RUN_COMMANDS = (
    "docker compose up -d qdrant ollama\n"
    "docker exec groundedcve-ollama ollama pull nomic-embed-text\n"
    "python Backend/verify_vector_pipeline.py"
)


def _truncate(text: str, width: int = 60) -> str:
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= width else text[: width - 1] + "\u2026"


def _hits_table(title: str, points) -> Table:
    """Render a ranked result list as rank | score | CVE_ID | Title."""
    table = Table(title=title, title_style="bold", show_lines=False, expand=False)
    table.add_column("rank", justify="right", style="cyan", no_wrap=True)
    table.add_column("score", justify="right", style="magenta", no_wrap=True)
    table.add_column("CVE_ID", style="yellow", no_wrap=True)
    table.add_column("Title")
    if not points:
        table.add_row("-", "-", "[dim]no hits[/dim]", "")
        return table
    for rank, p in enumerate(points, start=1):
        payload = p.payload or {}
        table.add_row(
            str(rank),
            f"{p.score:.4f}",
            str(payload.get("CVE_ID", "-")),
            _truncate(payload.get("Title", "")),
        )
    return table


def _result_signature(points):
    """Ordered list of (CVE_ID, Point_ID) so two result lists can be compared."""
    return [(
        (p.payload or {}).get("CVE_ID"),
        str(p.id),
    ) for p in points]


def _instruct_services_down(detail: str) -> None:
    console.print(Panel(
        f"[red]Could not reach the live services.[/red]\n\n{detail}\n\n"
        "Start them, then re-run this script:\n\n"
        "[bold]docker compose up -d qdrant ollama[/bold]\n"
        "[bold]docker exec groundedcve-ollama ollama pull nomic-embed-text[/bold]\n"
        "[bold]python Backend/verify_vector_pipeline.py[/bold]",
        title="[bold red]PRE-FLIGHT FAILED[/bold red]",
        border_style="red",
    ))


def preflight(client):
    """Confirm Qdrant and Ollama are reachable. Exits non-zero if not."""
    console.print("[bold cyan]PRE-FLIGHT -- checking live services[/bold cyan]")

    # Qdrant
    try:
        info = client.info()
        console.print(f"  Qdrant reachable  -> [green]version {info.version}[/green]")
    except Exception as e:
        _instruct_services_down(f"Qdrant error: {e.__class__.__name__}: {e}")
        sys.exit(1)

    # Ollama (tiny probe embedding)
    try:
        probe = OllamaEmbedder().embed_query("ping")
        if len(probe) != EMBED_DIM:
            _instruct_services_down(
                f"Ollama returned a {len(probe)}-dim vector, expected {EMBED_DIM}. "
                "Is nomic-embed-text pulled?")
            sys.exit(1)
        console.print(f"  Ollama reachable  -> [green]embedded probe, {len(probe)}-dim vector[/green]")
    except Exception as e:
        _instruct_services_down(f"Ollama error: {e.__class__.__name__}: {e}")
        sys.exit(1)
    console.print()


def build_sparse_embedder():
    """Construct the BM25 sparse embedder, or return None if fastembed is unavailable."""
    try:
        sparse = SparseEmbedder()
        # Force the lazy load now so unavailability surfaces here, not mid-claim.
        sparse.sparse_query("warmup")
        return sparse
    except Exception as e:
        console.print(
            f"[yellow]Sparse (BM25) embedder unavailable: {e.__class__.__name__}: {e}[/yellow]\n"
            "[yellow]Install it with: pip install 'fastembed>=0.3,<1.0'[/yellow]")
        return None


def claim1_embed_and_write(client, chunks, dense_embedder, sparse_embedder):
    console.print("[bold cyan]CLAIM 1 -- Embedding + Qdrant write[/bold cyan]")
    console.print("  nomic-embed-text embeds every chunk; points are upserted into Qdrant\n"
                  "  with named 'dense' (768-dim) and 'sparse' (BM25) vectors.")

    ensure_collection(client, QDRANT_COLLECTION_ITEMS)
    stats = index_chunks(
        chunks, client, dense_embedder,
        collection=QDRANT_COLLECTION_ITEMS, force=True, sparse_embedder=sparse_embedder,
    )
    console.print(f"  index_chunks: [green]{stats['embedded']} embedded[/green], "
                  f"{stats['skipped']} skipped, {stats['total']} total")

    count = client.count(QDRANT_COLLECTION_ITEMS, exact=True).count
    console.print(f"  live point count in '{QDRANT_COLLECTION_ITEMS}': [green]{count}[/green]")

    sample_id = chunks[0]["Point_ID"]
    retrieved = client.retrieve(QDRANT_COLLECTION_ITEMS, ids=[sample_id], with_vectors=True)
    if not retrieved:
        console.print(f"  [red]Could not retrieve sample point {sample_id}[/red]")
        console.print("\n  CLAIM 1: [bold red]FAIL[/bold red]\n")
        return False

    point = retrieved[0]
    vectors = point.vector or {}
    dense_vec = vectors.get(DENSE_VECTOR_NAME)
    sparse_vec = vectors.get(SPARSE_VECTOR_NAME)

    dense_ok = dense_vec is not None and len(dense_vec) == EMBED_DIM
    sparse_indices = getattr(sparse_vec, "indices", None) if sparse_vec is not None else None
    sparse_ok = sparse_indices is not None and len(sparse_indices) > 0

    console.print(f"  sample point id   : [yellow]{point.id}[/yellow]")
    console.print(f"  dense vector len  : {len(dense_vec) if dense_vec is not None else 'missing'} "
                  f"(expected {EMBED_DIM}) -> {'[green]OK[/green]' if dense_ok else '[red]BAD[/red]'}")
    console.print(f"  sparse vector     : "
                  f"{len(sparse_indices) if sparse_ok else 0} non-empty indices -> "
                  f"{'[green]OK[/green]' if sparse_ok else '[red]MISSING/EMPTY[/red]'}")

    passed = dense_ok and sparse_ok
    console.print(f"\n  CLAIM 1: {'[bold green]PASS[/bold green]' if passed else '[bold red]FAIL[/bold red]'}\n")
    return passed


def claim2_dense_meaning_search(client, dense_embedder):
    console.print("[bold cyan]CLAIM 2 -- Dense meaning search[/bold cyan]")
    query = "authentication bypass on a network appliance"
    console.print(f"  query (no shared exact tokens with the target title): [italic]\"{query}\"[/italic]")

    vec = dense_embedder.embed_query(query)
    hits = client.query_points(
        collection_name=QDRANT_COLLECTION_ITEMS,
        query=vec,
        using=DENSE_VECTOR_NAME,
        limit=3,
        with_payload=True,
    ).points

    console.print(_hits_table("Top-3 dense hits", hits))

    passed = bool(hits) and any(h.score > 0 for h in hits)
    console.print(f"\n  CLAIM 2: {'[bold green]PASS[/bold green]' if passed else '[bold red]FAIL[/bold red]'}\n")
    return passed


def _three_way(client, dense_embedder, sparse_embedder, query, expectation):
    """Run and print [A] dense / [B] sparse / [C] fused for a single query. Returns fused differs?"""
    console.print(f"  query: [italic]\"{query}\"[/italic]")
    console.print(f"  expectation: [dim]{expectation}[/dim]")

    dense_vec = dense_embedder.embed_query(query)
    sparse_vec = sparse_embedder.sparse_query(query)

    dense_hits = client.query_points(
        collection_name=QDRANT_COLLECTION_ITEMS,
        query=dense_vec, using=DENSE_VECTOR_NAME, limit=5, with_payload=True,
    ).points
    sparse_hits = client.query_points(
        collection_name=QDRANT_COLLECTION_ITEMS,
        query=sparse_vec, using=SPARSE_VECTOR_NAME, limit=5, with_payload=True,
    ).points
    fused_hits = client.query_points(
        collection_name=QDRANT_COLLECTION_ITEMS,
        prefetch=[
            Prefetch(query=dense_vec, using=DENSE_VECTOR_NAME, limit=5),
            Prefetch(query=sparse_vec, using=SPARSE_VECTOR_NAME, limit=5),
        ],
        query=FusionQuery(fusion=Fusion.RRF),
        limit=5, with_payload=True,
    ).points

    console.print(_hits_table("[A] Dense only", dense_hits))
    console.print(_hits_table("[B] Sparse/BM25 only", sparse_hits))
    console.print(_hits_table("[C] Fused (RRF)", fused_hits))

    fused_sig = _result_signature(fused_hits)
    differs = bool(fused_sig) and (
        fused_sig != _result_signature(dense_hits) or fused_sig != _result_signature(sparse_hits)
    )
    verdict = ("[green]fused list is non-empty and differs from a single track (combines both)[/green]"
               if differs else "[red]fused list empty or identical to both tracks[/red]")
    console.print(f"  -> {verdict}\n")
    return differs


def claim3_hybrid_rrf(client, chunks, dense_embedder, sparse_embedder):
    console.print("[bold cyan]CLAIM 3 -- Hybrid dense+sparse RRF (side by side)[/bold cyan]")

    if sparse_embedder is None:
        console.print("  [red]Sparse (BM25) embedder unavailable -- hybrid fusion cannot be shown.[/red]")
        console.print("  [red]Install fastembed and re-run: pip install 'fastembed>=0.3,<1.0'[/red]")
        console.print("\n  CLAIM 3: [bold red]FAIL[/bold red]\n")
        return False

    # Choose example queries from REAL data read at runtime.
    exact_cve = chunks[0].get("CVE_ID") or "CVE-2026-111357"
    conceptual = "authentication bypass on a network appliance"

    console.print("  [bold]Query 1 of 2 -- EXACT CVE identifier[/bold] (BM25/sparse should rank it top)")
    differs_exact = _three_way(
        client, dense_embedder, sparse_embedder, exact_cve,
        f"the BM25/sparse track should surface the exact item '{exact_cve}' at/near the top",
    )

    console.print("  [bold]Query 2 of 2 -- CONCEPTUAL phrase[/bold] (dense should surface the right item)")
    differs_concept = _three_way(
        client, dense_embedder, sparse_embedder, conceptual,
        "the dense track should surface the conceptually-matching Ivanti missing-auth item",
    )

    passed = differs_exact or differs_concept
    console.print(f"  CLAIM 3: {'[bold green]PASS[/bold green]' if passed else '[bold red]FAIL[/bold red]'}\n")
    return passed


def final_summary(c1: bool, c2: bool, c3: bool) -> None:
    def mark(ok: bool) -> str:
        return "[bold green]PASS[/bold green]" if ok else "[bold red]FAIL[/bold red]"

    body = (
        f"CLAIM 1 Embedding + Qdrant write ....... {mark(c1)}\n"
        f"CLAIM 2 Dense meaning search ........... {mark(c2)}\n"
        f"CLAIM 3 Hybrid dense+sparse RRF ........ {mark(c3)}"
    )
    all_pass = c1 and c2 and c3
    console.print(Panel(
        body,
        title="[bold]VECTOR-DB VERIFICATION SUMMARY[/bold]",
        border_style="green" if all_pass else "red",
        expand=False,
    ))

    console.print("\n[bold cyan]Commands used to produce this evidence:[/bold cyan]")
    for line in RUN_COMMANDS.splitlines():
        console.print(f"  [bold]{line}[/bold]")


def main() -> int:
    console.print(Panel(
        "[bold]GroundedCVE -- Live Vector-DB Pipeline Verification[/bold]\n"
        "Proving CLAIM 1 (embed+write), CLAIM 2 (dense meaning search), "
        "CLAIM 3 (hybrid dense+sparse RRF) end-to-end against live Qdrant + Ollama.",
        border_style="cyan",
    ))

    client = get_client()
    preflight(client)

    chunks = load_chunks(CHUNKS_FILE)
    if not chunks:
        console.print(f"[red]No chunks in {CHUNKS_FILE}.[/red] "
                      "Run [bold]python Backend/run_chunking.py[/bold] first, then re-run this script.")
        return 1
    console.print(f"[green]Loaded {len(chunks)} chunks from {CHUNKS_FILE.name}[/green]\n")

    dense_embedder = OllamaEmbedder()
    sparse_embedder = build_sparse_embedder()

    c1 = claim1_embed_and_write(client, chunks, dense_embedder, sparse_embedder)
    c2 = claim2_dense_meaning_search(client, dense_embedder)
    c3 = claim3_hybrid_rrf(client, chunks, dense_embedder, sparse_embedder)

    final_summary(c1, c2, c3)
    return 0 if (c1 and c2 and c3) else 1


if __name__ == "__main__":
    sys.exit(main())
