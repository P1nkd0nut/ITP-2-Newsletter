"""
GroundedCVE Indexing CLI (Task 2.3).

Embeds the chunks in Backend/data/staging/latest_chunks.json with Ollama
(nomic-embed-text) and upserts them into Qdrant. Needs both services running:

    docker compose up -d qdrant ollama
    docker exec groundedcve-ollama ollama pull nomic-embed-text

Usage:
    python Backend/run_indexing.py
    python Backend/run_indexing.py --force        # re-embed every chunk
"""
import argparse
import sys
from pathlib import Path

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from Backend.config import CHUNKS_FILE, EMBED_MODEL, QDRANT_COLLECTION_ITEMS
from Backend.storage.embedder import OllamaEmbedder, SparseEmbedder
from Backend.storage.indexer import index_chunks, load_chunks
from Backend.storage.vector_db import get_client


def main() -> int:
    ap = argparse.ArgumentParser(description="Embed chunks and upsert them into Qdrant")
    ap.add_argument("--input", type=Path, default=CHUNKS_FILE)
    ap.add_argument("--force", action="store_true", help="re-embed chunks even if unchanged")
    args = ap.parse_args()

    chunks = load_chunks(args.input)
    if not chunks:
        print(f"No chunks in {args.input}. Run Backend/run_chunking.py first.")
        return 2

    # Sparse (BM25) is best-effort: if fastembed is missing or the model fails to
    # load, index dense-only rather than hard-failing the pipeline.
    try:
        sparse_embedder = SparseEmbedder()
    except Exception as e:
        print(f"Sparse embedder unavailable ({e.__class__.__name__}: {e}); indexing dense-only")
        sparse_embedder = None

    try:
        stats = index_chunks(chunks, get_client(), OllamaEmbedder(), force=args.force,
                             sparse_embedder=sparse_embedder)
    except Exception as e:
        print(f"Indexing failed: {e}\nIs Qdrant up and has Ollama pulled {EMBED_MODEL}?")
        return 1

    print(f"{stats['total']} chunks -> '{QDRANT_COLLECTION_ITEMS}': "
          f"{stats['embedded']} embedded, {stats['skipped']} unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
