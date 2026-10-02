"""
Initialises the Qdrant data model for GroundedCVE (Task 2.1).

Creates two collections:
  1. QDRANT_COLLECTION_ITEMS     - all ingested items/chunks, with ranking metadata
                                    (score, rationale, confidence).
  2. QDRANT_COLLECTION_PUBLISHED - validated, published cards; queried by the
                                    novelty check.

Each collection is declared with named vectors so the dense (nomic-embed-text,
768-dim, cosine) and sparse (BM25 via fastembed) indexes from Task 2.3 can be
added without recreating the collection.

Usage:
    python Backend/storage/init_qdrant.py
"""
import sys
from pathlib import Path

# Add project root to sys.path so Backend modules import cleanly
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from qdrant_client.models import (
    Distance,
    SparseVectorParams,
    VectorParams,
)
from rich.console import Console

from Backend.config import EMBED_DIM, QDRANT_COLLECTION_ITEMS, QDRANT_COLLECTION_PUBLISHED
from Backend.storage.vector_db import get_client

console = Console()

DENSE_VECTOR_NAME = "dense"
SPARSE_VECTOR_NAME = "sparse"


def ensure_collection(client, name: str) -> bool:
    """Create the collection if it doesn't already exist. Returns True if created."""
    if client.collection_exists(name):
        return False

    client.create_collection(
        collection_name=name,
        vectors_config={
            DENSE_VECTOR_NAME: VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
        },
        sparse_vectors_config={
            SPARSE_VECTOR_NAME: SparseVectorParams(),
        },
    )
    return True


def main() -> None:
    client = get_client()

    console.print(f"[bold cyan]Connecting to Qdrant...[/bold cyan]")
    info = client.info()
    console.print(f"Connected - Qdrant version {info.version}")

    for name in (QDRANT_COLLECTION_ITEMS, QDRANT_COLLECTION_PUBLISHED):
        created = ensure_collection(client, name)
        status = "[green]created[/green]" if created else "[yellow]already exists[/yellow]"
        console.print(f"Collection '{name}': {status}")


if __name__ == "__main__":
    main()
