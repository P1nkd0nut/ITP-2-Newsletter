"""
Qdrant connection helper for GroundedCVE (Task 2.1).
"""
from qdrant_client import QdrantClient

from Backend.config import QDRANT_HOST, QDRANT_PORT


def get_client() -> QdrantClient:
    """Return a QdrantClient pointed at the docker-compose Qdrant instance."""
    return QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
