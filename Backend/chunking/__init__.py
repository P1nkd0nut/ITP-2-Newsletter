"""
GroundedCVE Chunking Package (Task 2.2).
Stage 2: cleaning + two-tier heading-aware chunking of staged envelopes.
"""
from .chunker import chunk_envelope, chunk_envelopes, evidence_texts, parse_sections
from .cleaner import clean_content, detect_format
from .models import Chunk

__all__ = [
    "Chunk",
    "chunk_envelope",
    "chunk_envelopes",
    "clean_content",
    "detect_format",
    "evidence_texts",
    "parse_sections",
]
