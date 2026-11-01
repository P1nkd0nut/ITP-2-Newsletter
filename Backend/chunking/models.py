"""
Chunk model for GroundedCVE (Task 2.2).

Every chunk carries Item_ID, CVE_ID, Source_URL and Source_Type so any claim
can be traced back to its source (plan, Task 2.2). Embedding prefixes
("search_document: ") are applied at indexing time in Task 2.3, not stored here.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

TIER_1 = 1  # Executive Summary Tier
TIER_2 = 2  # Technical PoC / Evidence Tier
TIER_NAMES = {TIER_1: "executive_summary", TIER_2: "technical_poc"}


@dataclass
class Chunk:
    Chunk_ID: str                      # "<Item_ID>::t<tier>::<index>" - deterministic
    Item_ID: str
    Tier: int                          # 1 or 2
    Chunk_Index: int                   # index within (item, tier)
    Text: str                          # cleaned text used for embedding AND as gate evidence
    Source_Type: str
    Source_URL: str
    Title: str = ""
    Published_Date: str = ""
    CVE_ID: Optional[str] = None
    Heading_Path: List[str] = field(default_factory=list)
    Has_Code: bool = False
    Content_Format: str = "text"       # json | html | markdown | text (format of Raw_Content)
    Parent_Content_Hash: str = ""      # envelope's SHA-256 of Raw_Content
    Flags: List[str] = field(default_factory=list)  # oversize_split, hard_split, thin_source

    @property
    def Tier_Name(self) -> str:
        return TIER_NAMES[self.Tier]

    @property
    def Char_Count(self) -> int:
        return len(self.Text)

    @property
    def Chunk_Hash(self) -> str:
        return hashlib.sha256(self.Text.encode("utf-8", errors="replace")).hexdigest()

    @property
    def point_id(self) -> str:
        """Deterministic UUID for Qdrant (point IDs must be UUIDs or ints). Used by Task 2.3."""
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"groundedcve:{self.Chunk_ID}"))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["Tier_Name"] = self.Tier_Name
        d["Char_Count"] = self.Char_Count
        d["Chunk_Hash"] = self.Chunk_Hash
        d["Point_ID"] = self.point_id
        return d
