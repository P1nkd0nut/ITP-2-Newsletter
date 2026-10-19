"""
Two-tier, heading-aware chunking (Task 2.2).

  Tier 1 (Executive Summary Tier, cap 2,500 chars): flaw concept, affected
      software, impact - the prose. Sources without headings (NVD, KEV)
      become a single Tier 1 chunk when they fit.
  Tier 2 (Technical PoC / Evidence Tier, cap 5,000 chars): fenced code,
      commands, PoC scripts, reproduction steps. Split only at logical
      boundaries (code block / step / paragraph) and NEVER truncated; a single
      code block over the cap is split at line boundaries and flagged
      `oversize_split`.

Nothing is dropped: the concatenation of all chunk text covers the whole
cleaned document. Chunks are built from a cleaned copy; Raw_Content is untouched.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, List, Optional, Set, Tuple

from Backend.config import (
    CHUNK_MIN_MERGE_CHARS,
    CHUNK_THIN_SOURCE_CHARS,
    CHUNK_TIER1_MAX_CHARS,
    CHUNK_TIER2_MAX_CHARS,
)

from .cleaner import clean_content
from .models import TIER_1, TIER_2, Chunk

# --------------------------------------------------------------------------- #
# Parsing cleaned text into heading sections
# --------------------------------------------------------------------------- #
_FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})(.*)$")
_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(\S.*?)\s*#*\s*$")
_CMD_RE = re.compile(r"^\s*\$\s+\S")

# Headings that mark a section as PoC / reproduction material (whole section -> Tier 2).
_T2_HEADING_RE = re.compile(
    r"\b(poc|proof[- ]of[- ]concept|reproduc\w*|steps?|payloads?|exploit (code|script|chain)|"
    r"usage|how to (test|exploit|reproduce)|commands?|testing)\b",
    re.I,
)


@dataclass
class Block:
    kind: str   # "text" | "code"
    text: str


@dataclass
class Section:
    path: List[str]
    heading_line: Optional[str]
    level: int
    blocks: List[Block] = field(default_factory=list)


def parse_sections(text: str) -> List[Section]:
    """Split cleaned markdown-ish text into heading sections of text/code blocks."""
    sections = [Section(path=[], heading_line=None, level=0)]
    stack: List[Tuple[int, str]] = []
    lines = text.split("\n")
    para: List[str] = []

    def flush_para() -> None:
        if para:
            t = "\n".join(para).strip("\n")
            if t.strip():
                sections[-1].blocks.append(Block("text", t))
            para.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        fm = _FENCE_RE.match(line)
        if fm:
            flush_para()
            marker = fm.group(1)
            body: List[str] = []
            j = i + 1
            while j < len(lines):
                cm = _FENCE_RE.match(lines[j])
                if cm and cm.group(1)[0] == marker[0] and len(cm.group(1)) >= len(marker) and not cm.group(2).strip():
                    break
                body.append(lines[j])
                j += 1
            if any(b.strip() for b in body):
                sections[-1].blocks.append(Block("code", f"{line.strip()}\n" + "\n".join(body) + f"\n{marker}"))
            i = j + 1
            continue

        hm = _HEADING_RE.match(line)
        if hm:
            flush_para()
            level, title = len(hm.group(1)), hm.group(2)
            while stack and stack[-1][0] >= level:
                stack.pop()
            stack.append((level, title))
            sections.append(Section(path=[t for _, t in stack], heading_line=f"{'#' * level} {title}", level=level))
            i += 1
            continue

        if _CMD_RE.match(line):  # unfenced "$ command" run -> code block
            flush_para()
            run: List[str] = []
            j = i
            while j < len(lines) and lines[j].strip() and (
                _CMD_RE.match(lines[j]) or (run and run[-1].rstrip().endswith("\\"))
            ):
                run.append(lines[j])
                j += 1
            sections[-1].blocks.append(Block("code", "```\n" + "\n".join(run) + "\n```"))
            i = j
            continue

        if not line.strip():
            flush_para()
        else:
            para.append(line)
        i += 1
    flush_para()
    return [s for s in sections if s.blocks]


# --------------------------------------------------------------------------- #
# Splitting oversize text without truncating
# --------------------------------------------------------------------------- #
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")
_TEXT_LEVELS: List[Tuple[Any, str]] = [("\n\n", "\n\n"), ("\n", "\n"), (_SENTENCE_RE, " "), (" ", " ")]
_CODE_LEVELS: List[Tuple[Any, str]] = [("\n\n", "\n\n"), ("\n", "\n")]


def _split(text: str, limit: int, levels: List[Tuple[Any, str]], level: int = 0) -> Tuple[List[str], bool]:
    """Greedy split at the coarsest boundary that works. Returns (parts, hard_cut_used)."""
    if len(text) <= limit:
        return [text], False
    if level >= len(levels):
        return [text[i:i + limit] for i in range(0, len(text), limit)], True
    pat, joiner = levels[level]
    pieces = text.split(pat) if isinstance(pat, str) else pat.split(text)
    if len(pieces) == 1:
        return _split(text, limit, levels, level + 1)
    out: List[str] = []
    cur: Optional[str] = None
    hard = False
    for p in pieces:
        if len(p) > limit:
            if cur is not None:
                out.append(cur)
                cur = None
            sub, h = _split(p, limit, levels, level + 1)
            out.extend(sub)
            hard |= h
        elif cur is None:
            cur = p
        elif len(cur) + len(joiner) + len(p) <= limit:
            cur += joiner + p
        else:
            out.append(cur)
            cur = p
    if cur is not None:
        out.append(cur)
    return out, hard


def _split_code(fenced: str, limit: int) -> Tuple[List[str], bool]:
    lines = fenced.split("\n")
    opener, closer, inner = lines[0], lines[-1], "\n".join(lines[1:-1])
    budget = max(limit - len(opener) - len(closer) - 2, 50)
    parts, hard = _split(inner, budget, _CODE_LEVELS)
    return [f"{opener}\n{p}\n{closer}" for p in parts], hard


# --------------------------------------------------------------------------- #
# Units and packing
# --------------------------------------------------------------------------- #
@dataclass
class _Unit:
    tier: int
    text: str
    code: bool
    sec: int
    heading_line: Optional[str]
    level: int
    path: List[str]
    parts: Tuple[str, ...] = ()          # (lead_in, code) for a glued composite
    flags: Set[str] = field(default_factory=set)


@dataclass
class _Pending:
    text: str
    path: List[str]
    has_code: bool
    flags: Set[str]


def _is_t2_section(path: List[str]) -> bool:
    return any(_T2_HEADING_RE.search(h) for h in path)


def _build_units(sections: List[Section]) -> List[_Unit]:
    units: List[_Unit] = []
    for si, sec in enumerate(sections):
        t2_sec = _is_t2_section(sec.path)
        common = dict(sec=si, heading_line=sec.heading_line, level=sec.level, path=sec.path)
        k = 0
        while k < len(sec.blocks):
            b = sec.blocks[k]
            nxt = sec.blocks[k + 1] if k + 1 < len(sec.blocks) else None
            if b.kind == "code":
                units.append(_Unit(TIER_2, b.text, True, **common))
            elif t2_sec:
                units.append(_Unit(TIER_2, b.text, False, **common))
            elif nxt is not None and nxt.kind == "code" and b.text.rstrip().endswith(":"):
                # lead-in ("Run the following:") stays glued to its command
                units.append(_Unit(TIER_2, b.text + "\n\n" + nxt.text, True, parts=(b.text, nxt.text), **common))
                k += 1
            else:
                units.append(_Unit(TIER_1, b.text, False, **common))
            k += 1
    return units


class _Packer:
    def __init__(self, cap: int, min_merge: int):
        self.cap, self.min_merge = cap, min_merge
        self.out: List[_Pending] = []
        self._reset()

    def _reset(self) -> None:
        self.parts: List[str] = []
        self.size = 0
        self.emitted: Set[int] = set()
        self.last_sec: Optional[int] = None
        self.path: Optional[List[str]] = None
        self.has_code = False
        self.flags: Set[str] = set()

    def _flush(self) -> None:
        if self.parts:
            self.out.append(_Pending("\n\n".join(self.parts), self.path or [], self.has_code, set(self.flags)))
        self._reset()

    def finish(self) -> List[_Pending]:
        self._flush()
        return self.out

    def add(self, u: _Unit) -> None:
        for piece in self._fit(u):
            self._add_piece(piece)

    def _fit(self, u: _Unit) -> List[_Unit]:
        hl = len(u.heading_line) + 2 if u.heading_line else 0
        if hl + len(u.text) <= self.cap:
            return [u]
        if u.parts:  # composite too big: lead-in and code are split independently
            lead, code = u.parts
            return self._fit(replace(u, text=lead, code=False, parts=())) + \
                   self._fit(replace(u, text=code, code=True, parts=()))
        limit = max(self.cap - hl, 200)
        parts, hard = _split_code(u.text, limit) if u.code else _split(u.text, limit, _TEXT_LEVELS)
        flags = set(u.flags) | {"oversize_split"} | ({"hard_split"} if hard else set())
        return [replace(u, text=p, flags=set(flags)) for p in parts]

    def _pre(self, u: _Unit) -> str:
        return u.heading_line + "\n\n" if (u.heading_line and u.sec not in self.emitted) else ""

    def _add_piece(self, u: _Unit) -> None:
        if self.parts and u.sec != self.last_sec and u.level <= 2 and self.size >= self.min_merge:
            self._flush()
        pre = self._pre(u)
        add = len(pre) + len(u.text) + (2 if self.parts else 0)
        if self.parts and self.size + add > self.cap:
            self._flush()
            pre = self._pre(u)
            add = len(pre) + len(u.text)
        if not self.parts:
            self.path = u.path
        self.parts.append(pre + u.text)
        self.size += add
        self.emitted.add(u.sec)
        self.last_sec = u.sec
        self.has_code |= u.code
        self.flags |= u.flags


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def _get(env: Any, name: str, default: Any = None) -> Any:
    v = env.get(name, default) if isinstance(env, dict) else getattr(env, name, default)
    return getattr(v, "value", v)  # Enum -> value


def chunk_envelope(
    envelope: Any,
    tier1_cap: int = CHUNK_TIER1_MAX_CHARS,
    tier2_cap: int = CHUNK_TIER2_MAX_CHARS,
) -> List[Chunk]:
    """
    Chunk one staging envelope (a StagingEnvelope or a dict with the same keys).
    Returns Tier 1 chunks followed by Tier 2 chunks.
    """
    item_id = str(_get(envelope, "Item_ID"))
    raw = _get(envelope, "Raw_Content") or ""
    source_type = str(_get(envelope, "Source_Type") or "OTHER")

    cleaned, fmt = clean_content(source_type, raw)
    if not cleaned.strip():
        return []

    units = _build_units(parse_sections(cleaned))
    p1, p2 = _Packer(tier1_cap, CHUNK_MIN_MERGE_CHARS), _Packer(tier2_cap, CHUNK_MIN_MERGE_CHARS)
    for u in units:
        (p2 if u.tier == TIER_2 else p1).add(u)

    thin = len(cleaned) < CHUNK_THIN_SOURCE_CHARS
    parent_hash = _get(envelope, "Content_Hash") or hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()

    chunks: List[Chunk] = []
    for tier, pending, cap in ((TIER_1, p1.finish(), tier1_cap), (TIER_2, p2.finish(), tier2_cap)):
        for idx, p in enumerate(pending):
            flags = set(p.flags) | ({"thin_source"} if thin else set())
            if len(p.text) > cap:  # should be unreachable; surfaced rather than hidden
                flags.add("over_cap")
            chunks.append(Chunk(
                Chunk_ID=f"{item_id}::t{tier}::{idx:03d}",
                Item_ID=item_id,
                Tier=tier,
                Chunk_Index=idx,
                Text=p.text,
                Source_Type=source_type,
                Source_URL=str(_get(envelope, "Source_URL") or ""),
                Title=str(_get(envelope, "Title") or ""),
                Published_Date=str(_get(envelope, "Published_Date") or ""),
                CVE_ID=_get(envelope, "CVE_ID"),
                Heading_Path=list(p.path),
                Has_Code=p.has_code,
                Content_Format=fmt,
                Parent_Content_Hash=parent_hash,
                Flags=sorted(flags),
            ))
    return chunks


def chunk_envelopes(envelopes: Iterable[Any], **kwargs: Any) -> List[Chunk]:
    out: List[Chunk] = []
    for env in envelopes:
        out.extend(chunk_envelope(env, **kwargs))
    return out


def evidence_texts(chunks: Iterable[Chunk], item_id: Optional[str] = None) -> List[str]:
    """
    Tier 2 chunk texts for the verification gate's `evidence` argument.

    Chunk text is entity-decoded (e.g. `&amp;&amp;` -> `&&`), so passing it as
    evidence stops the gate from flagging correct commands that appear
    HTML-encoded in Raw_Content.
    """
    return [c.Text for c in chunks if c.Tier == TIER_2 and (item_id is None or c.Item_ID == item_id)]
