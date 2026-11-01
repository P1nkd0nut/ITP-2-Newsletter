"""
Cleaning for GroundedCVE chunking (Task 2.2).

Produces a CLEANED COPY of an envelope's Raw_Content for embedding and chunking.
Raw_Content itself is never modified: the verification gate audits claims
against the original source text.

Every format is normalised to the same lightweight markdown dialect
(`#` headings, fenced code blocks, `- ` lists, `a | b` table rows) so the
chunker only has to understand one structure.

Code inside fences is NEVER altered (no whitespace, entity or boilerplate
rewriting) so commands stay verbatim.
"""
from __future__ import annotations

import json
import re
from typing import Any, List, Tuple

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

JSON_SOURCES = {"NVD", "CISA_KEV"}

# --------------------------------------------------------------------------- #
# Format detection
# --------------------------------------------------------------------------- #
_HTML_START_RE = re.compile(r"(?is)^\s*(<!doctype html|<html)")
_HTML_TAG_RE = re.compile(r"(?i)</?(p|div|pre|code|h[1-6]|li|ul|ol|table|tr|td|span|a|section|article)\b")
_MD_SIGNAL_RE = re.compile(r"(?m)^(#{1,6}\s+\S|```|~~~)")


def detect_format(source_type: str, raw: str) -> str:
    """Return one of: json, html, markdown, text."""
    s = (raw or "").lstrip("\ufeff \t\r\n")
    if not s:
        return "text"
    if s[0] in "{[":
        try:
            json.loads(s)
            return "json"
        except ValueError:
            pass
    if _HTML_START_RE.match(s):
        return "html"
    tags = len(_HTML_TAG_RE.findall(s))
    md = len(_MD_SIGNAL_RE.findall(s))
    if tags >= 3 and tags > md:
        return "html"
    if md:
        return "markdown"
    return "text"


# --------------------------------------------------------------------------- #
# Shared post-processing (applied outside fenced code only)
# --------------------------------------------------------------------------- #
_FENCE_SPLIT_RE = re.compile(r"(^(?:```|~~~).*?^(?:```|~~~)[ \t]*$)", re.M | re.S)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_LINKED_IMAGE_RE = re.compile(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)")
_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_IMG_TAG_RE = re.compile(r"(?i)<img\b[^>]*>")
_ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\n(.*?)\n---[ \t]*\n", re.S)

_BOILERPLATE_RES = [
    re.compile(p, re.I)
    for p in (
        r"sign in",
        r"log in",
        r"skip to (main )?content",
        r"back to top",
        r"was this helpful\??",
        r"(share|tweet|print|subscribe)( this)?:?",
        r"accept( all)? cookies",
        r"cookie (policy|settings)",
        r"privacy policy",
        r"terms of (use|service)",
        r"all rights reserved\.?",
        r"(copyright\s*)?©.*",
        r"except as otherwise noted, the content of this page is licensed.*",
        r"content and code samples on this page are subject to the licenses described in the site policies\.?",
        r"last updated.*",
        r"link to this section",
        r"table of contents",
        r"on this page",
    )
]


def _is_boilerplate(line: str) -> bool:
    s = line.strip().strip("*_# ").strip()
    if not s:
        return False
    return any(rx.fullmatch(s) for rx in _BOILERPLATE_RES)


def _clean_prose(segment: str) -> str:
    seg = _COMMENT_RE.sub("", segment)
    seg = _LINKED_IMAGE_RE.sub("", seg)
    seg = _IMAGE_RE.sub("", seg)
    seg = _IMG_TAG_RE.sub("", seg)
    seg = _ZERO_WIDTH_RE.sub("", seg)
    lines = [ln.rstrip() for ln in seg.split("\n") if not _is_boilerplate(ln)]
    seg = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", seg).strip("\n")


def _postprocess(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n").lstrip("\ufeff")
    pieces: List[str] = []
    for i, seg in enumerate(_FENCE_SPLIT_RE.split(text)):
        if i % 2 == 1:           # fenced code: untouched
            pieces.append(seg.strip("\n"))
        else:
            cleaned = _clean_prose(seg)
            if cleaned.strip():
                pieces.append(cleaned)
    return "\n\n".join(pieces).strip()


# --------------------------------------------------------------------------- #
# JSON (NVD, CISA KEV)
# --------------------------------------------------------------------------- #
def _en(descs: Any) -> str:
    if not isinstance(descs, list):
        return ""
    en = [d.get("value", "") for d in descs if isinstance(d, dict) and d.get("lang") == "en"]
    anyl = [d.get("value", "") for d in descs if isinstance(d, dict)]
    return " ".join((en or anyl)[:1]).strip()


def _render_nvd(j: dict) -> str:
    lines = [f"CVE ID: {j.get('id', '')}".strip()]
    if j.get("published"):
        lines.append(f"Published: {j['published']}")
    if j.get("vulnStatus"):
        lines.append(f"Status: {j['vulnStatus']}")
    desc = _en(j.get("descriptions"))
    if desc:
        lines += ["", "Description:", desc]

    affected_lines: List[str] = []
    for a in j.get("affected") or []:
        for ad in (a.get("affectedData") or []) if isinstance(a, dict) else []:
            vendor, product = ad.get("vendor", ""), ad.get("product", "")
            vers = []
            for v in ad.get("versions") or []:
                if not isinstance(v, dict):
                    continue
                s = str(v.get("version", ""))
                if v.get("lessThan"):
                    s += f" (< {v['lessThan']})"
                if v.get("lessThanOrEqual"):
                    s += f" (<= {v['lessThanOrEqual']})"
                if v.get("status"):
                    s += f" [{v['status']}]"
                vers.append(s.strip())
            mods = ", ".join(ad.get("modules") or [])
            line = f"- {vendor} {product}".strip()
            if vers:
                line += f": versions {', '.join(vers)}"
            if mods:
                line += f"; components: {mods}"
            affected_lines.append(line)
    if affected_lines:
        lines += ["", "Affected products:", *affected_lines]

    cwes = []
    for w in j.get("weaknesses") or []:
        for d in (w.get("description") or []) if isinstance(w, dict) else []:
            val = d.get("value")
            if val and val not in cwes:
                cwes.append(val)
    if cwes:
        lines += ["", f"Weaknesses: {', '.join(cwes)}"]

    metrics = j.get("metrics") or {}
    cvss_lines = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = (m or {}).get("cvssData") or {}
            if "baseScore" in data:
                sev = data.get("baseSeverity") or m.get("baseSeverity") or ""
                cvss_lines.append(
                    f"- CVSS {data.get('version', '')}: {data['baseScore']} {sev} {data.get('vectorString', '')}".rstrip()
                )
    if cvss_lines:
        lines += ["", "CVSS metrics:", *cvss_lines]

    refs = [r.get("url") for r in j.get("references") or [] if isinstance(r, dict) and r.get("url")]
    if refs:
        lines += ["", "References:", *[f"- {u}" for u in refs]]
    return "\n".join(lines)


def _render_kev(j: dict) -> str:
    def f(label: str, key: str) -> str:
        v = j.get(key)
        if isinstance(v, list):
            v = ", ".join(map(str, v))
        return f"{label}: {v}" if v not in (None, "") else ""

    head = [f("CVE ID", "cveID"), f("Name", "vulnerabilityName"),
            f("Vendor", "vendorProject"), f("Product", "product")]
    body = []
    if j.get("shortDescription"):
        body += ["", "Description:", j["shortDescription"]]
    if j.get("requiredAction"):
        body += ["", "Required action:", j["requiredAction"]]
    tail = [f("Date added to KEV", "dateAdded"), f("Due date", "dueDate"),
            f("Known ransomware campaign use", "knownRansomwareCampaignUse"), f("CWEs", "cwes")]
    notes = []
    if j.get("notes"):
        notes = ["", "Notes:", j["notes"]]
    return "\n".join([x for x in head if x] + body + [""] + [x for x in tail if x] + notes)


def _render_generic(obj: Any, indent: int = 0) -> List[str]:
    pad = "  " * indent
    out: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                if isinstance(v, list) and all(not isinstance(x, (dict, list)) for x in v):
                    out.append(f"{pad}{k}: {', '.join(map(str, v))}")
                else:
                    out.append(f"{pad}{k}:")
                    out += _render_generic(v, indent + 1)
            elif v not in (None, "", [], {}):
                out.append(f"{pad}{k}: {v}")
    elif isinstance(obj, list):
        for x in obj:
            if isinstance(x, (dict, list)):
                out += _render_generic(x, indent)
                out.append("")
            else:
                out.append(f"{pad}- {x}")
    else:
        out.append(f"{pad}{obj}")
    return out


def clean_json(raw: str) -> str:
    j = json.loads(raw.lstrip("\ufeff \t\r\n"))
    if isinstance(j, dict) and "descriptions" in j and "id" in j:
        text = _render_nvd(j)
    elif isinstance(j, dict) and "cveID" in j:
        text = _render_kev(j)
    else:
        text = "\n".join(_render_generic(j))
    return _postprocess(text)


# --------------------------------------------------------------------------- #
# HTML (Project Zero, Android bulletins, Apple releases)
# --------------------------------------------------------------------------- #
_DROP = {"script", "style", "noscript", "svg", "iframe", "form", "nav", "header", "footer",
         "aside", "button", "template", "head", "meta", "link", "select", "input", "title"}
_VOID_DROP = {"meta", "link", "input"}
_INLINE = {"a", "span", "b", "i", "em", "strong", "code", "small", "sup", "sub", "abbr", "u",
           "mark", "kbd", "samp", "var", "cite", "q", "time", "label", "font", "s", "del", "ins",
           "bdi", "wbr", "br", "img"}
_BLOCKISH = ["pre", "ul", "ol", "table", "p", "div", "h1", "h2", "h3", "h4", "h5", "h6"]
_HEADING_TAG_RE = re.compile(r"h([1-6])")


def _ws(s: str) -> str:
    return re.sub(r"[ \t\r\n\f\v\u00a0]+", " ", s).strip()


def _inline_children(tag: Tag) -> str:
    parts = []
    for c in tag.children:
        if isinstance(c, Comment):
            continue
        if isinstance(c, NavigableString):
            parts.append(str(c))
        elif isinstance(c, Tag) and c.name not in _DROP:
            parts.append(_inline(c))
    return "".join(parts)


def _inline(tag: Tag) -> str:
    n = tag.name
    if n == "br":
        return " "
    if n == "img":
        return ""
    if n == "code":
        t = _ws(tag.get_text())
        return f"`{t}`" if t and "`" not in t else t
    if n == "a":
        inner = _ws(_inline_children(tag))
        href = (tag.get("href") or "").strip()
        if inner and href.startswith(("http://", "https://")) and inner != href:
            return f"[{inner}]({href})"
        return inner
    return _inline_children(tag)


def _fence(pre: Tag) -> str:
    lang = ""
    for el in [pre, *pre.find_all("code", limit=1)]:
        for cls in el.get("class") or []:
            m = re.match(r"(?:language|lang)-(\S+)", cls)
            if m:
                lang = m.group(1)
    code = pre.get_text().strip("\n")
    if not code.strip():
        return ""
    marker = "````" if "```" in code else "```"
    return f"{marker}{lang}\n{code}\n{marker}"


def _walk(node: Tag, out: List[str]) -> None:
    buf: List[str] = []

    def flush() -> None:
        txt = _ws("".join(buf))
        buf.clear()
        if txt:
            out.append(txt)

    for child in node.children:
        if isinstance(child, Comment):
            continue
        if isinstance(child, NavigableString):
            buf.append(str(child))
            continue
        if not isinstance(child, Tag) or child.name in _DROP:
            continue
        if child.name in _INLINE and not child.find(_BLOCKISH):
            buf.append(_inline(child))
            continue
        flush()
        _block(child, out)
    flush()


def _block(tag: Tag, out: List[str]) -> None:
    n = tag.name
    m = _HEADING_TAG_RE.fullmatch(n)
    if m:
        txt = _ws(_inline_children(tag))
        if txt:
            out.append("#" * int(m.group(1)) + " " + txt)
    elif n == "pre":
        fenced = _fence(tag)
        if fenced:
            out.append(fenced)
    elif n in ("ul", "ol"):
        lines: List[str] = []
        _list_into(tag, out, lines, 0)
        _flush_lines(out, lines)
    elif n == "table":
        rows = []
        for tr in tag.find_all("tr"):
            cells = [_ws(_inline_children(c)) for c in tr.find_all(["th", "td"])]
            if any(cells):
                rows.append(" | ".join(cells))
        if rows:
            out.append("\n".join(rows))
    elif n == "hr":
        return
    else:
        _walk(tag, out)


def _flush_lines(out: List[str], lines: List[str]) -> None:
    if lines:
        out.append("\n".join(lines))
        lines.clear()


def _list_into(tag: Tag, out: List[str], lines: List[str], depth: int) -> None:
    ordered = tag.name == "ol"
    for idx, li in enumerate(tag.find_all("li", recursive=False), start=1):
        marker = f"{idx}. " if ordered else "- "
        segs: List[Tuple[str, Any]] = []
        buf: List[str] = []

        def flush_buf() -> None:
            txt = _ws("".join(buf))
            buf.clear()
            if txt:
                segs.append(("text", txt))

        for c in li.children:
            if isinstance(c, Comment):
                continue
            if isinstance(c, NavigableString):
                buf.append(str(c))
            elif isinstance(c, Tag) and c.name not in _DROP:
                if c.name in _INLINE and not c.find(_BLOCKISH):
                    buf.append(_inline(c))
                elif c.name in ("ul", "ol"):
                    flush_buf()
                    segs.append(("list", c))
                elif c.name == "pre":
                    flush_buf()
                    fenced = _fence(c)
                    if fenced:
                        segs.append(("code", fenced))
                else:
                    flush_buf()
                    sub: List[str] = []
                    _block(c, sub)
                    for s in sub:
                        segs.append(("code" if s.startswith(("```", "````")) else "text", s))
        flush_buf()

        used_marker = False
        for kind, val in segs:
            if kind == "text":
                prefix = "  " * depth + ("" if used_marker else marker)
                if used_marker:
                    prefix += "  "
                lines.append(prefix + val)
                used_marker = True
            elif kind == "list":
                _list_into(val, out, lines, depth + 1)
            else:  # code inside a list item: break the list block, emit the fence, continue
                _flush_lines(out, lines)
                out.append(val)
                used_marker = True


def clean_html(raw: str) -> str:
    soup = BeautifulSoup(raw, "html.parser")
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        c.extract()
    for t in soup.find_all(_DROP):
        if getattr(t, "decomposed", False):
            continue
        # html.parser can wrongly nest the page inside an unclosed void tag (<link>, <meta>, <input>) or <head>;
        # unwrap those instead of decomposing so the real content isn't deleted with them.
        if (t.name in _VOID_DROP and t.contents) or (t.name == "head" and t.find(["body", *_BLOCKISH])):
            t.unwrap()
        else:
            t.decompose()
    for t in soup.select("[hidden], [aria-hidden=true]"):
        t.decompose()
    for pre in soup.find_all("pre"):
        for br in pre.find_all("br"):
            br.replace_with("\n")

    candidates = [el for sel in ("article", "main", "[role=main]") for el in soup.select(sel)]
    root: Tag = max(candidates, key=lambda e: len(e.get_text())) if candidates else (soup.body or soup)

    out: List[str] = []
    _walk(root, out)
    return _postprocess("\n\n".join(out))


# --------------------------------------------------------------------------- #
# Markdown / plain text
# --------------------------------------------------------------------------- #
def clean_markdown(raw: str) -> str:
    text = raw.replace("\r\n", "\n").lstrip("\ufeff")
    m = _FRONTMATTER_RE.match(text)
    if m and re.search(r"(?m)^[\w-]+\s*:", m.group(1)):
        text = text[m.end():]
    return _postprocess(text)


def clean_text(raw: str) -> str:
    return _postprocess(raw)


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #
def clean_content(source_type: str, raw: str) -> Tuple[str, str]:
    """Return (cleaned_text, detected_format). Never mutates `raw`."""
    raw = raw or ""
    fmt = detect_format(source_type, raw)
    if fmt == "json":
        return clean_json(raw), fmt
    if fmt == "html":
        return clean_html(raw), fmt
    if fmt == "markdown":
        return clean_markdown(raw), fmt
    return clean_text(raw), fmt
