"""
Grounded Card Summariser (Task 3.1).

Writes each top-ranked item's newsletter card from that item's own retrieved
chunks, then runs it through the Deterministic Source-Verification Gate
(Task 3.2). A failing draft is regenerated once with the gate's failure
reasons; if it still fails, the card is quarantined and never published.
"""
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

import requests

from Backend.config import (
    OLLAMA_HOST,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
    SUMMARY_TOP_K_CHUNKS,
)
from Backend.ingestion.models import StagingEnvelope
from Backend.verification.gate import VerificationGate
from Backend.verification.models import CheckFailure, DraftCard

logger = logging.getLogger(__name__)

# llm(system_prompt, user_prompt) -> raw model text (expected to be a JSON object)
LLM = Callable[[str, str], str]

MAX_EXCERPT_CHARS = 12000

SYSTEM_PROMPT = """You write short newsletter cards about security vulnerabilities for penetration testers.
Use ONLY the numbered source excerpts you are given. Do not use outside knowledge.

Rules:
- Every CVE ID, CWE, CVSS score and version number you write must appear in the excerpts.
- Only claim an impact (e.g. remote code execution, privilege escalation) if the excerpts state it.
- testing_syntax: commands copied character for character from the excerpts. If the excerpts contain no commands, use [].
- references: only URLs that appear in the excerpts or the item's source URL. Never invent links.
- If the excerpts do not say something, leave it out rather than guess.

Respond ONLY with a JSON object:
{
  "mechanism": "<1-3 sentences: what the flaw is and how it works>",
  "impact": "<1-2 sentences: what an attacker gains and which versions are affected>",
  "testing_syntax": ["<command copied verbatim>", ...],
  "remediation": "<1-2 sentences: how to fix or mitigate>",
  "references": ["<url>", ...]
}"""


def build_prompt(envelope: StagingEnvelope, chunks: Sequence[Dict[str, Any]],
                 failures: Optional[List[CheckFailure]] = None) -> str:
    lines = [
        f"Item: {envelope.Title}",
        f"CVE ID: {envelope.CVE_ID or 'N/A'}",
        f"Product: {envelope.Vendor_Product or 'Unspecified'}",
        f"Source URL: {envelope.Source_URL}",
        "",
        "Source excerpts:",
    ]
    used = 0
    for i, c in enumerate(chunks, 1):
        text = c.get("Text", "")
        if used + len(text) > MAX_EXCERPT_CHARS:
            text = text[: max(0, MAX_EXCERPT_CHARS - used)]
        if not text:
            break
        heading = " > ".join(c.get("Heading_Path") or [])
        lines += [f"[{i}]{' ' + heading if heading else ''}", text, ""]
        used += len(text)

    if failures:
        lines += [
            "Your previous draft was rejected because these facts are not in the excerpts.",
            "Remove or correct each one:",
            *[f"- {f.check}: {f.value} ({f.reason})" for f in failures],
        ]
    return "\n".join(lines)


def parse_card(raw: str) -> DraftCard:
    """Parse the model's JSON, tolerating ```json fences or text around the object."""
    text = raw.strip()
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError("Model response contains no JSON object")
    data = json.loads(m.group(0))

    def as_list(v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v] if v.strip() else []
        return [str(x) for x in v if str(x).strip()]

    return DraftCard(
        mechanism=str(data.get("mechanism") or "").strip(),
        impact=str(data.get("impact") or "").strip(),
        testing_syntax=as_list(data.get("testing_syntax")),
        remediation=str(data.get("remediation") or "").strip(),
        references=as_list(data.get("references")),
    )


# ---------------------------------------------------------------- LLM backends

def openrouter_llm(api_key: str = OPENROUTER_API_KEY, model: str = OPENROUTER_MODEL,
                   base_url: str = OPENROUTER_BASE_URL, timeout: int = 60) -> LLM:
    def call(system: str, user: str) -> str:
        resp = requests.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://github.com/P1nkd0nut/ITP-2-Newsletter",
                "X-Title": "GroundedCVE",
            },
            json={
                "model": model,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "response_format": {"type": "json_object"},
                "temperature": 0.1,
            },
            timeout=timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"OpenRouter returned {resp.status_code}")
        return resp.json()["choices"][0]["message"]["content"]

    call.model_name = f"openrouter/{model}"
    return call


def ollama_llm(model: str, host: str = OLLAMA_HOST, timeout: int = 180) -> LLM:
    def call(system: str, user: str) -> str:
        resp = requests.post(
            f"{host.rstrip('/')}/api/generate",
            json={"model": model, "system": system, "prompt": user, "format": "json", "stream": False,
                  "options": {"temperature": 0.1, "num_ctx": 8192}},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    call.model_name = f"ollama/{model}"
    return call


def default_llm(ollama_model: Optional[str] = None) -> Optional[LLM]:
    """OpenRouter (Qwen 2.5 72B) when OPENROUTER_API_KEY is set, else local Ollama if a model is named."""
    if OPENROUTER_API_KEY:
        return openrouter_llm()
    if ollama_model:
        return ollama_llm(ollama_model)
    return None


# ------------------------------------------------------------------ summariser

def retrieval_query(envelope: StagingEnvelope) -> str:
    return f"{envelope.Title}. How the vulnerability works, its impact, affected versions, exploitation and fix."


class GroundedSummariser:
    def __init__(self, llm: LLM, retriever, gate: Optional[VerificationGate] = None,
                 top_k: int = SUMMARY_TOP_K_CHUNKS):
        self.llm = llm
        self.retriever = retriever
        self.gate = gate or VerificationGate()
        self.top_k = top_k

    def summarise(self, envelope: StagingEnvelope) -> Dict[str, Any]:
        """
        Returns a card record. status is PASSED (publishable), QUARANTINED (gate
        rejected both drafts) or ERROR (no chunks, or the model failed).
        """
        chunks, mode = self.retriever.retrieve(envelope.Item_ID, retrieval_query(envelope), self.top_k)
        record: Dict[str, Any] = {
            "Item_ID": envelope.Item_ID,
            "CVE_ID": envelope.CVE_ID,
            "Title": envelope.Title,
            "Source_URL": envelope.Source_URL,
            "Content_Hash": envelope.Content_Hash,
            "chunk_ids": [c.get("Chunk_ID") for c in chunks],
            "retrieval": mode,
            "model": getattr(self.llm, "model_name", "custom"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "card": None,
            "verification": None,
        }
        if not chunks:
            record.update(status="ERROR", error="No chunks found for this item. Run run_chunking.py first.")
            return record

        def generate(failures: Optional[List[CheckFailure]]) -> DraftCard:
            return parse_card(self.llm(SYSTEM_PROMPT, build_prompt(envelope, chunks, failures)))

        try:
            card, result = self.gate.verify_with_retry(generate, envelope, evidence=[c["Text"] for c in chunks])
        except Exception as e:
            record.update(status="ERROR", error=f"Card generation failed: {e}")
            return record

        record.update(status=result.status, card=card.model_dump(), verification=result.model_dump())
        return record
