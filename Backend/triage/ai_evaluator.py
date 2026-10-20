"""
AI Severity & Practical Exploitability Assessor (Task 3.1 & Task 2.4).
Uses local Ollama (Qwen 2.5) to evaluate the true offensive utility and severity
of an advisory, replacing noisy or unverified CVSS metrics with expert AI evaluation.
Includes an intelligent heuristic fallback for zero-downtime execution.
"""
import json
import logging
import re
from typing import Dict, Any, Optional
import requests
from Backend.config import (
    OLLAMA_HOST,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
)
from Backend.ingestion.models import StagingEnvelope
from Backend.triage.models import AISeverityAssessment

logger = logging.getLogger(__name__)

DEFAULT_AI_MODEL = "qwen2.5:3b"

SYSTEM_PROMPT = """You are a senior offensive penetration tester and threat intelligence analyst.
Analyze the provided vulnerability advisory. Evaluate its practical offensive exploitability and real-world attack impact on a scale from 0.0 to 10.0:
- 9.0 - 10.0 (CRITICAL): Unauthenticated Remote Code Execution (RCE), Authentication Bypass, Full Account Takeover, or Kernel/Root Privilege Escalation.
- 7.0 - 8.9 (HIGH): Server-Side Request Forgery (SSRF), SQL Injection with data exfiltration, Intent Hijacking, Memory Buffer Overflow.
- 4.0 - 6.9 (MEDIUM): Stored/Reflected XSS, CSRF, constrained Path Traversal, Sensitive Information Disclosure.
- 0.0 - 3.9 (LOW): Local Denial of Service, memory leak, local race condition requiring physical/restricted access.

You MUST respond ONLY with a valid JSON object matching this schema:
{
  "severity_score": <float between 0.0 and 10.0>,
  "offensive_impact": "<e.g. Remote Code Execution | Authentication Bypass | Privilege Escalation | Cross-Site Scripting | Denial of Service>",
  "exploitability": "<CRITICAL | HIGH | MEDIUM | LOW>",
  "reasoning": "<1-2 sentence technical offensive rationale>"
}"""


class AISeverityEvaluator:
    """Evaluates practical severity via OpenRouter (Qwen 2.5 72B) or local Ollama with heuristic fallback."""

    def __init__(
        self,
        ollama_host: str = OLLAMA_HOST,
        model_name: str = DEFAULT_AI_MODEL,
        openrouter_api_key: Optional[str] = None,
        openrouter_model: str = OPENROUTER_MODEL,
    ):
        self.ollama_host = ollama_host.rstrip("/")
        self.model_name = model_name
        self.openrouter_api_key = (
            openrouter_api_key if openrouter_api_key is not None else OPENROUTER_API_KEY
        )
        self.openrouter_model = openrouter_model

    def evaluate(self, envelope: StagingEnvelope) -> AISeverityAssessment:
        """
        Evaluates practical severity:
        1. OpenRouter gateway (Qwen 2.5 72B) if API key configured
        2. Local Ollama instance (Qwen 2.5)
        3. Offensive heuristic fallback engine
        """
        # 1. Attempt OpenRouter if API key is present
        if self.openrouter_api_key:
            try:
                assessment = self._evaluate_with_openrouter(envelope)
                if assessment:
                    return assessment
            except Exception as e:
                logger.warning(f"OpenRouter evaluation failed ({e}). Falling back to local Ollama.")

        # 2. Attempt local Ollama
        try:
            assessment = self._evaluate_with_ollama(envelope)
            if assessment:
                return assessment
        except Exception as e:
            logger.warning(f"Ollama AI evaluation failed ({e}). Falling back to offensive heuristic engine.")

        # 3. Resilient fallback to offensive heuristic evaluation
        return self._evaluate_heuristic(envelope)

    def _evaluate_with_openrouter(self, envelope: StagingEnvelope) -> Optional[AISeverityAssessment]:
        endpoint = f"{OPENROUTER_BASE_URL.rstrip('/')}/chat/completions"
        snippet = envelope.Raw_Content[:1500].strip()

        user_content = (
            f"Title: {envelope.Title}\n"
            f"Target: {envelope.Vendor_Product or 'Unspecified'}\n"
            f"CVE ID: {envelope.CVE_ID or 'N/A'}\n"
            f"Source Type: {envelope.Source_Type.value}\n\n"
            f"Technical Description / Advisory Context:\n{snippet}\n"
        )

        headers = {
            "Authorization": f"Bearer {self.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/P1nkd0nut/ITP-2-Newsletter",
            "X-Title": "GroundedCVE",
        }

        payload = {
            "model": self.openrouter_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }

        resp = requests.post(endpoint, json=payload, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            parsed = json.loads(content)
            score = float(parsed.get("severity_score", 5.0))
            score = max(0.0, min(10.0, round(score, 1)))

            return AISeverityAssessment(
                severity_score=score,
                offensive_impact=str(parsed.get("offensive_impact", "Exploit Primitive")),
                exploitability=str(parsed.get("exploitability", "MEDIUM")).upper(),
                reasoning=str(parsed.get("reasoning", "Assessed by OpenRouter Qwen 2.5 72B.")),
                evaluated_by=f"openrouter/{self.openrouter_model}",
            )
        else:
            logger.warning(f"OpenRouter returned status {resp.status_code}: {resp.text}")
        return None

    def _evaluate_with_ollama(self, envelope: StagingEnvelope) -> Optional[AISeverityAssessment]:
        endpoint = f"{self.ollama_host}/api/generate"
        snippet = envelope.Raw_Content[:1200].strip()

        user_content = (
            f"Title: {envelope.Title}\n"
            f"Target: {envelope.Vendor_Product or 'Unspecified'}\n"
            f"CVE ID: {envelope.CVE_ID or 'N/A'}\n"
            f"Source Type: {envelope.Source_Type.value}\n\n"
            f"Technical Description / Advisory Context:\n{snippet}\n"
        )

        payload = {
            "model": self.model_name,
            "system": SYSTEM_PROMPT,
            "prompt": user_content,
            "format": "json",
            "stream": False,
            "options": {
                "temperature": 0.1,  # Low temperature for deterministic scoring
                "num_ctx": 4096,
            },
        }

        resp = requests.post(endpoint, json=payload, timeout=12)
        if resp.status_code == 200:
            raw_response = resp.json().get("response", "")
            data = json.loads(raw_response)
            score = float(data.get("severity_score", 5.0))
            score = max(0.0, min(10.0, round(score, 1)))

            return AISeverityAssessment(
                severity_score=score,
                offensive_impact=str(data.get("offensive_impact", "Exploit Primitive")),
                exploitability=str(data.get("exploitability", "MEDIUM")).upper(),
                reasoning=str(data.get("reasoning", "Assessed by local LLM based on technical disclosure mechanics.")),
                evaluated_by=f"ollama/{self.model_name}",
            )
        return None

    def _evaluate_heuristic(self, envelope: StagingEnvelope) -> AISeverityAssessment:
        """
        Rule-based offensive heuristic evaluator when local Ollama is not available.
        Weights practical exploit mechanisms over theoretical bugs.
        """
        text = f"{envelope.Title} {envelope.Raw_Content}".lower()

        def mentions(terms) -> bool:
            # Whole-word match so short terms like "rce" or "cors" don't fire inside "resource" or "scorsese"
            return any(re.search(rf"\b{re.escape(term)}\b", text) for term in terms)

        # Critical impact tier (RCE, Auth Bypass, Remote Injection)
        if mentions([
            "remote code execution", "rce", "arbitrary command", "command injection",
            "authentication bypass", "auth bypass", "account takeover", "privilege escalation",
            "heap overflow", "buffer overflow", "pre-auth"
        ]):
            return AISeverityAssessment(
                severity_score=9.5,
                offensive_impact="Remote Code Execution / Critical Control Bypass",
                exploitability="CRITICAL",
                reasoning="Advisory contains severe offensive primitives allowing arbitrary execution or total auth bypass.",
                evaluated_by="heuristic_engine",
            )

        # High impact tier (SSRF, SQLi, Intent Hijacking, Memory Corruption)
        if mentions([
            "sql injection", "sqli", "ssrf", "server-side request forgery",
            "insecure deserialization", "intent hijacking", "hooking bypass",
            "webview", "path traversal", "directory traversal", "file upload"
        ]):
            return AISeverityAssessment(
                severity_score=8.0,
                offensive_impact="Server-Side Attack / Data Exfiltration Primitive",
                exploitability="HIGH",
                reasoning="Enables high-impact offensive vectors including internal network pivoting or sensitive data exfiltration.",
                evaluated_by="heuristic_engine",
            )

        # Medium impact tier (XSS, CSRF, Token Leaks)
        if mentions([
            "cross-site scripting", "xss", "csrf", "cross-site request forgery",
            "information disclosure", "token leak", "cors", "open redirect"
        ]):
            return AISeverityAssessment(
                severity_score=6.0,
                offensive_impact="Client-Side Injection / Session Hijacking",
                exploitability="MEDIUM",
                reasoning="Provides exploitable client-side interaction primitives requiring user engagement.",
                evaluated_by="heuristic_engine",
            )

        # Low impact tier (DoS, Local memory leak)
        return AISeverityAssessment(
            severity_score=3.5,
            offensive_impact="Denial of Service / Constrained Execution",
            exploitability="LOW",
            reasoning="Flaw is constrained to local interruption or resource exhaustion with minimal offensive control gain.",
            evaluated_by="heuristic_engine",
        )
