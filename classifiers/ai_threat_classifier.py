from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Any

log = logging.getLogger(__name__)


AI_THREAT_CATEGORIES = [
    "Prompt Injection",
    "Sensitive Information Disclosure",
    "AI Supply Chain",
    "Tool Poisoning / MCP Risk",
    "Data or Model Poisoning",
    "AI-generated Code Vulnerability",
    "Agent Excessive Agency",
    "RAG / Vector DB Risk",
    "AI-enabled Phishing",
    "AI-assisted Vulnerability Exploitation",
    "Other Security",
    "Not AI-related",
]

SEVERITIES = ("Low", "Medium", "High", "Critical")


@dataclass
class AIClassification:
    category: str = "Other Security"
    severity: str = "Low"
    summary: str = ""
    is_ai_related: bool = False
    classifier_used: str = "rule-based"
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Classifier:
    name = "base"

    def classify(self, title: str, body: str) -> AIClassification:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Rule-based classifier
# --------------------------------------------------------------------------- #


_CATEGORY_RULES: list[tuple[str, list[str]]] = [
    (
        "Prompt Injection",
        [
            "prompt injection",
            "indirect prompt",
            "jailbreak",
            "system prompt leak",
            "prompt leak",
        ],
    ),
    (
        "Tool Poisoning / MCP Risk",
        [
            "mcp",
            "model context protocol",
            "tool poisoning",
            "malicious tool",
            "rogue tool",
        ],
    ),
    (
        "Agent Excessive Agency",
        [
            "agent",
            "excessive agency",
            "autonomous agent",
            "agentic",
            "tool calling abuse",
        ],
    ),
    (
        "AI Supply Chain",
        [
            "ai supply chain",
            "model supply chain",
            "huggingface",
            "hugging face",
            "model registry",
            "pickle deserialization",
            "malicious model",
            "poisoned model",
        ],
    ),
    (
        "Data or Model Poisoning",
        [
            "data poisoning",
            "model poisoning",
            "training data poison",
            "backdoor model",
        ],
    ),
    (
        "RAG / Vector DB Risk",
        [
            "rag",
            "retrieval augmented",
            "vector database",
            "vector db",
            "embedding poisoning",
        ],
    ),
    (
        "Sensitive Information Disclosure",
        [
            "data leak",
            "credential leak",
            "credential theft",
            "token leak",
            "secret leak",
            "information disclosure",
            "exfiltrat",
        ],
    ),
    (
        "AI-generated Code Vulnerability",
        [
            "ai-generated code",
            "copilot generated",
            "llm generated code",
            "insecure code suggestion",
        ],
    ),
    (
        "AI-enabled Phishing",
        [
            "ai phishing",
            "deepfake",
            "voice clone",
            "ai-generated phishing",
            "llm phishing",
        ],
    ),
    (
        "AI-assisted Vulnerability Exploitation",
        [
            "ai-assisted exploit",
            "llm exploit",
            "automated exploit generation",
            "ai discovered vulnerability",
        ],
    ),
]

_AI_KEYWORDS = {
    "ai", "llm", "gpt", "openai", "anthropic", "claude", "gemini",
    "copilot", "chatgpt", "mcp", "agent", "agentic",
    "machine learning", "neural", "model context protocol",
    "rag", "vector db", "huggingface", "hugging face",
}

_CRITICAL_KEYWORDS = (
    "remote code execution", " rce", "actively exploited", "exploited in the wild",
    "zero-day", "0-day", "wormable",
)
_HIGH_KEYWORDS = (
    "critical vulnerability", "credential theft", "credential leak",
    "data leak", "data breach", "supply chain attack",
    "privilege escalation", "authentication bypass",
)
_MEDIUM_KEYWORDS = (
    "vulnerability", "advisory", "exploit", "patch", "security update",
    "misconfiguration",
)


def _contains_any(text: str, words: tuple[str, ...] | list[str]) -> bool:
    return any(w in text for w in words)


class RuleBasedClassifier(Classifier):
    name = "rule-based"

    def classify(self, title: str, body: str) -> AIClassification:
        blob = f"{title}\n{body}".lower()
        category = None
        for cat, keywords in _CATEGORY_RULES:
            if any(k in blob for k in keywords):
                category = cat
                break

        is_ai = bool(category) or any(re.search(rf"\b{re.escape(k)}\b", blob) for k in _AI_KEYWORDS)
        if not category:
            category = "Other Security" if not is_ai else "Other Security"

        if _contains_any(blob, _CRITICAL_KEYWORDS):
            severity = "Critical"
        elif _contains_any(blob, _HIGH_KEYWORDS):
            severity = "High"
        elif _contains_any(blob, _MEDIUM_KEYWORDS):
            severity = "Medium"
        else:
            severity = "Low"

        summary = (body or title)[:400].strip()

        return AIClassification(
            category=category,
            severity=severity,
            summary=summary,
            is_ai_related=is_ai,
            classifier_used=self.name,
            raw={"matched_keywords": []},
        )


# --------------------------------------------------------------------------- #
# Claude (Anthropic) classifier
# --------------------------------------------------------------------------- #


_CLAUDE_SYSTEM_PROMPT = """You are an AI security analyst.
Classify the given threat intelligence item into EXACTLY ONE of these categories:
- Prompt Injection
- Sensitive Information Disclosure
- AI Supply Chain
- Tool Poisoning / MCP Risk
- Data or Model Poisoning
- AI-generated Code Vulnerability
- Agent Excessive Agency
- RAG / Vector DB Risk
- AI-enabled Phishing
- AI-assisted Vulnerability Exploitation
- Other Security
- Not AI-related

Return ONLY a JSON object with these exact keys (no markdown, no commentary):
{
  "category": "<one of the categories above>",
  "severity": "Low|Medium|High|Critical",
  "summary": "<<=400 chars, plain text, English>",
  "is_ai_related": true|false
}
"""


class ClaudeClassifier(Classifier):
    name = "claude"

    def __init__(self, api_key: str | None = None, model: str = "claude-haiku-4-5-20251001") -> None:
        try:
            import anthropic  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("anthropic package not installed") from exc
        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self._model = model
        self._fallback = RuleBasedClassifier()

    def classify(self, title: str, body: str) -> AIClassification:
        user_msg = f"Title: {title}\n\nContent:\n{body[:6000]}"
        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=512,
                system=_CLAUDE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
            )
            text_parts = []
            for block in resp.content:
                text = getattr(block, "text", None)
                if text:
                    text_parts.append(text)
            raw_text = "".join(text_parts).strip()
            data = _parse_json_block(raw_text)
        except Exception as exc:  # noqa: BLE001
            log.warning("Claude classification failed, falling back: %s", exc)
            return self._fallback.classify(title, body)

        category = data.get("category", "Other Security")
        if category not in AI_THREAT_CATEGORIES:
            category = "Other Security"
        severity = data.get("severity", "Low")
        if severity not in SEVERITIES:
            severity = "Low"
        summary = str(data.get("summary") or "")[:400]
        is_ai = bool(data.get("is_ai_related", category not in ("Other Security", "Not AI-related")))

        return AIClassification(
            category=category,
            severity=severity,
            summary=summary,
            is_ai_related=is_ai,
            classifier_used=self.name,
            raw=data,
        )


_JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)


def _parse_json_block(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = _JSON_OBJ_RE.search(text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return {}


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #


def build_classifier(mode: str | None = None) -> Classifier:
    """Build classifier. Mode resolution order: arg > env > default(rule-based)."""
    chosen = (mode or os.environ.get("THREAT_WATCH_CLASSIFIER") or "rule-based").strip().lower()
    if chosen in ("claude", "anthropic"):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            log.warning("ANTHROPIC_API_KEY not set; using rule-based classifier")
            return RuleBasedClassifier()
        try:
            return ClaudeClassifier()
        except Exception as exc:  # noqa: BLE001
            log.warning("Failed to init Claude classifier (%s); using rule-based", exc)
            return RuleBasedClassifier()
    return RuleBasedClassifier()
