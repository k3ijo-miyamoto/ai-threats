from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class ImpactDecision:
    company_impact: str  # Yes / No / Unknown
    affected_asset: str
    reason: str
    recommended_action: str
    priority: str  # High / Medium / Low

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _keyword_matches(keyword: str, text: str) -> bool:
    """Word-boundary aware keyword match.

    Multi-word keywords (containing spaces) use simple substring match because
    word-boundary regex on the full phrase is equivalent. Single tokens use
    \\b...\\b so e.g. 'rag' does not match 'storage' or 'fragment'.
    """
    kw = keyword.strip()
    if not kw:
        return False
    if " " in kw:
        return kw in text
    return re.search(rf"\b{re.escape(kw)}\b", text) is not None


_DEFAULT_ACTIONS = {
    "Prompt Injection": "Review affected AI tools' tool-execution boundaries and untrusted input handling.",
    "Tool Poisoning / MCP Risk": "Audit installed MCP servers and tool configurations; verify provenance.",
    "Agent Excessive Agency": "Review agent permissions/scopes and ensure human-in-the-loop where needed.",
    "AI Supply Chain": "Verify model/package provenance, pin versions, and scan for known compromised artifacts.",
    "Data or Model Poisoning": "Validate training data sources and integrity controls.",
    "AI-generated Code Vulnerability": "Run SAST on AI-generated code paths; review code-review policy.",
    "RAG / Vector DB Risk": "Audit RAG ingestion pipeline and vector store access controls.",
    "Sensitive Information Disclosure": "Review data handling, DLP coverage, and logging of AI interactions.",
    "AI-enabled Phishing": "Update phishing awareness training and detection rules.",
    "AI-assisted Vulnerability Exploitation": "Accelerate patching cadence for surface mentioned in advisory.",
    "Other Security": "Triage per standard vulnerability management process.",
    "Not AI-related": "No specific AI action required; route to general security triage.",
}


class ImpactScorer:
    def __init__(self, company_config: dict[str, Any]) -> None:
        self._assets: list[dict[str, Any]] = company_config.get("company_ai_assets") or []
        self._high_risk_categories: set[str] = set(
            company_config.get("high_risk_categories") or []
        )
        self._critical_keywords: list[str] = [
            k.lower() for k in (company_config.get("critical_keywords") or [])
        ]

    def score(
        self,
        title: str,
        body: str,
        category: str,
        severity: str,
        is_ai_related: bool = True,
    ) -> ImpactDecision:
        blob = f"{title}\n{body}".lower()
        # Be inclusive: trust the classifier's flag, OR an AI-specific category.
        ai_relevant = bool(is_ai_related) or category not in ("Other Security", "Not AI-related")

        matched_assets: list[dict[str, Any]] = []
        for asset in self._assets:
            keywords = [str(k).lower() for k in (asset.get("keywords") or [])]
            if any(k and _keyword_matches(k, blob) for k in keywords):
                matched_assets.append(asset)

        critical_hit = any(_keyword_matches(k, blob) for k in self._critical_keywords)
        is_high_risk_category = category in self._high_risk_categories

        if matched_assets:
            company_impact = "Yes"
            asset_names = ", ".join(a.get("name", "?") for a in matched_assets)
            reason_parts = [f"Matches company asset(s): {asset_names}."]
            if critical_hit:
                reason_parts.append("Critical keyword detected (e.g., RCE / credential leak / active exploitation).")
            reason = " ".join(reason_parts)
        elif is_high_risk_category or critical_hit:
            company_impact = "Unknown"
            asset_names = ""
            reason = (
                "No direct asset match, but category or wording suggests potential exposure "
                f"(category={category}; critical_keyword={critical_hit})."
            )
        elif category == "Not AI-related":
            company_impact = "No"
            asset_names = ""
            reason = "Not AI-related and no asset match."
        else:
            company_impact = "Unknown"
            asset_names = ""
            reason = "No company asset match; needs human triage to confirm exposure."

        priority = self._priority(
            company_impact, severity, critical_hit, is_high_risk_category, ai_relevant
        )
        action = _DEFAULT_ACTIONS.get(category, "Triage per standard vulnerability management process.")

        return ImpactDecision(
            company_impact=company_impact,
            affected_asset=asset_names,
            reason=reason,
            recommended_action=action,
            priority=priority,
        )

    @staticmethod
    def _priority(
        company_impact: str,
        severity: str,
        critical_hit: bool,
        is_high_risk_category: bool,
        ai_relevant: bool,
    ) -> str:
        """Decide priority. AI-relevance is a near-required condition for High,
        EXCEPT when the item directly matches a company-owned asset
        (company_impact == 'Yes'), where we keep High to avoid missing
        infrastructure-level issues around our AI stack."""

        # 1) Company asset directly affected — AI relevance not required.
        if company_impact == "Yes":
            if severity in ("Critical", "High", "Medium"):
                return "High"
            return "Medium"

        # 2) Non-AI items: cap at Medium regardless of severity.
        if not ai_relevant:
            if severity in ("Critical", "High"):
                return "Medium"
            return "Low"

        # 3) AI-related items without direct asset match.
        if severity == "Critical":
            return "High"
        if company_impact == "Unknown" and (
            severity == "High" or critical_hit or is_high_risk_category
        ):
            return "High"
        if company_impact == "Unknown":
            return "Medium"
        if severity == "High":
            return "Medium"
        return "Low"
