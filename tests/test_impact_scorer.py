"""Priority-decision tests for ImpactScorer.

The priority function has multiple branches (AI-relevance gate, asset-match
exception, KEV/EPSS upgrade). These tests pin down the matrix.
"""

from __future__ import annotations

import pytest

from classifiers import ImpactScorer


def _score(scorer, **kwargs):
    """Helper to build a score with sensible defaults."""
    defaults = {
        "title": "Test title",
        "body": "Test body",
        "category": "Other Security",
        "severity": "Medium",
        "is_ai_related": True,
    }
    defaults.update(kwargs)
    return scorer.score(**defaults)


# ---------------------------------------------------------------------------
# Word-boundary keyword matching
# ---------------------------------------------------------------------------


class TestKeywordMatching:
    def test_rag_does_not_match_storage(self, sample_company_cfg):
        sample_company_cfg["company_ai_assets"].append({
            "name": "RAG Knowledge Base",
            "category": "rag",
            "keywords": ["rag"],
            "risk_level": "medium",
        })
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(scorer, title="Laravel Storage path traversal", body="storage bug")
        assert d.company_impact != "Yes", "'storage' must not match keyword 'rag'"

    def test_copilot_matches_keyword(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(scorer, title="GitHub Copilot leaks repo data", body="...")
        assert d.company_impact == "Yes"
        assert "Copilot" in d.affected_asset


# ---------------------------------------------------------------------------
# Priority matrix
# ---------------------------------------------------------------------------


class TestPriorityMatrix:
    """Verify each branch of _priority."""

    def test_company_asset_yes_severity_high_is_high(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(scorer, title="GitHub Copilot bug", severity="High")
        assert d.company_impact == "Yes"
        assert d.priority == "High"

    def test_company_asset_yes_severity_low_is_medium(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(scorer, title="Copilot minor issue", severity="Low")
        assert d.company_impact == "Yes"
        assert d.priority == "Medium"

    def test_non_ai_critical_capped_at_medium(self, sample_company_cfg):
        """Non-AI Critical without asset match must NOT be High."""
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="Siemens industrial control RCE",
            body="Some non-AI critical bug",
            category="Other Security",
            severity="Critical",
            is_ai_related=False,
        )
        assert d.priority == "Medium", "AI-gate should cap non-AI at Medium"

    def test_ai_critical_is_high(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="Prompt injection RCE in agent framework",
            body="Critical AI flaw",
            category="Prompt Injection",
            severity="Critical",
            is_ai_related=True,
        )
        assert d.priority == "High"

    def test_ai_unknown_with_high_risk_category_is_high(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="Some agent tool issue",
            body="...",
            category="Tool Poisoning / MCP Risk",
            severity="Medium",
            is_ai_related=True,
        )
        # Unknown impact + high-risk category → High
        assert d.company_impact == "Unknown"
        assert d.priority == "High"

    def test_ai_unknown_severity_high_is_high(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="AI-relevant flaw",
            body="...",
            category="AI-generated Code Vulnerability",
            severity="High",
        )
        assert d.priority == "High"

    def test_non_ai_low_is_low(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="Generic library bug",
            severity="Low",
            is_ai_related=False,
            category="Other Security",
        )
        assert d.priority == "Low"


# ---------------------------------------------------------------------------
# KEV / EPSS upgrade
# ---------------------------------------------------------------------------


class TestKEVEPSS:
    def test_kev_makes_unknown_ai_high(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="AI Supply Chain CVE",
            body="...",
            category="AI Supply Chain",
            severity="Medium",
            is_ai_related=True,
            in_kev=True,
        )
        assert d.priority == "High"
        assert "KEV" in d.reason

    def test_high_epss_makes_unknown_ai_high(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="AI Supply Chain CVE",
            category="AI Supply Chain",
            severity="Medium",
            is_ai_related=True,
            epss_score=0.85,
        )
        assert d.priority == "High"
        assert "EPSS" in d.reason

    def test_low_epss_does_not_upgrade(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="AI Supply Chain CVE",
            category="AI Supply Chain",
            severity="Medium",
            is_ai_related=True,
            epss_score=0.1,
        )
        # AI + high_risk_category → Unknown already gets bumped to High
        # We just verify EPSS itself didn't fabricate the upgrade.
        assert "EPSS" not in d.reason

    def test_kev_on_non_ai_still_capped_unless_asset_match(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="KEV-listed non-AI Critical",
            body="Industrial control RCE",
            category="Other Security",
            severity="Critical",
            is_ai_related=False,
            in_kev=True,
        )
        # Non-AI items still capped at Medium (theme stays AI)
        assert d.priority == "Medium"


# ---------------------------------------------------------------------------
# Reason field
# ---------------------------------------------------------------------------


class TestReason:
    def test_reason_mentions_asset_when_matched(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(scorer, title="Copilot affected", severity="High")
        assert "Copilot" in d.reason

    def test_reason_mentions_kev_when_set(self, sample_company_cfg):
        scorer = ImpactScorer(sample_company_cfg)
        d = _score(
            scorer,
            title="AI Supply Chain bug",
            category="AI Supply Chain",
            severity="Medium",
            in_kev=True,
        )
        assert "KEV" in d.reason
