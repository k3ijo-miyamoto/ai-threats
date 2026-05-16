"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure project root is importable when pytest is invoked from anywhere.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture
def tmp_register(tmp_path):
    """Provide a fresh ThreatRegister backed by a temp SQLite/CSV."""
    from storage import ThreatRegister
    return ThreatRegister(
        sqlite_path=tmp_path / "test.sqlite",
        csv_path=tmp_path / "test.csv",
    )


@pytest.fixture
def sample_company_cfg():
    """Minimal company_assets config used by ImpactScorer tests."""
    return {
        "company_ai_assets": [
            {
                "name": "GitHub Copilot Business",
                "category": "coding_ai",
                "keywords": ["github copilot", "copilot"],
                "risk_level": "high",
            },
            {
                "name": "MCP Servers",
                "category": "agent_tools",
                "keywords": ["mcp", "model context protocol"],
                "risk_level": "high",
            },
        ],
        "high_risk_categories": [
            "Prompt Injection",
            "Tool Poisoning / MCP Risk",
            "Agent Excessive Agency",
            "AI Supply Chain",
        ],
        "critical_keywords": [
            "rce",
            "remote code execution",
            "credential theft",
            "active exploitation",
        ],
    }
