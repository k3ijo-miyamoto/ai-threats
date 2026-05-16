"""Tests for RuleBasedClassifier. No external API calls."""

from __future__ import annotations

from classifiers import RuleBasedClassifier


class TestRuleBasedCategorization:
    def setup_method(self):
        self.clf = RuleBasedClassifier()

    def test_prompt_injection_detection(self):
        r = self.clf.classify(
            "New prompt injection bypass discovered",
            "A new technique allows prompt injection to break out of system prompts.",
        )
        assert r.category == "Prompt Injection"
        assert r.is_ai_related is True

    def test_mcp_tool_poisoning(self):
        r = self.clf.classify(
            "Malicious MCP server steals credentials",
            "Tool poisoning attack via Model Context Protocol",
        )
        assert r.category == "Tool Poisoning / MCP Risk"
        assert r.is_ai_related is True

    def test_unrelated_security_not_misclassified_as_prompt_injection(self):
        r = self.clf.classify(
            "Windows kernel patch released",
            "Standard kernel vulnerability fixed in May update.",
        )
        assert r.category != "Prompt Injection"

    def test_severity_critical_on_active_exploitation(self):
        r = self.clf.classify(
            "Critical remote code execution",
            "Actively exploited in the wild; RCE possible.",
        )
        assert r.severity == "Critical"

    def test_severity_high_on_credential_leak(self):
        r = self.clf.classify(
            "Token leak in service",
            "Credential leak via API endpoint.",
        )
        assert r.severity in ("High", "Critical")

    def test_classifier_used_field(self):
        r = self.clf.classify("Anything", "anything")
        assert r.classifier_used == "rule-based"
