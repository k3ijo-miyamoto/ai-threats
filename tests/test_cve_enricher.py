"""CVE extraction tests. Pure regex, no network."""

from __future__ import annotations

from classifiers.cve_enricher import CVEEnricher


class TestExtractCVEs:
    def test_extracts_standard_cve(self):
        cves = CVEEnricher.extract_cves("Patch for CVE-2024-3094 released")
        assert cves == ["CVE-2024-3094"]

    def test_case_insensitive(self):
        cves = CVEEnricher.extract_cves("cve-2024-3094 affects xz")
        assert cves == ["CVE-2024-3094"]

    def test_multiple_cves_deduplicated(self):
        cves = CVEEnricher.extract_cves(
            "See CVE-2024-3094 and CVE-2023-44487",
            "Also relates to CVE-2024-3094",  # duplicate
        )
        assert cves == ["CVE-2024-3094", "CVE-2023-44487"]

    def test_no_match_returns_empty(self):
        assert CVEEnricher.extract_cves("nothing here") == []

    def test_ignores_partial_strings(self):
        # CVE-12345 without proper year is not valid
        cves = CVEEnricher.extract_cves("CVE-12345 invalid format")
        assert cves == []

    def test_supports_7_digit_numbers(self):
        # Modern CVE IDs can have up to 7 digits
        cves = CVEEnricher.extract_cves("CVE-2024-1234567 found")
        assert cves == ["CVE-2024-1234567"]

    def test_handles_none_input(self):
        cves = CVEEnricher.extract_cves(None, "", "CVE-2024-3094")
        assert cves == ["CVE-2024-3094"]

    def test_word_boundary_does_not_match_inside_word(self):
        # E.g., "ACVE-2024-3094B" should NOT match (no word boundary)
        cves = CVEEnricher.extract_cves("xCVE-2024-3094 weird")
        # \b at start of "CVE" still matches since "x" is followed by uppercase C
        # which is a word-char boundary transition... actually no, both word chars.
        # The regex \bCVE-... will not match because there's no transition between x and C.
        assert cves == []
