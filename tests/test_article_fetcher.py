"""Article fetcher tests (no network — only should_fetch logic)."""

from __future__ import annotations

from collectors import ArticleFetcher


class TestShouldFetch:
    def setup_method(self):
        self.f = ArticleFetcher(min_summary_length=500)

    def test_skips_when_summary_long(self):
        long_summary = "x" * 600
        assert self.f.should_fetch("https://example.com", long_summary) is False

    def test_fetches_when_summary_short(self):
        assert self.f.should_fetch("https://example.com", "short") is True

    def test_skips_github_advisory(self):
        assert self.f.should_fetch(
            "https://github.com/advisories/GHSA-xxxx-yyyy", "short"
        ) is False

    def test_skips_github_api(self):
        assert self.f.should_fetch("https://api.github.com/foo", "short") is False

    def test_skips_twitter(self):
        assert self.f.should_fetch("https://twitter.com/foo/status/1", "short") is False
        assert self.f.should_fetch("https://x.com/foo/status/1", "short") is False

    def test_skips_youtube(self):
        assert self.f.should_fetch("https://youtube.com/watch?v=abc", "short") is False
        assert self.f.should_fetch("https://youtu.be/abc", "short") is False

    def test_no_url_returns_false(self):
        assert self.f.should_fetch("", "short") is False
