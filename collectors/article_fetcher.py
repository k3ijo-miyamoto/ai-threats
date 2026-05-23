"""Best-effort article body fetching using trafilatura.

Not all sources benefit equally. We use it on RSS items where the summary
is short (often <500 chars) to improve downstream classification quality.
Failures are non-fatal — the original summary is preserved.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

log = logging.getLogger(__name__)


class ArticleFetcher:
    REQUEST_TIMEOUT = 20
    USER_AGENT = "AIThreatWatch/0.1 (+https://example.invalid)"

    def __init__(self, min_summary_length: int = 500, max_body_chars: int = 6000) -> None:
        self.min_summary_length = min_summary_length
        self.max_body_chars = max_body_chars
        self._extract = self._load_extractor()
        self._cache: dict[str, str] = {}

    def _load_extractor(self) -> Any | None:
        try:
            import trafilatura  # type: ignore

            def _extract(html: str, url: str) -> str:
                # favor_precision = False to err on the side of more content for AI classifier
                return trafilatura.extract(
                    html,
                    url=url,
                    favor_recall=True,
                    include_comments=False,
                    include_tables=False,
                ) or ""

            return _extract
        except ImportError:  # pragma: no cover
            log.warning("trafilatura not installed; article fetching disabled")
            return None

    def should_fetch(self, url: str, current_summary: str) -> bool:
        if not self._extract or not url:
            return False
        if len(current_summary or "") >= self.min_summary_length:
            return False
        # URLs pointing to a section anchor of a larger digest page (e.g.
        # JPCERT Weekly Report wr260520.html#3) all resolve to the same HTML,
        # so trafilatura returns the entire bulletin for each sub-item. That
        # cross-contaminates per-item summaries (every PostgreSQL/MongoDB/etc.
        # entry ends up describing all the other products too). Skip.
        if "#" in url:
            return False
        # Skip API endpoints (already structured), Twitter/X links, video sites, etc.
        lowered = url.lower()
        skip_hosts = (
            "api.github.com",
            "github.com/advisories/",  # advisory page is content-light; rely on API data
            "twitter.com", "x.com",
            "youtube.com", "youtu.be",
        )
        return not any(h in lowered for h in skip_hosts)

    def fetch(self, url: str) -> str:
        if not self._extract or not url:
            return ""
        if url in self._cache:
            return self._cache[url]
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": self.USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
                timeout=self.REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            resp.raise_for_status()
            body = self._extract(resp.text, url) or ""
        except requests.RequestException as exc:
            log.debug("article fetch failed for %s: %s", url, exc)
            body = ""
        except Exception as exc:  # noqa: BLE001 — trafilatura can raise odd parser errors
            log.debug("article extract failed for %s: %s", url, exc)
            body = ""

        body = body[: self.max_body_chars]
        self._cache[url] = body
        return body

    def enrich_summary(self, url: str, summary: str) -> str:
        """Return a possibly-extended summary.

        If we can fetch a longer article body, append it to the original summary
        (separated by a marker) so the classifier sees both. We preserve the
        original because some feeds (e.g., CISA) already have curated text.
        """
        if not self.should_fetch(url, summary):
            return summary
        body = self.fetch(url)
        if not body or len(body) <= len(summary or ""):
            return summary
        if summary:
            return f"{summary}\n\n---\n{body}"
        return body
