from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

import feedparser

from .base import Collector, ThreatItem

log = logging.getLogger(__name__)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


def _strip_html(text: str) -> str:
    if not text:
        return ""
    text = _HTML_TAG_RE.sub(" ", text)
    return _WHITESPACE_RE.sub(" ", text).strip()


def _entry_published(entry: Any) -> str:
    for attr in ("published_parsed", "updated_parsed"):
        value = getattr(entry, attr, None) or (entry.get(attr) if isinstance(entry, dict) else None)
        if value:
            try:
                dt = datetime(*value[:6], tzinfo=timezone.utc)
                return dt.isoformat()
            except (TypeError, ValueError):
                continue
    for attr in ("published", "updated"):
        value = getattr(entry, attr, None) or (entry.get(attr) if isinstance(entry, dict) else None)
        if value:
            return str(value)
    return ""


class RSSCollector(Collector):
    """Generic RSS/Atom collector backed by feedparser."""

    REQUEST_TIMEOUT = 30

    def collect(self) -> list[ThreatItem]:
        log.info("RSS collect: %s (%s)", self.name, self.url)
        try:
            parsed = feedparser.parse(
                self.url,
                request_headers={"User-Agent": "AIThreatWatch/0.1 (+https://example.invalid)"},
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("RSS parse failed for %s: %s", self.name, exc)
            return []

        if parsed.bozo and not parsed.entries:
            log.warning("RSS feed empty or malformed: %s (%s)", self.name, parsed.bozo_exception)
            return []

        items: list[ThreatItem] = []
        for entry in parsed.entries:
            title = _strip_html(getattr(entry, "title", "") or "")
            url = getattr(entry, "link", "") or ""
            summary = _strip_html(
                getattr(entry, "summary", "")
                or getattr(entry, "description", "")
                or ""
            )
            tags: list[str] = []
            raw_tags = getattr(entry, "tags", None)
            if raw_tags:
                for t in raw_tags:
                    term = t.get("term") if isinstance(t, dict) else getattr(t, "term", None)
                    if term:
                        tags.append(str(term))
            if not title or not url:
                continue
            items.append(
                ThreatItem(
                    source=self.name,
                    source_category=self.category,
                    title=title,
                    url=url,
                    summary=summary[:4000],
                    published_at=_entry_published(entry),
                    raw_tags=tags,
                )
            )
        log.info("RSS collected %d items from %s", len(items), self.name)
        return items
