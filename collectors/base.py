from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class ThreatItem:
    source: str
    source_category: str
    title: str
    url: str
    summary: str = ""
    published_at: str = ""
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        basis = (self.url or "") + "|" + (self.title or "")
        return hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Collector:
    """Base class for all collectors."""

    def __init__(self, name: str, url: str, category: str, **kwargs: Any) -> None:
        self.name = name
        self.url = url
        self.category = category
        self.options = kwargs

    def collect(self) -> list[ThreatItem]:
        raise NotImplementedError
