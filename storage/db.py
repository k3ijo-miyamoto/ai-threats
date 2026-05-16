from __future__ import annotations

import csv
import json
import logging
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger(__name__)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_register (
    threat_id        TEXT PRIMARY KEY,
    fingerprint      TEXT UNIQUE NOT NULL,
    collected_at     TEXT NOT NULL,
    published_at     TEXT,
    source           TEXT NOT NULL,
    source_category  TEXT,
    title            TEXT NOT NULL,
    url              TEXT NOT NULL,
    summary          TEXT,
    category         TEXT,
    severity         TEXT,
    company_impact   TEXT,
    affected_asset   TEXT,
    reason           TEXT,
    recommended_action TEXT,
    priority         TEXT,
    classifier_used  TEXT,
    is_ai_related    INTEGER,
    status           TEXT NOT NULL DEFAULT 'New',
    notified         INTEGER NOT NULL DEFAULT 0,
    extra_json       TEXT
);

CREATE INDEX IF NOT EXISTS idx_threat_collected_at ON threat_register(collected_at);
CREATE INDEX IF NOT EXISTS idx_threat_priority    ON threat_register(priority);
CREATE INDEX IF NOT EXISTS idx_threat_status      ON threat_register(status);
"""


@dataclass
class ThreatRecord:
    threat_id: str
    fingerprint: str
    collected_at: str
    published_at: str
    source: str
    source_category: str
    title: str
    url: str
    summary: str
    category: str
    severity: str
    company_impact: str
    affected_asset: str
    reason: str
    recommended_action: str
    priority: str
    classifier_used: str
    is_ai_related: bool
    status: str = "New"
    notified: bool = False
    extra: dict[str, Any] | None = None

    def to_row(self) -> dict[str, Any]:
        d = asdict(self)
        d["is_ai_related"] = 1 if self.is_ai_related else 0
        d["notified"] = 1 if self.notified else 0
        d["extra_json"] = json.dumps(self.extra or {}, ensure_ascii=False)
        d.pop("extra", None)
        return d


CSV_FIELDS = [
    "threat_id", "collected_at", "published_at", "source", "source_category",
    "title", "url", "summary", "category", "severity",
    "company_impact", "affected_asset", "reason", "recommended_action",
    "priority", "classifier_used", "is_ai_related", "status",
]


class ThreatRegister:
    """SQLite-backed AI Threat Register with CSV mirror."""

    def __init__(self, sqlite_path: str | Path, csv_path: str | Path | None = None) -> None:
        self.sqlite_path = Path(sqlite_path)
        self.csv_path = Path(csv_path) if csv_path else None
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------------ #

    def fingerprint_exists(self, fingerprint: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT 1 FROM threat_register WHERE fingerprint = ? LIMIT 1",
                (fingerprint,),
            )
            return cur.fetchone() is not None

    def next_threat_id(self) -> str:
        with self._connect() as conn:
            cur = conn.execute("SELECT COUNT(*) AS n FROM threat_register")
            n = cur.fetchone()["n"]
        return f"AI-THREAT-{n + 1:04d}"

    def insert(self, record: ThreatRecord) -> bool:
        row = record.to_row()
        cols = ",".join(row.keys())
        placeholders = ",".join(["?"] * len(row))
        try:
            with self._connect() as conn:
                conn.execute(
                    f"INSERT INTO threat_register ({cols}) VALUES ({placeholders})",
                    list(row.values()),
                )
                conn.commit()
            return True
        except sqlite3.IntegrityError as exc:
            log.debug("Duplicate insert skipped (%s): %s", record.fingerprint, exc)
            return False

    def mark_notified(self, threat_ids: list[str]) -> None:
        if not threat_ids:
            return
        placeholders = ",".join(["?"] * len(threat_ids))
        with self._connect() as conn:
            conn.execute(
                f"UPDATE threat_register SET notified = 1 WHERE threat_id IN ({placeholders})",
                threat_ids,
            )
            conn.commit()

    def recent(self, since_iso: str | None = None, limit: int = 500) -> list[sqlite3.Row]:
        with self._connect() as conn:
            if since_iso:
                cur = conn.execute(
                    "SELECT * FROM threat_register WHERE collected_at >= ? "
                    "ORDER BY collected_at DESC LIMIT ?",
                    (since_iso, limit),
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM threat_register ORDER BY collected_at DESC LIMIT ?",
                    (limit,),
                )
            return list(cur.fetchall())

    def pending_notifications(self, priorities: tuple[str, ...] = ("High",)) -> list[sqlite3.Row]:
        placeholders = ",".join(["?"] * len(priorities))
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT * FROM threat_register "
                f"WHERE notified = 0 AND priority IN ({placeholders}) "
                f"ORDER BY collected_at DESC",
                priorities,
            )
            return list(cur.fetchall())

    def export_csv(self) -> None:
        if not self.csv_path:
            return
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            cur = conn.execute(
                f"SELECT {', '.join(CSV_FIELDS)} FROM threat_register ORDER BY collected_at DESC"
            )
            rows = cur.fetchall()
        with self.csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r[k] for k in CSV_FIELDS})

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS n FROM threat_register").fetchone()["n"]
            by_priority = {
                r["priority"]: r["n"]
                for r in conn.execute(
                    "SELECT priority, COUNT(*) AS n FROM threat_register GROUP BY priority"
                ).fetchall()
            }
            by_impact = {
                r["company_impact"]: r["n"]
                for r in conn.execute(
                    "SELECT company_impact, COUNT(*) AS n FROM threat_register GROUP BY company_impact"
                ).fetchall()
            }
        return {"total": total, "by_priority": by_priority, "by_company_impact": by_impact}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
