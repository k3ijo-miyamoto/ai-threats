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
    extra_json       TEXT,
    tailored_action  TEXT,
    cve_ids          TEXT,
    in_kev           INTEGER NOT NULL DEFAULT 0,
    kev_due_date     TEXT,
    kev_known_ransomware INTEGER NOT NULL DEFAULT 0,
    epss_max_score   REAL NOT NULL DEFAULT 0,
    epss_max_cve     TEXT,
    reviewed_at      TEXT,
    reviewer         TEXT,
    review_note      TEXT,
    corrected_category TEXT,
    iocs_json        TEXT
);

CREATE INDEX IF NOT EXISTS idx_threat_collected_at ON threat_register(collected_at);
CREATE INDEX IF NOT EXISTS idx_threat_priority    ON threat_register(priority);
CREATE INDEX IF NOT EXISTS idx_threat_status      ON threat_register(status);

-- SBOM (Software Bill of Materials) tables. Each SBOM represents one
-- "system" we care about (initially: this threat_watch project itself).
-- Matching an advisory's vulnerable package against any package in any
-- SBOM is a stronger signal than fuzzy keyword matching, because the
-- advisory's `vulnerabilities[].package.name` field is structured data
-- from the advisory creator — no false positive from incidental mentions.
CREATE TABLE IF NOT EXISTS sboms (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT UNIQUE NOT NULL,
    source        TEXT,
    format        TEXT,
    generated_at  TEXT NOT NULL,
    payload       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sbom_packages (
    sbom_id       INTEGER NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    package_name  TEXT NOT NULL,
    version       TEXT,
    ecosystem     TEXT,
    PRIMARY KEY (sbom_id, package_name, version)
);

CREATE INDEX IF NOT EXISTS idx_sbom_packages_name ON sbom_packages(package_name);
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
    tailored_action: str = ""
    cve_ids: str = ""
    in_kev: bool = False
    kev_due_date: str = ""
    kev_known_ransomware: bool = False
    epss_max_score: float = 0.0
    epss_max_cve: str = ""
    reviewed_at: str = ""
    reviewer: str = ""
    review_note: str = ""
    corrected_category: str = ""
    iocs_json: str = ""
    extra: dict[str, Any] | None = None

    def to_row(self) -> dict[str, Any]:
        d = asdict(self)
        d["is_ai_related"] = 1 if self.is_ai_related else 0
        d["notified"] = 1 if self.notified else 0
        d["in_kev"] = 1 if self.in_kev else 0
        d["kev_known_ransomware"] = 1 if self.kev_known_ransomware else 0
        d["extra_json"] = json.dumps(self.extra or {}, ensure_ascii=False)
        d.pop("extra", None)
        return d


CSV_FIELDS = [
    "threat_id", "collected_at", "published_at", "source", "source_category",
    "title", "url", "summary", "category", "severity",
    "company_impact", "affected_asset", "reason", "recommended_action",
    "priority", "classifier_used", "is_ai_related", "status",
    "cve_ids", "in_kev", "kev_due_date", "epss_max_score", "epss_max_cve",
    "reviewer", "reviewed_at", "corrected_category",
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
            # Lightweight migrations for older DBs: add columns introduced later.
            existing = {row["name"] for row in conn.execute("PRAGMA table_info(threat_register)")}
            migrations = (
                ("tailored_action",      "ALTER TABLE threat_register ADD COLUMN tailored_action TEXT"),
                ("cve_ids",              "ALTER TABLE threat_register ADD COLUMN cve_ids TEXT"),
                ("in_kev",               "ALTER TABLE threat_register ADD COLUMN in_kev INTEGER NOT NULL DEFAULT 0"),
                ("kev_due_date",         "ALTER TABLE threat_register ADD COLUMN kev_due_date TEXT"),
                ("kev_known_ransomware", "ALTER TABLE threat_register ADD COLUMN kev_known_ransomware INTEGER NOT NULL DEFAULT 0"),
                ("epss_max_score",       "ALTER TABLE threat_register ADD COLUMN epss_max_score REAL NOT NULL DEFAULT 0"),
                ("epss_max_cve",         "ALTER TABLE threat_register ADD COLUMN epss_max_cve TEXT"),
                ("reviewed_at",          "ALTER TABLE threat_register ADD COLUMN reviewed_at TEXT"),
                ("reviewer",             "ALTER TABLE threat_register ADD COLUMN reviewer TEXT"),
                ("review_note",          "ALTER TABLE threat_register ADD COLUMN review_note TEXT"),
                ("corrected_category",   "ALTER TABLE threat_register ADD COLUMN corrected_category TEXT"),
                ("iocs_json",            "ALTER TABLE threat_register ADD COLUMN iocs_json TEXT"),
            )
            for col, ddl in migrations:
                if col not in existing:
                    conn.execute(ddl)
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

    def cve_already_notified(self, cve_ids: str) -> list[sqlite3.Row]:
        """Return previously-notified rows that share ANY CVE id with cve_ids."""
        if not cve_ids:
            return []
        targets = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
        if not targets:
            return []
        with self._connect() as conn:
            # SQLite has no array overlap; use LIKE for each CVE.
            clauses = " OR ".join(["UPPER(cve_ids) LIKE ?"] * len(targets))
            params = [f"%{c}%" for c in targets]
            cur = conn.execute(
                f"SELECT threat_id, source, title, cve_ids, collected_at "
                f"FROM threat_register WHERE notified = 1 AND ({clauses}) "
                f"ORDER BY collected_at DESC",
                params,
            )
            return list(cur.fetchall())

    def cve_clusters(self, min_size: int = 2) -> list[dict[str, Any]]:
        """Group records by CVE id; returns clusters with >= min_size members."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT threat_id, source, title, cve_ids, priority, severity, "
                "collected_at FROM threat_register WHERE cve_ids != '' AND cve_ids IS NOT NULL"
            )
            rows = cur.fetchall()
        buckets: dict[str, list[sqlite3.Row]] = {}
        for r in rows:
            for cve in (r["cve_ids"] or "").split(","):
                cve = cve.strip().upper()
                if cve:
                    buckets.setdefault(cve, []).append(r)
        clusters: list[dict[str, Any]] = []
        for cve, members in buckets.items():
            if len(members) >= min_size:
                clusters.append({
                    "cve": cve,
                    "members": [dict(m) for m in members],
                    "sources": sorted({m["source"] for m in members}),
                })
        clusters.sort(key=lambda c: (-len(c["members"]), c["cve"]))
        return clusters

    # ------------------------------------------------------------------ #
    # SBOM
    # ------------------------------------------------------------------ #

    def upsert_sbom(
        self,
        *,
        name: str,
        source: str,
        format: str,
        payload: str,
        packages: list[tuple[str, str, str]],
    ) -> int:
        """Replace any existing SBOM with the same name and store the new one.

        packages is a list of (package_name, version, ecosystem) tuples.
        Package names are stored lowercased so matching is case-insensitive.
        Returns the sbom id.
        """
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute("SELECT id FROM sboms WHERE name = ?", (name,))
            row = cur.fetchone()
            if row:
                sbom_id = int(row["id"])
                conn.execute(
                    "UPDATE sboms SET source=?, format=?, generated_at=?, payload=? WHERE id=?",
                    (source, format, now, payload, sbom_id),
                )
                conn.execute("DELETE FROM sbom_packages WHERE sbom_id = ?", (sbom_id,))
            else:
                cur = conn.execute(
                    "INSERT INTO sboms (name, source, format, generated_at, payload) VALUES (?, ?, ?, ?, ?)",
                    (name, source, format, now, payload),
                )
                sbom_id = int(cur.lastrowid)
            seen: set[tuple[str, str]] = set()
            for pkg, ver, eco in packages:
                key = (pkg.lower(), ver or "")
                if key in seen:
                    continue
                seen.add(key)
                conn.execute(
                    "INSERT OR IGNORE INTO sbom_packages (sbom_id, package_name, version, ecosystem) VALUES (?, ?, ?, ?)",
                    (sbom_id, pkg.lower(), ver, eco),
                )
            conn.commit()
        return sbom_id

    def list_sboms(self) -> list[sqlite3.Row]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT s.id, s.name, s.source, s.format, s.generated_at, "
                "(SELECT COUNT(*) FROM sbom_packages WHERE sbom_id = s.id) AS package_count "
                "FROM sboms s ORDER BY s.name"
            )
            return list(cur.fetchall())

    def get_sbom_packages(self, name: str) -> list[sqlite3.Row]:
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT p.package_name, p.version, p.ecosystem "
                "FROM sbom_packages p JOIN sboms s ON p.sbom_id = s.id "
                "WHERE s.name = ? ORDER BY p.package_name",
                (name,),
            )
            return list(cur.fetchall())

    def sbom_package_index(self) -> dict[str, list[str]]:
        """Return {package_name_lower: [sbom_name, ...]} for impact_scorer lookups."""
        index: dict[str, list[str]] = {}
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT s.name AS sbom_name, p.package_name "
                "FROM sbom_packages p JOIN sboms s ON p.sbom_id = s.id"
            )
            for row in cur.fetchall():
                index.setdefault(row["package_name"], []).append(row["sbom_name"])
        return index

    # ------------------------------------------------------------------ #

    def kev_due_within(self, days: int = 7) -> list[sqlite3.Row]:
        """Return KEV-listed records whose due date is within `days` from now."""
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) + timedelta(days=days)).date().isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT * FROM threat_register "
                "WHERE in_kev = 1 AND kev_due_date != '' AND kev_due_date IS NOT NULL "
                "AND kev_due_date <= ? "
                "ORDER BY kev_due_date ASC",
                (cutoff,),
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
                writer.writerow({k: _csv_safe(r[k]) for k in CSV_FIELDS})

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


_CSV_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> Any:
    """Neutralise CSV formula injection.

    Spreadsheet apps (Excel, Sheets, LibreOffice) interpret cells starting
    with =, +, -, @ as formulas. An attacker who controls an advisory title
    (e.g., `=cmd|'/c calc'!A0`) can land code execution / DDE / external
    fetch when an operator opens threat_register.csv. Prefix a single quote
    to anything that starts with one of those characters so the value is
    rendered as literal text.
    """
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIX):
        return "'" + value
    return value
