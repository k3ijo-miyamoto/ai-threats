#!/usr/bin/env python3
"""AI Threat Watch MCP server.

Exposes the Threat Register over the Model Context Protocol so a Claude
client (Claude CLI / Claude Desktop / Cursor / etc.) can query and update
records via natural language.

Run:
    python mcp_server.py                # stdio transport (default for MCP clients)

Register with Claude CLI: see README.md > "MCP integration".
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "threat_register.sqlite"
CSV_PATH = ROOT / "data" / "threat_register.csv"

log = logging.getLogger("threat_watch.mcp")

mcp = FastMCP("ai-threat-watch")


# ----------------------------------------------------------------------- #
# Helpers
# ----------------------------------------------------------------------- #


_ALLOWED_STATUSES = {"New", "Reviewing", "Actioned", "Closed", "FalsePositive"}
_ALLOWED_PRIORITIES = {"High", "Medium", "Low"}

_CORE_FIELDS = (
    "threat_id", "collected_at", "published_at",
    "source", "category", "severity",
    "company_impact", "affected_asset",
    "priority", "status",
    "cve_ids", "in_kev", "kev_due_date", "epss_max_score",
    "title", "url",
)


def _connect() -> sqlite3.Connection:
    if not DB_PATH.exists():
        raise RuntimeError(
            f"Database not found at {DB_PATH}. Run `python main.py collect` first."
        )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _row_to_dict(row: sqlite3.Row, fields: tuple[str, ...] = _CORE_FIELDS) -> dict[str, Any]:
    return {k: row[k] for k in fields if k in row.keys()}


def _refresh_csv() -> None:
    """Lazy CSV mirror refresh after writes; safe to fail."""
    try:
        from storage import ThreatRegister  # local import to keep startup cheap
        ThreatRegister(DB_PATH, CSV_PATH).export_csv()
    except Exception as exc:  # noqa: BLE001
        log.debug("CSV refresh skipped: %s", exc)


# ----------------------------------------------------------------------- #
# Read tools
# ----------------------------------------------------------------------- #


@mcp.tool()
def query_threats(
    priority: list[str] | None = None,
    status: list[str] | None = None,
    company_impact: list[str] | None = None,
    category: str | None = None,
    source: str | None = None,
    kev_only: bool = False,
    cve: str | None = None,
    days: int | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Search the Threat Register with flexible filters.

    Args:
        priority: Filter by priority. Accepts subset of High|Medium|Low.
        status: Filter by status. Accepts subset of New|Reviewing|Actioned|Closed|FalsePositive.
        company_impact: Filter by company_impact. Accepts subset of Yes|Unknown|No.
        category: Partial match on category (e.g., "MCP", "Prompt").
        source: Partial match on source (e.g., "JVN", "CISA", "GitHub").
        kev_only: When True, only KEV-listed records are returned.
        cve: Exact CVE id, e.g., "CVE-2024-3094". Records whose cve_ids list contains it.
        days: Look-back window in days (based on collected_at).
        limit: Max number of records to return (default 20, hard cap 200).

    Returns:
        {"total": <matching count>, "records": [<record dicts>]}
    """
    limit = max(1, min(200, int(limit)))
    clauses: list[str] = []
    params: list[Any] = []

    if priority:
        ps = [p for p in priority if p in _ALLOWED_PRIORITIES]
        if ps:
            clauses.append(f"priority IN ({','.join('?' * len(ps))})")
            params.extend(ps)
    if status:
        ss = [s for s in status if s in _ALLOWED_STATUSES]
        if ss:
            clauses.append(f"status IN ({','.join('?' * len(ss))})")
            params.extend(ss)
    if company_impact:
        ci = [c for c in company_impact if c in ("Yes", "Unknown", "No")]
        if ci:
            clauses.append(f"company_impact IN ({','.join('?' * len(ci))})")
            params.extend(ci)
    if category:
        clauses.append("category LIKE ?")
        params.append(f"%{category}%")
    if source:
        clauses.append("source LIKE ?")
        params.append(f"%{source}%")
    if kev_only:
        clauses.append("in_kev = 1")
    if cve:
        clauses.append("UPPER(cve_ids) LIKE ?")
        params.append(f"%{cve.upper()}%")
    if days is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=int(days))).isoformat()
        clauses.append("collected_at >= ?")
        params.append(cutoff)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM threat_register {where}", params).fetchone()[0]
        cur = conn.execute(
            f"SELECT * FROM threat_register {where} ORDER BY collected_at DESC LIMIT ?",
            (*params, limit),
        )
        records = [_row_to_dict(r) for r in cur.fetchall()]
    return {"total": total, "returned": len(records), "records": records}


@mcp.tool()
def get_threat(threat_id: str) -> dict[str, Any]:
    """Fetch a single record by threat_id with all fields.

    Args:
        threat_id: e.g., "AI-THREAT-0042"

    Returns:
        Full record as dict, or {"error": "..."} if not found.
    """
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM threat_register WHERE threat_id = ?",
            (threat_id,),
        ).fetchone()
    if not row:
        return {"error": f"Threat not found: {threat_id}"}
    d = {k: row[k] for k in row.keys()}
    # Best-effort decode of extra_json for convenience.
    if d.get("extra_json"):
        try:
            d["extra"] = json.loads(d["extra_json"])
        except json.JSONDecodeError:
            pass
    return d


@mcp.tool()
def cve_cluster(cve: str) -> dict[str, Any]:
    """Get all records that reference a given CVE id.

    Useful for: "how many sources reported CVE-2025-55182, and are any still open?"

    Args:
        cve: e.g., "CVE-2025-55182"

    Returns:
        {"cve": ..., "count": N, "sources": [...], "records": [...]}
    """
    with _connect() as conn:
        cur = conn.execute(
            "SELECT * FROM threat_register WHERE UPPER(cve_ids) LIKE ? ORDER BY collected_at DESC",
            (f"%{cve.upper()}%",),
        )
        rows = cur.fetchall()
    records = [_row_to_dict(r) for r in rows]
    sources = sorted({r["source"] for r in rows if r["source"]})
    return {
        "cve": cve.upper(),
        "count": len(rows),
        "sources": sources,
        "records": records,
    }


@mcp.tool()
def list_kev_due(within_days: int = 7) -> dict[str, Any]:
    """List KEV-listed records whose due date is within N days from now.

    Negative `days_to_due` means the due date has already passed.

    Args:
        within_days: Look-ahead window in days (default 7).

    Returns:
        {"count": N, "items": [...]}  each item includes days_to_due.
    """
    cutoff = (datetime.now(timezone.utc) + timedelta(days=int(within_days))).date().isoformat()
    today = datetime.now(timezone.utc).date()
    with _connect() as conn:
        cur = conn.execute(
            "SELECT * FROM threat_register "
            "WHERE in_kev = 1 AND kev_due_date != '' AND kev_due_date IS NOT NULL "
            "AND kev_due_date <= ? "
            "ORDER BY kev_due_date ASC",
            (cutoff,),
        )
        rows = cur.fetchall()
    items: list[dict[str, Any]] = []
    for r in rows:
        d = _row_to_dict(r)
        try:
            due = datetime.fromisoformat(r["kev_due_date"]).date()
            d["days_to_due"] = (due - today).days
        except (TypeError, ValueError):
            d["days_to_due"] = None
        d["kev_known_ransomware"] = bool(r["kev_known_ransomware"])
        items.append(d)
    return {"count": len(items), "within_days": within_days, "items": items}


@mcp.tool()
def recent_high(days: int = 7, limit: int = 30) -> dict[str, Any]:
    """Convenience: recent High-priority items that are still open (New or Reviewing).

    Args:
        days: Look-back window in days (default 7).
        limit: Max records (default 30).

    Returns:
        {"total": N, "records": [...]}
    """
    return query_threats(
        priority=["High"],
        status=["New", "Reviewing"],
        days=days,
        limit=limit,
    )


@mcp.tool()
def stats(days: int = 30) -> dict[str, Any]:
    """Aggregate statistics for the given window.

    Args:
        days: Look-back window in days (default 30).

    Returns:
        Dict with counts by priority, company_impact, status, category, source,
        plus KEV / EPSS signal counts.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(days))).isoformat()
    out: dict[str, Any] = {"window_days": days}
    with _connect() as conn:
        total = conn.execute(
            "SELECT COUNT(*) AS n FROM threat_register WHERE collected_at >= ?",
            (cutoff,),
        ).fetchone()["n"]
        out["total"] = total

        def by(col: str) -> dict[str, int]:
            cur = conn.execute(
                f"SELECT {col} AS k, COUNT(*) AS n FROM threat_register "
                f"WHERE collected_at >= ? GROUP BY {col} ORDER BY n DESC",
                (cutoff,),
            )
            return {(r["k"] or "Unknown"): r["n"] for r in cur.fetchall()}

        out["by_priority"] = by("priority")
        out["by_company_impact"] = by("company_impact")
        out["by_status"] = by("status")
        out["by_category"] = by("category")
        out["by_source"] = by("source")
        out["kev_listed"] = conn.execute(
            "SELECT COUNT(*) AS n FROM threat_register WHERE collected_at >= ? AND in_kev = 1",
            (cutoff,),
        ).fetchone()["n"]
        out["epss_high"] = conn.execute(
            "SELECT COUNT(*) AS n FROM threat_register WHERE collected_at >= ? AND epss_max_score >= 0.7",
            (cutoff,),
        ).fetchone()["n"]
    return out


# ----------------------------------------------------------------------- #
# Write tool
# ----------------------------------------------------------------------- #


@mcp.tool()
def mark_reviewed(
    threat_id: str,
    status: str | None = None,
    corrected_category: str | None = None,
    priority: str | None = None,
    note: str | None = None,
    reviewer: str | None = None,
) -> dict[str, Any]:
    """Record a human review on a threat record.

    The original `category` is preserved; reviewer corrections go into
    `corrected_category` (later used as Claude few-shot training data).

    Args:
        threat_id: e.g., "AI-THREAT-0042" (required).
        status: New|Reviewing|Actioned|Closed|FalsePositive (optional).
        corrected_category: Reviewer-correct category (optional).
        priority: High|Medium|Low override (optional).
        note: Free-form note (optional).
        reviewer: Reviewer identifier (optional; defaults to "claude-cli").

    Returns:
        {"ok": true, "threat_id": ..., "updated": [...]} on success.
    """
    if status and status not in _ALLOWED_STATUSES:
        return {"error": f"Invalid status. Allowed: {sorted(_ALLOWED_STATUSES)}"}
    if priority and priority not in _ALLOWED_PRIORITIES:
        return {"error": "Invalid priority. Allowed: High|Medium|Low"}

    updates: list[tuple[str, Any]] = []
    if status is not None:
        updates.append(("status", status))
    if corrected_category is not None:
        updates.append(("corrected_category", corrected_category))
    if priority is not None:
        updates.append(("priority", priority))
    if note is not None:
        updates.append(("review_note", note))

    if not updates:
        return {"error": "Nothing to update. Provide at least one of status/corrected_category/priority/note."}

    updates.append(("reviewed_at", datetime.now(timezone.utc).isoformat()))
    updates.append(("reviewer", reviewer or "claude-cli"))

    set_clause = ", ".join(f"{c} = ?" for c, _ in updates)
    values = [v for _, v in updates] + [threat_id]

    with _connect() as conn:
        cur = conn.execute(
            f"UPDATE threat_register SET {set_clause} WHERE threat_id = ?",
            values,
        )
        if cur.rowcount == 0:
            return {"error": f"Threat not found: {threat_id}"}
        conn.commit()

    _refresh_csv()
    return {
        "ok": True,
        "threat_id": threat_id,
        "updated": [c for c, _ in updates if c not in ("reviewed_at", "reviewer")],
        "reviewer": reviewer or "claude-cli",
    }


# ----------------------------------------------------------------------- #
# Resources (read-only context Claude can pull on demand)
# ----------------------------------------------------------------------- #


@mcp.resource("threat://summary/weekly")
def resource_weekly_summary() -> str:
    """Plain-text summary of the last 7 days."""
    s = stats(days=7)
    lines = [
        f"AI Threat Watch — last 7 days",
        f"Total: {s['total']}",
        f"By priority: {s.get('by_priority', {})}",
        f"By company_impact: {s.get('by_company_impact', {})}",
        f"By status: {s.get('by_status', {})}",
        f"KEV-listed: {s.get('kev_listed', 0)}",
        f"EPSS ≥ 0.7: {s.get('epss_high', 0)}",
    ]
    return "\n".join(lines)


@mcp.resource("threat://kev/pending")
def resource_kev_pending() -> str:
    """KEV-listed records still in New/Reviewing status."""
    r = query_threats(status=["New", "Reviewing"], kev_only=True, limit=100)
    if r["total"] == 0:
        return "No pending KEV-listed records. 🎉"
    lines = [f"KEV-listed pending records ({r['total']}):", ""]
    for it in r["records"]:
        lines.append(
            f"- {it['threat_id']} | due={it.get('kev_due_date') or '-'} | "
            f"CVE={it.get('cve_ids') or '-'} | priority={it['priority']} | "
            f"status={it['status']} | {it['title']}"
        )
    return "\n".join(lines)


# ----------------------------------------------------------------------- #
# Entry point
# ----------------------------------------------------------------------- #


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    mcp.run()


if __name__ == "__main__":
    main()
