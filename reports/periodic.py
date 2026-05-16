"""Monthly / quarterly reports.

Differences from the weekly report:
- Longer window (30 or 90 days) and emphasis on trend / triage status
- Trend table: this period vs previous period for each AI category
- Pending High items (not Actioned/Closed)
- CVE clusters (same CVE across multiple sources) for prioritisation
- Policy-implications summary placeholder for human input
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from storage import ThreatRegister


_AI_CATEGORIES = {
    "Prompt Injection",
    "Sensitive Information Disclosure",
    "AI Supply Chain",
    "Tool Poisoning / MCP Risk",
    "Data or Model Poisoning",
    "AI-generated Code Vulnerability",
    "Agent Excessive Agency",
    "RAG / Vector DB Risk",
    "AI-enabled Phishing",
    "AI-assisted Vulnerability Exploitation",
}


def _esc(s: Any) -> str:
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def _arrow(curr: int, prev: int) -> str:
    if prev == 0 and curr == 0:
        return "—"
    if prev == 0:
        return f"NEW (+{curr})"
    delta = curr - prev
    if delta == 0:
        return "→"
    pct = (delta / prev) * 100
    sign = "▲" if delta > 0 else "▼"
    return f"{sign} {delta:+d} ({pct:+.0f}%)"


def generate_periodic_report(
    register: ThreatRegister,
    out_path: str | Path,
    period: str = "monthly",
) -> Path:
    period = period.lower()
    if period == "monthly":
        window_days = 30
        title = "Monthly Report"
    elif period == "quarterly":
        window_days = 90
        title = "Quarterly Report"
    else:
        raise ValueError(f"unknown period: {period}")

    now = datetime.now(timezone.utc)
    cur_start = (now - timedelta(days=window_days)).isoformat()
    prev_start = (now - timedelta(days=window_days * 2)).isoformat()

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cur_rows = register.recent(since_iso=cur_start, limit=10000)
    # Get the previous window by fetching wider and slicing.
    all_rows = register.recent(since_iso=prev_start, limit=20000)
    cur_ids = {r["threat_id"] for r in cur_rows}
    prev_rows = [r for r in all_rows if r["threat_id"] not in cur_ids]

    def category_counter(rows: list[Any]) -> Counter[str]:
        c: Counter[str] = Counter()
        for r in rows:
            c[r["category"] or "Unknown"] += 1
        return c

    cur_cat = category_counter(cur_rows)
    prev_cat = category_counter(prev_rows)

    cur_priority: Counter[str] = Counter()
    cur_impact: Counter[str] = Counter()
    cur_status: Counter[str] = Counter()
    in_kev_cur = 0
    high_epss_cur = 0
    pending_high: list[dict[str, Any]] = []

    for r in cur_rows:
        d = dict(r)
        cur_priority[d.get("priority") or "Low"] += 1
        cur_impact[d.get("company_impact") or "Unknown"] += 1
        cur_status[d.get("status") or "New"] += 1
        if d.get("in_kev"):
            in_kev_cur += 1
        if (d.get("epss_max_score") or 0.0) >= 0.7:
            high_epss_cur += 1
        if d.get("priority") == "High" and d.get("status") in (None, "", "New", "Reviewing"):
            pending_high.append(d)

    clusters = register.cve_clusters(min_size=2)

    lines: list[str] = []
    lines.append(f"# AI Threat Watch — {title}")
    lines.append("")
    lines.append(f"- Period: {cur_start[:10]} → {now.isoformat()[:10]} (UTC, {window_days} days)")
    lines.append(f"- Items collected (this period): **{len(cur_rows)}**")
    lines.append(f"- Items collected (previous {window_days}d): {len(prev_rows)}")
    lines.append("")

    # Trend table
    lines.append("## Category Trend (this vs previous period)")
    lines.append("")
    lines.append("| Category | This | Previous | Trend |")
    lines.append("|---|---:|---:|---|")
    all_cats = sorted(set(cur_cat) | set(prev_cat))
    # AI-related first, then Others
    ai_first = sorted([c for c in all_cats if c in _AI_CATEGORIES])
    other = sorted([c for c in all_cats if c not in _AI_CATEGORIES])
    for c in ai_first + other:
        lines.append(f"| {_esc(c)} | {cur_cat.get(c, 0)} | {prev_cat.get(c, 0)} | {_arrow(cur_cat.get(c, 0), prev_cat.get(c, 0))} |")
    lines.append("")

    # High level breakdown
    lines.append("## Priority / Impact / Status Breakdown (this period)")
    lines.append("")
    lines.append(f"- High: {cur_priority.get('High', 0)} · Medium: {cur_priority.get('Medium', 0)} · Low: {cur_priority.get('Low', 0)}")
    lines.append(f"- Company Impact: Yes={cur_impact.get('Yes', 0)} · Unknown={cur_impact.get('Unknown', 0)} · No={cur_impact.get('No', 0)}")
    lines.append(f"- Status: New={cur_status.get('New', 0)} · Reviewing={cur_status.get('Reviewing', 0)} · Actioned={cur_status.get('Actioned', 0)} · Closed={cur_status.get('Closed', 0)} · FalsePositive={cur_status.get('FalsePositive', 0)}")
    lines.append(f"- CVE signals: KEV-listed={in_kev_cur} · EPSS≥0.7={high_epss_cur}")
    lines.append("")

    # Pending High items
    lines.append(f"## Pending High Priority Items ({len(pending_high)})")
    lines.append("")
    lines.append("_High-priority items with status=New or Reviewing._")
    lines.append("")
    if pending_high:
        lines.append("| ID | Severity | Category | Impact | KEV | Status | Title | Source |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for it in pending_high[:50]:
            title_md = f"[{_esc(it.get('title'))[:90]}]({it.get('url') or ''})"
            kev_marker = "✓" if it.get("in_kev") else ""
            lines.append(
                "| {tid} | {sev} | {cat} | {imp} | {kev} | {st} | {t} | {src} |".format(
                    tid=_esc(it.get("threat_id")),
                    sev=_esc(it.get("severity")),
                    cat=_esc(it.get("category")),
                    imp=_esc(it.get("company_impact")),
                    kev=kev_marker,
                    st=_esc(it.get("status")),
                    t=title_md,
                    src=_esc(it.get("source")),
                )
            )
    else:
        lines.append("_No pending High priority items. 🎉_")
    lines.append("")

    # CVE clusters
    if clusters:
        top_clusters = clusters[:10]
        lines.append(f"## Top CVE Clusters ({len(top_clusters)} of {len(clusters)})")
        lines.append("")
        lines.append("_Same CVE referenced from multiple sources. Prioritise these for triage; one fix may close several entries._")
        lines.append("")
        lines.append("| CVE | # Records | Sources | Sample Title |")
        lines.append("|---|---:|---|---|")
        for cl in top_clusters:
            srcs = ", ".join(cl["sources"])
            sample = cl["members"][0]
            lines.append(f"| {_esc(cl['cve'])} | {len(cl['members'])} | {_esc(srcs)[:80]} | {_esc(sample.get('title'))[:80]} |")
        lines.append("")

    # Policy implications placeholder
    lines.append("## Policy Implications (to be filled by AI Threat Lead)")
    lines.append("")
    lines.append("_Drawing on this period's trends, list any updates to:_")
    lines.append("- Approved AI Tool List")
    lines.append("- AI usage policy")
    lines.append("- Engineering / IT controls")
    lines.append("- Training material for staff")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("_Generated automatically. AI judgement is preliminary; final decisions require human review._")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path
