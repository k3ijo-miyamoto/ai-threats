from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from storage import ThreatRegister


def _esc(s: Any) -> str:
    if s is None:
        return ""
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def generate_weekly_report(
    register: ThreatRegister,
    out_path: str | Path,
    days: int = 7,
) -> Path:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=days)).isoformat()
    rows = register.recent(since_iso=since, limit=2000)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cat_counter: Counter[str] = Counter()
    priority_counter: Counter[str] = Counter()
    impact_counter: Counter[str] = Counter()
    source_counter: Counter[str] = Counter()

    high_rows: list[dict[str, Any]] = []
    unknown_rows: list[dict[str, Any]] = []
    medium_rows: list[dict[str, Any]] = []

    for r in rows:
        cat_counter[r["category"] or "Unknown"] += 1
        priority_counter[r["priority"] or "Low"] += 1
        impact_counter[r["company_impact"] or "Unknown"] += 1
        source_counter[r["source"] or "Unknown"] += 1
        d = dict(r)
        if d.get("priority") == "High":
            high_rows.append(d)
        elif d.get("company_impact") == "Unknown":
            unknown_rows.append(d)
        elif d.get("priority") == "Medium":
            medium_rows.append(d)

    lines: list[str] = []
    lines.append(f"# AI Threat Watch — Weekly Report")
    lines.append("")
    lines.append(f"- Period: {since[:10]} → {now.isoformat()[:10]} (UTC)")
    lines.append(f"- Total items collected: **{len(rows)}**")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("### By Priority")
    lines.append("")
    lines.append("| Priority | Count |")
    lines.append("|---|---:|")
    for k in ("High", "Medium", "Low"):
        lines.append(f"| {k} | {priority_counter.get(k, 0)} |")
    lines.append("")

    lines.append("### By Company Impact")
    lines.append("")
    lines.append("| Impact | Count |")
    lines.append("|---|---:|")
    for k in ("Yes", "Unknown", "No"):
        lines.append(f"| {k} | {impact_counter.get(k, 0)} |")
    lines.append("")

    lines.append("### By Category")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|---|---:|")
    for k, v in cat_counter.most_common():
        lines.append(f"| {_esc(k)} | {v} |")
    lines.append("")

    lines.append("### By Source")
    lines.append("")
    lines.append("| Source | Count |")
    lines.append("|---|---:|")
    for k, v in source_counter.most_common():
        lines.append(f"| {_esc(k)} | {v} |")
    lines.append("")

    def render_table(title: str, items: list[dict[str, Any]]) -> None:
        lines.append(f"## {title} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("_None._")
            lines.append("")
            return
        lines.append("| ID | Priority | Severity | Category | Impact | Title | Source |")
        lines.append("|---|---|---|---|---|---|---|")
        for it in items[:100]:
            title_md = f"[{_esc(it.get('title'))[:100]}]({it.get('url') or ''})"
            lines.append(
                "| {tid} | {pri} | {sev} | {cat} | {imp} | {title} | {src} |".format(
                    tid=_esc(it.get("threat_id")),
                    pri=_esc(it.get("priority")),
                    sev=_esc(it.get("severity")),
                    cat=_esc(it.get("category")),
                    imp=_esc(it.get("company_impact")),
                    title=title_md,
                    src=_esc(it.get("source")),
                )
            )
        lines.append("")

    render_table("High Priority Items", high_rows)

    # Per-item tailored mitigations (only for High items that have one).
    high_with_advice = [r for r in high_rows if (r.get("tailored_action") or "").strip()]
    if high_with_advice:
        lines.append(f"## High Priority — Tailored Mitigations ({len(high_with_advice)})")
        lines.append("")
        lines.append("_Per-item mitigation advice generated for each High-priority threat. "
                     "Treat as starting point; final actions require human judgement._")
        lines.append("")
        for it in high_with_advice:
            tid = _esc(it.get("threat_id"))
            sev = _esc(it.get("severity"))
            cat = _esc(it.get("category"))
            title = _esc(it.get("title"))
            url = it.get("url") or ""
            asset = _esc(it.get("affected_asset")) or "(none)"
            impact = _esc(it.get("company_impact"))
            advice = (it.get("tailored_action") or "").strip()

            lines.append(f"### {tid} — {title}")
            lines.append("")
            lines.append(f"- **Severity / Category**: {sev} · {cat}")
            lines.append(f"- **Company Impact / Asset**: {impact} · {asset}")
            if url:
                lines.append(f"- **Source**: <{url}>")
            lines.append("")
            lines.append("**Recommended actions:**")
            lines.append("")
            lines.append(advice)
            lines.append("")

    render_table("Company Impact = Unknown (needs triage)", unknown_rows)
    render_table("Medium Priority Items", medium_rows)

    lines.append("---")
    lines.append("")
    lines.append("_Generated automatically. Final judgement requires human review._")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path
