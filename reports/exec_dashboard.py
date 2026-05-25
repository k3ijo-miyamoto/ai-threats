from __future__ import annotations

import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


def _esc_pie_label(s: str) -> str:
    """Pie labels live inside double quotes; strip embedded quotes."""
    return (s or "Unknown").replace('"', "'")


def _parse_iso(ts: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def generate_exec_dashboard(
    register: ThreatRegister,
    out_path: str | Path,
) -> Path:
    """Render a Mermaid-based executive dashboard to `out_path`.

    Four sections: (1) triage funnel, (2) weekly AI signal trend with category
    breakdown, (3) KEV status + lead-time buckets, (4) source contribution to
    High items. All charts use Mermaid syntax that GitHub renders natively.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    with sqlite3.connect(register.sqlite_path) as conn:
        conn.row_factory = sqlite3.Row
        rows_30d = [
            dict(r) for r in conn.execute(
                "SELECT * FROM threat_register WHERE collected_at >= ?",
                ((now - timedelta(days=30)).isoformat(),),
            ).fetchall()
        ]
        rows_8w = [
            dict(r) for r in conn.execute(
                "SELECT * FROM threat_register WHERE collected_at >= ?",
                ((now - timedelta(weeks=8)).isoformat(),),
            ).fetchall()
        ]
        rows_kev = [
            dict(r) for r in conn.execute(
                "SELECT * FROM threat_register WHERE in_kev = 1"
            ).fetchall()
        ]

    # ----------------------------------------------------------------- #
    # 1. Triage funnel (last 30 days)
    # ----------------------------------------------------------------- #
    # In-scope gate: matches what the impact scorer treats as triage-worthy.
    # We OR three signals so classifier-borderline items still count when
    # category, is_ai_related, or company_impact indicates relevance. We also
    # honour `corrected_category` so reviewer overrides are not lost. Funnel
    # stages are forced monotone — High etc. are intersected with the prior
    # stage, so the chart can never widen left-to-right.
    def _is_relevant(r: dict) -> bool:
        cat = r.get("corrected_category") or r.get("category") or ""
        return (
            cat in _AI_CATEGORIES
            or bool(r.get("is_ai_related"))
            or r.get("company_impact") == "Yes"
        )

    total = len(rows_30d)
    relevant_rows = [r for r in rows_30d if _is_relevant(r)]
    ai_relevant = len(relevant_rows)
    high_rows = [r for r in relevant_rows if r.get("priority") == "High"]
    high = len(high_rows)
    notified = sum(1 for r in high_rows if r.get("notified"))
    resolved = sum(1 for r in high_rows if r.get("status") in ("Actioned", "Closed"))

    funnel_md = (
        "```mermaid\n"
        "flowchart LR\n"
        f'    A["Collected<br/>{total}"] --> B["Triage対象<br/>{ai_relevant}"]\n'
        f'    B --> C["High Priority<br/>{high}"]\n'
        f'    C --> D["通知済<br/>{notified}"]\n'
        f'    D --> E["Actioned / Closed<br/>{resolved}"]\n'
        "    style C fill:#fce4ec,stroke:#c2185b\n"
        "    style E fill:#e8f5e9,stroke:#388e3c\n"
        "```"
    )

    # ----------------------------------------------------------------- #
    # 2. Weekly AI signal trend + category breakdown (last 8 weeks)
    # ----------------------------------------------------------------- #
    weeks: list[tuple[str, datetime, datetime]] = []
    for i in range(8):
        end = now - timedelta(weeks=i)
        start = end - timedelta(weeks=1)
        # Label = number of weeks ago for the bucket end.
        label = "今週" if i == 0 else f"-{i}w"
        weeks.append((label, start, end))
    weeks.reverse()  # oldest first

    weekly_ai_counts: list[int] = []
    weekly_cat_counter: Counter[str] = Counter()
    for _label, start, end in weeks:
        wk_count = 0
        for r in rows_8w:
            if not _is_relevant(r):
                continue
            dt = _parse_iso(r.get("collected_at") or "")
            if dt is None or not (start <= dt < end):
                continue
            wk_count += 1
            # Use corrected category if a reviewer overrode it. Restrict to
            # canonical AI categories so the table doesn't surface
            # `Other Security` rows that slipped past classification.
            cat = r.get("corrected_category") or r.get("category") or "Unknown"
            if cat in _AI_CATEGORIES:
                weekly_cat_counter[cat] += 1
        weekly_ai_counts.append(wk_count)

    y_max = max(weekly_ai_counts + [5]) + 2
    x_axis = ", ".join(f'"{lbl}"' for lbl, _, _ in weeks)
    bar_values = ", ".join(str(n) for n in weekly_ai_counts)
    trend_md = (
        "```mermaid\n"
        "xychart-beta\n"
        '    title "AI関連シグナル — 週次推移 (last 8 weeks)"\n'
        f"    x-axis [{x_axis}]\n"
        f'    y-axis "件数" 0 --> {y_max}\n'
        f"    bar [{bar_values}]\n"
        "```"
    )

    cat_table_lines = ["| Category | Count (last 8w) |", "|---|---:|"]
    if weekly_cat_counter:
        for cat, n in weekly_cat_counter.most_common(5):
            cat_table_lines.append(f"| {cat} | {n} |")
    else:
        cat_table_lines.append("| _直近 8 週で AI 関連分類なし_ | 0 |")
    cat_table_md = "\n".join(cat_table_lines)

    # ----------------------------------------------------------------- #
    # 3. KEV status pie + lead-time buckets
    # ----------------------------------------------------------------- #
    kev_status_counter: Counter[str] = Counter()
    overdue = upcoming = on_time_open = 0
    today = now.date()
    for r in rows_kev:
        status = r.get("status") or "New"
        kev_status_counter[status] += 1
        if status in ("Actioned", "Closed", "FalsePositive"):
            continue
        due_str = r.get("kev_due_date") or ""
        if not due_str:
            continue
        try:
            due_date = datetime.strptime(due_str, "%Y-%m-%d").date()
        except ValueError:
            continue
        delta = (due_date - today).days
        if delta < 0:
            overdue += 1
        elif delta <= 7:
            upcoming += 1
        else:
            on_time_open += 1

    if kev_status_counter:
        pie_lines = [
            "```mermaid",
            "pie showData",
            '    title KEVアイテム — ステータス分布',
        ]
        for status in ("New", "Reviewing", "Actioned", "Closed", "FalsePositive"):
            n = kev_status_counter.get(status, 0)
            if n:
                pie_lines.append(f'    "{status}" : {n}')
        pie_lines.append("```")
        kev_pie_md = "\n".join(pie_lines)
    else:
        kev_pie_md = "_KEV-listed アイテムなし。_"

    bucket_max = max(overdue, upcoming, on_time_open, 1) + 2
    kev_bucket_md = (
        "```mermaid\n"
        "xychart-beta\n"
        '    title "KEV 未完了 — 期限バケット"\n'
        '    x-axis ["期限超過", "今週以内", "余裕あり"]\n'
        f'    y-axis "件数" 0 --> {bucket_max}\n'
        f"    bar [{overdue}, {upcoming}, {on_time_open}]\n"
        "```"
    )

    # ----------------------------------------------------------------- #
    # 4. Source contribution to High items (last 30 days)
    # ----------------------------------------------------------------- #
    high_by_source: Counter[str] = Counter(
        r.get("source") or "Unknown"
        for r in rows_30d
        if r.get("priority") == "High"
    )
    if high_by_source:
        src_lines = [
            "```mermaid",
            "pie showData",
            '    title High優先度の情報源 (last 30 days)',
        ]
        for src, n in high_by_source.most_common(8):
            src_lines.append(f'    "{_esc_pie_label(src)}" : {n}')
        src_lines.append("```")
        source_pie_md = "\n".join(src_lines)
    else:
        source_pie_md = "_直近 30 日に High 優先度のアイテムなし。_"

    # ----------------------------------------------------------------- #
    # Assemble
    # ----------------------------------------------------------------- #
    body = f"""# AI Threat Watch — Dashboard

_Generated: {now.isoformat(timespec="seconds")} · データソース: `data/threat_register.sqlite`_

GitHub 上で Mermaid 図はそのままレンダリングされます。再生成は `python main.py dashboard`。

---

## 1. Triage ファネル — ノイズ削減ゲートの効き (last 30 days)

直近 30 日に収集した全アイテムが、どのゲートで何件まで絞り込まれたか。
AI 関連シグナルを持たない一般的脆弱性は Medium 以下に降格される設計のため、
High に残るのは Triage 対象として in-scope と判定されたアイテムのみ。

{funnel_md}

**読み方**: `Collected → Triage対象` の絞り込みがノイズ排除の主役。
`High → 通知済 → Actioned/Closed` の右肩下がりが運用追従度を表す。
通知済より Actioned/Closed が極端に少なければトリアージが詰まっているサイン。

---

## 2. AI 関連シグナル — 週次トレンド (last 8 weeks)

Triage 対象 (in-scope) と判定された AI 関連シグナル件数の週次推移。
急増があればカテゴリ内訳表で当たりをつける。

{trend_md}

### 直近 8 週のカテゴリ内訳 (Top 5)

{cat_table_md}

---

## 3. KEV (Known Exploited Vulnerabilities) 対応リードタイム

KEV-listed の脆弱性は CISA が修正期限を設定しているため、期限超過は SLA 違反として扱う。

### ステータス分布 (全 KEV 蓄積)

{kev_pie_md}

### 未完了 KEV — 期限バケット

{kev_bucket_md}

- **期限超過**: {overdue} 件 — 即時対応 (SLA 違反)
- **今週以内**: {upcoming} 件 — 7 日以内に期限到来
- **余裕あり**: {on_time_open} 件 — 7 日以上先

---

## 4. ソース別貢献度 — High 優先度はどこから来るか (last 30 days)

直近 30 日に High 判定された脅威の情報源分布。
寄与の低いソースは打ち切り候補、寄与の高いソースは継続強化対象。

{source_pie_md}

---

_本ダッシュボードは `reports/exec_dashboard.py` が生成。詳細は
[週次レポート](../reports/weekly_report.md) と
[日次レポート](../reports/daily/) を参照。_
"""

    out_path.write_text(body, encoding="utf-8")
    return out_path
