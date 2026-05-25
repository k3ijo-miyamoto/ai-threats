---
name: daily-report
description: AI Threat Watch の毎日のサマリーを生成。新規収集を実行し、対応すべきHighアイテム・KEV期限切迫・トレンド・推奨アクションをひとつのブリーフィングにまとめる。MCPツール ai-threat-watch を活用する。
---

You are generating the daily AI Threat Watch briefing. Follow these steps in order.

## Step 0 — Self-diagnostic (cron health check)

Before running the pipeline, verify the daily ingestion has not silently stopped. Run this Bash one-liner:

```bash
y=$(date -u -d "yesterday" +%Y-%m-%d); d2=$(date -u -d "2 days ago" +%Y-%m-%d); \
  f1=$( [ -f "reports/daily/${y}.md" ] && echo 1 || echo 0 ); \
  f2=$( [ -f "reports/daily/${d2}.md" ] && echo 1 || echo 0 ); \
  echo "health: yesterday=${f1} day_before=${f2}"
```

Interpret the result:

- `yesterday=1 day_before=1` → healthy. Suppress the health banner in Step 4.
- `yesterday=0` (one or both 0) → degraded. The previous cron tick did not produce a report — either cron stopped, the wrapper script failed, or the host was off. Record this and surface a banner.

If degraded, **also** check whether collection itself stalled by inspecting `stats(days=3)` later in Step 2: if `total < 5` for a 3-day window, treat the pipeline as silent (vs. just the report file missing) and say so explicitly.

Carry the health verdict into Step 4 — do not skip it just because today's run will succeed.

## Step 1 — Run the collection pipeline

Execute the daily ingestion via Bash:

```bash
python main.py run --period weekly
```

Capture the line that prints `new=N duplicate=M errors=E` and the notification result; you will use these numbers.

If `errors > 0`, surface a brief warning at the top of the report but continue.

## Step 2 — Gather context via the MCP server (ai-threat-watch)

Call these MCP tools in this order:

1. `stats(days=1)` — what landed in the last 24h
2. `stats(days=7)` — last-week context for trend comparison
3. `stats(days=14)` — previous week for the diff
4. `recent_high(days=1)` — High-priority items added today (status New/Reviewing)
5. `list_kev_due(within_days=7)` — KEV deadlines urgent or overdue
6. `query_threats(status=["Actioned","Closed"], days=1, limit=20)` — what was resolved in the last 24h

Use the tool outputs as the source of truth. Do not re-run SQL via Bash unless an MCP tool errors.

## Step 3 — Compute "what is different today"

From `stats(days=7)` and `stats(days=14)`:
- For each AI-related category (anything not in {`Other Security`, `Not AI-related`}),
  derive `this_week = count_last_7d`, `previous_week = count_8_to_14d_ago = last14 - last7`.
- Flag categories where `this_week >= 2 * previous_week` OR `previous_week == 0 and this_week >= 2`.

From `stats(days=1)`:
- Count items where `category` is AI-related; this is today's AI signal volume.

## Step 4 — Produce the report

Output **directly in chat** AND persist to `reports/daily/YYYY-MM-DD.md` using the same content (see Step 5).
Use Japanese for the narrative, English for technical identifiers (CVE, threat_id, category names).
Be concrete. If a section has no items, say so in one short line instead of padding.

Use a dashboard-style layout: TL;DR quote at the top, scannable stats table, then section headers (##) for each block. This renders cleanly on GitHub web and in IDEs (markdown tables, blockquotes), and degrades acceptably in Slack (where tables become plain text but the structure still reads).

Format:

```
🌅 AI Threat Watch — Daily Report (YYYY-MM-DD)

> **TL;DR**: <1 sentence — the single thing the reader should walk away knowing>

| 📊 | 24h | 7d | trend |
|---|---:|---:|:---:|
| Total | <n> | <n> | <↑ ↓ → > |
| High | <n> | <n> | <↑ ↓ → > |
| AI関連 | <n> | <n> | <↑ ↓ → > |
| KEV 期限切迫 | <n> | - | <⚠ if any overdue, else →> |

Pipeline: `new=<n> dup=<m> errors=<e>` · advised=<n> · 通知=<n>

---

## 🔴 要対応 (本日トリアージすべき High)

_本日の新規 High がゼロなら "本日の新規 High はゼロ" と 1 行で。 1 件以上なら下記表。_

| ID | severity | category | title | 初動 |
|---|---|---|---|---|
| AI-THREAT-NNNN | Critical | Tool Poisoning / MCP Risk | <短いtitle> | <一文> |

---

## 🟡 KEV 期限切迫 (within 7 days, 期限超過含む — <N> 件)

| ID | due | days | CVE | status | 備考 |
|---|---|---:|---|---|---|
| AI-THREAT-NNNN | YYYY-MM-DD | **+2d** | CVE-XXXX-XXXX | New | <Critical / RANSOMWARE 等のフラグ> |
| AI-THREAT-NNNN | YYYY-MM-DD | -16d | CVE-XXXX-XXXX | New | overdue |

_上位 5 件まで、 残りは末尾に "and N more (概略)" で 1 行。 件数 0 なら 表自体を省略。_

---

## 📈 トレンド (this_week vs previous_week)

- **Tool Poisoning / MCP Risk: 13 vs 5 (▲160%)** _← 急増は太字_
- AI Supply Chain: 8 vs 13 (▼38%)
- AI-generated Code Vulnerability: 5 vs 7 (▼29%)

_該当ゼロなら "目立った変化なし" の 1 行で。_

---

## ✅ 昨日対応済み

- **AI-THREAT-NNNN** (status) — <note の最初の1行>

_該当ゼロなら "新たな対応記録なし" の 1 行で。_

---

## 📝 本日のアクション (優先順)

1. 🔴 **AI-THREAT-NNNN** — <最も急ぐ事。 threat_id 必須>
2. 🟡 **AI-THREAT-NNNN** — <次>
3. 🟢 <任意の改善 / 監視タスク>

---

🎬 **Executive takeaway**: <1 文。 例: "Quiet day; only KEV catch-up needed." / "Prompt Injection surge — investigate agent frameworks in use.">
```

Rules for the dashboard:
- `trend` column in the stats table: use ↑ (up vs 7d/14d avg), ↓ (down), → (flat), ⚠ (only for KEV 期限切迫 when ≥1 overdue or +<3d).
- Priority dots in actions: 🔴 (P0 — today), 🟡 (P1 — this week), 🟢 (P2 — backlog).
- `days` column in KEV table: positive = days remaining (bold if <3), negative = overdue.
- Section dividers (`---`) between every block keep scanning easy.
- Cap each list / table at 5 items; overflow goes into a trailing "and N more" line.

## Step 5 — Persist the report to file

After printing the report in chat, write the **exact same content** to:

```
reports/daily/YYYY-MM-DD.md
```

(Use today's UTC date for `YYYY-MM-DD`.) Use the Write tool. Overwrite if the file already exists — the latest run for a given day is authoritative. The directory `reports/daily/` already exists; do not create it again.

The file body should start with the same `🌅 AI Threat Watch — Daily Report (YYYY-MM-DD)` heading line that appears in chat, so the file is self-contained and can be browsed standalone later.

## Style guardrails

- Reference specific `threat_id` and CVE — never write "some MCP issue"; always name the record.
- Recommended actions must include the `threat_id` they refer to so the reader can run `mark_reviewed` immediately.
- Do not invent statistics. If an MCP call returns 0 items, say so.
- Skip ⚠️ section entirely if `list_kev_due.count == 0`.
- Keep the report short enough that a busy reader scans it in under a minute. Cap each list at 5 items, with "and N more" if there are leftovers.
