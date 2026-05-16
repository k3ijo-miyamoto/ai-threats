---
name: daily-report
description: AI Threat Watch の毎日のサマリーを生成。新規収集を実行し、対応すべきHighアイテム・KEV期限切迫・トレンド・推奨アクションをひとつのブリーフィングにまとめる。MCPツール ai-threat-watch を活用する。
---

You are generating the daily AI Threat Watch briefing. Follow these steps in order.

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

Output **directly in chat** (do not write to a file unless the user asks).
Use Japanese for the narrative, English for technical identifiers (CVE, threat_id, category names).
Be concrete. If a section has no items, say so in one short line instead of padding.

Format:

```
🌅 AI Threat Watch — Daily Report (YYYY-MM-DD)

📊 直近24時間: <total>件 (High: X, Medium: Y, Low: Z)
   うちAI関連: N件 / 非AI関連: M件
   (収集パイプライン: new=<n> duplicate=<m> errors=<e>)

🚨 要対応 (本日トリアージすべき High):
  • AI-THREAT-NNNN [<severity>, <category>]
    "<title 1行要約>"
    → <一文の具体的な初動アクション>
  ...

⚠️ KEV期限切迫 (within 7 days, 期限超過含む):
  • AI-THREAT-NNNN | due=YYYY-MM-DD (XX days) | CVE-XXXX
    <短いタイトル> [RANSOMWARE フラグ付きなら明示]
  ...

📈 トレンド (this_week vs previous_week):
  • <Category>: this_week=X, previous=Y (▲ZX%)
  ...
  なし → "目立った変化なし" と1行

✅ 昨日対応済み:
  • AI-THREAT-NNNN: <status> — <note の最初の1行があれば>
  なし → "新たな対応記録なし"

📝 本日の推奨アクション (重要度順):
  1. <最も急ぐべきこと、threat_idを必ず引用>
  2. <次>
  3. <次>
```

Close with one sentence — an executive-level takeaway about today's posture (e.g., "Quiet day; only KEV catch-up needed." or "Prompt Injection surge — investigate agent frameworks in use.").

## Style guardrails

- Reference specific `threat_id` and CVE — never write "some MCP issue"; always name the record.
- Recommended actions must include the `threat_id` they refer to so the reader can run `mark_reviewed` immediately.
- Do not invent statistics. If an MCP call returns 0 items, say so.
- Skip ⚠️ section entirely if `list_kev_due.count == 0`.
- Keep the report short enough that a busy reader scans it in under a minute. Cap each list at 5 items, with "and N more" if there are leftovers.
