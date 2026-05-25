# AI Threat Watch — Dashboard

_Generated: 2026-05-25T22:37:58+00:00 · データソース: `data/threat_register.sqlite`_

GitHub 上で Mermaid 図はそのままレンダリングされます。再生成は `python main.py dashboard`。

---

## 1. Triage ファネル — ノイズ削減ゲートの効き (last 30 days)

直近 30 日に収集した全アイテムが、どのゲートで何件まで絞り込まれたか。
AI 関連シグナルを持たない一般的脆弱性は Medium 以下に降格される設計のため、
High に残るのは Triage 対象として in-scope と判定されたアイテムのみ。

```mermaid
flowchart LR
    A["Collected<br/>402"] --> B["Triage対象<br/>82"]
    B --> C["High Priority<br/>72"]
    C --> D["通知済<br/>72"]
    D --> E["Actioned / Closed<br/>5"]
    style C fill:#fce4ec,stroke:#c2185b
    style E fill:#e8f5e9,stroke:#388e3c
```

**読み方**: `Collected → Triage対象` の絞り込みがノイズ排除の主役。
`High → 通知済 → Actioned/Closed` の右肩下がりが運用追従度を表す。
通知済より Actioned/Closed が極端に少なければトリアージが詰まっているサイン。

---

## 2. AI 関連シグナル — 週次トレンド (last 8 weeks)

Triage 対象 (in-scope) と判定された AI 関連シグナル件数の週次推移。
急増があればカテゴリ内訳表で当たりをつける。

```mermaid
xychart-beta
    title "AI関連シグナル — 週次推移 (last 8 weeks)"
    x-axis ["-7w", "-6w", "-5w", "-4w", "-3w", "-2w", "-1w", "今週"]
    y-axis "件数" 0 --> 44
    bar [0, 0, 0, 0, 0, 0, 42, 40]
```

### 直近 8 週のカテゴリ内訳 (Top 5)

| Category | Count (last 8w) |
|---|---:|
| AI Supply Chain | 21 |
| Tool Poisoning / MCP Risk | 19 |
| AI-generated Code Vulnerability | 12 |
| Sensitive Information Disclosure | 6 |
| Agent Excessive Agency | 4 |

---

## 3. KEV (Known Exploited Vulnerabilities) 対応リードタイム

KEV-listed の脆弱性は CISA が修正期限を設定しているため、期限超過は SLA 違反として扱う。

### ステータス分布 (全 KEV 蓄積)

```mermaid
pie showData
    title KEVアイテム — ステータス分布
    "New" : 8
    "Actioned" : 1
    "Closed" : 10
```

### 未完了 KEV — 期限バケット

```mermaid
xychart-beta
    title "KEV 未完了 — 期限バケット"
    x-axis ["期限超過", "今週以内", "余裕あり"]
    y-axis "件数" 0 --> 7
    bar [5, 1, 2]
```

- **期限超過**: 5 件 — 即時対応 (SLA 違反)
- **今週以内**: 1 件 — 7 日以内に期限到来
- **余裕あり**: 2 件 — 7 日以上先

---

## 4. ソース別貢献度 — High 優先度はどこから来るか (last 30 days)

直近 30 日に High 判定された脅威の情報源分布。
寄与の低いソースは打ち切り候補、寄与の高いソースは継続強化対象。

```mermaid
pie showData
    title High優先度の情報源 (last 30 days)
    "GitHub Advisory Database" : 52
    "Microsoft Security Blog" : 7
    "CISA Cybersecurity Advisories" : 5
    "GitHub Security Blog" : 3
    "IPA セキュリティ情報" : 2
    "JVN セキュリティ情報" : 2
    "JPCERT/CC 注意喚起・WeeklyReport" : 1
```

---

_本ダッシュボードは `reports/dashboard.py` が生成。詳細は
[週次レポート](../reports/weekly_report.md) と
[日次レポート](../reports/daily/) を参照。_
