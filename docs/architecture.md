# AI Threat Watch — アーキテクチャ図

GitHub / VS Code (Markdown Preview Enhanced 等) で mermaid ブロックがそのまま描画される。 静的画像が欲しい場合は `mmdc -i docs/architecture.md -o docs/architecture.svg` 等で書き出す。

## 0. Smoke test (動作確認用)

```mermaid
flowchart LR
    A[Hello] --> B[World]
```

## 1. データフロー全体図

```mermaid
flowchart TD
    subgraph INPUT["External Sources"]
        S1["CISA Advisories RSS"]
        S2["Microsoft Security Blog RSS"]
        S3["GitHub Security Blog RSS"]
        S4["GitHub Advisory DB API"]
        S5["JPCERT IPA JVN RSS"]
        S6["OpenAI Anthropic RSS"]
    end

    subgraph CONFIG["Configuration"]
        SRC["sources.yaml"]
        ASSETS["company_assets.yaml<br>asset + critical keywords"]
    end

    subgraph COLLECT["Collection"]
        C1["rss_collector.py"]
        C2["github_advisory.py"]
        DEDUP{"Dedup<br>SHA-256 fingerprint"}
    end

    subgraph ENRICH["Enrichment"]
        AF["article_fetcher.py<br>trafilatura; skip URLs with hash"]
        CVE["cve_enricher.py<br>KEV + EPSS"]
    end

    subgraph CLASSIFY["Classification and Scoring"]
        CLS["ai_threat_classifier.py<br>rule-based or Claude"]
        FEW["Few-shot examples<br>from past reviews"]
        SCORE["impact_scorer.py<br>asset match + AI-gate"]
        ADV["mitigation_advisor.py<br>Claude tailored actions"]
    end

    subgraph STORE["Storage"]
        SQL["SQLite threat_register"]
        CSV["CSV mirror"]
    end

    subgraph OUT["Outputs"]
        SLACK["Slack webhook - High only"]
        TEAMS["Teams webhook - High only"]
        WEEKLY["reports/weekly_report.md"]
        DAILY["reports/daily/YYYY-MM-DD.md<br>by /daily-report skill"]
        DASH["dashboard.py - Streamlit"]
        MCP["mcp_server.py - MCP protocol"]
    end

    subgraph HUMAN["Human Triage"]
        REV["review CLI<br>or MCP mark_reviewed"]
    end

    SRC --> C1
    SRC --> C2
    S1 --> C1
    S2 --> C1
    S3 --> C1
    S5 --> C1
    S6 --> C1
    S4 --> C2

    C1 --> DEDUP
    C2 --> DEDUP
    DEDUP -->|new| AF
    AF --> CLS
    DEDUP --> CVE

    ASSETS --> SCORE
    CVE --> SCORE
    CLS --> SCORE
    FEW --> CLS

    SCORE -->|priority=High| ADV
    ADV --> SQL
    SCORE --> SQL
    SQL --> CSV

    SQL -->|High AND notified=0| SLACK
    SQL -->|High AND notified=0| TEAMS
    SQL --> WEEKLY
    SQL --> DAILY
    SQL --> DASH
    SQL --> MCP

    MCP --> REV
    REV -->|corrected_category| SQL
    SQL -.->|past corrections| FEW
```

## 2. 優先度判定ロジック (impact_scorer の核)

> 「**AI 関連を必須条件にしつつ、自社アセット直撃は例外として High を維持**」 の流れ

```mermaid
flowchart TD
    START([new threat]) --> A{company_impact == Yes?}
    A -->|Yes 自社アセット直撃| AH{severity in<br>Critical High Medium?}
    AH -->|Yes| HIGH1[priority = High<br>AI 関連でなくても]
    AH -->|No| MED1[priority = Medium]

    A -->|No| B{is_ai_related?}
    B -->|No 非AI関連| BS{severity in<br>Critical High?}
    BS -->|Yes| MED2[priority = Medium<br>非AI天井]
    BS -->|No| LOW1[priority = Low]

    B -->|Yes AI関連| C{severity == Critical?}
    C -->|Yes| HIGH2[priority = High]
    C -->|No| D{Unknown AND<br>severity=High OR<br>critical_keyword OR<br>high_risk_category?}
    D -->|Yes| HIGH3[priority = High]
    D -->|No| E{company_impact == Unknown?}
    E -->|Yes| MED3[priority = Medium]
    E -->|No| F{severity == High?}
    F -->|Yes| MED4[priority = Medium]
    F -->|No| LOW2[priority = Low]
```

KEV-listed (`in_kev=1`) または EPSS ≥ 0.7 は **テキスト由来の critical_keyword と同等扱い** で D 分岐の `critical_keyword` 側に合流する。

## 3. モジュール責任分担

```mermaid
flowchart LR
    subgraph main["main.py — CLI orchestrator"]
        CMD[collect / advise / notify /<br>report / review / run]
    end

    subgraph collectors["collectors/"]
        BASE[base.py<br>ThreatItem, Collector基底]
        RSS[rss_collector.py]
        GHA[github_advisory.py]
        FETCH[article_fetcher.py]
    end

    subgraph classifiers["classifiers/"]
        TC[ai_threat_classifier.py]
        IS[impact_scorer.py]
        CE[cve_enricher.py]
        MA[mitigation_advisor.py]
    end

    subgraph storage["storage/"]
        DB[db.py<br>ThreatRegister<br>+ schema migration]
    end

    subgraph notifiers["notifiers/"]
        SL[slack.py]
        TM[teams.py]
    end

    subgraph reports["reports/"]
        WK[weekly.py]
        PR[periodic.py]
    end

    subgraph access["access layer (read-side)"]
        DASHm[dashboard.py<br>Streamlit]
        MCPm[mcp_server.py<br>MCP server]
    end

    CMD --> RSS
    CMD --> GHA
    CMD --> FETCH
    CMD --> TC
    CMD --> CE
    CMD --> IS
    CMD --> MA
    CMD --> DB
    CMD --> SL
    CMD --> TM
    CMD --> WK
    CMD --> PR
    RSS -.-> BASE
    GHA -.-> BASE
    DASHm --> DB
    MCPm --> DB
```

## 4. CLI コマンドの動作対応

| コマンド | 動作 |
|---|---|
| `python main.py collect` | 収集 → 重複排除 → エンリッチ → 分類 → 影響判定 → 保存 |
| `python main.py advise` | priority=High かつ `tailored_action` 未生成のものに Claude で対策生成 |
| `python main.py notify` | priority=High かつ notified=0 を Slack / Teams に送信 |
| `python main.py report --days 7` | `reports/weekly_report.md` 生成 |
| `python main.py review <id>` | 人間レビュー結果を記録 (→ Few-shot 学習データへ) |
| `python main.py run` | 上記を一括 (collect → advise → notify → report) |
| `python main.py alerts --kev-due-within 7` | KEV 期限切迫アイテム表示 |
| `python main.py stats` | レジスタ統計 |
| `streamlit run dashboard.py` | Web ダッシュボード |
| `python mcp_server.py` (auto via `.mcp.json`) | MCP サーバ (Claude CLI / Desktop から `query_threats` 等を提供) |

## 5. 関連ドキュメント

- [CLAUDE.md](../CLAUDE.md) — プロジェクト全体の設計思想 / 運用ルール (ASCII 図はこちらにある)
- [README.md](../README.md) — セットアップ / コマンド一覧 / カスタマイズ手順
- [docs/design/post-mythos.md](design/post-mythos.md) — Mythos 世界線でこの図をどう延伸するかの設計メモ
