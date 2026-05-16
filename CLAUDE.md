# AI Threat Watch MVP

## 目的

AI関連の脅威情報を自動収集し、AIセキュリティ観点で分類し、自社への影響を一次判定したうえで、人間がレビューできる形にする。

この仕組みは、単なるニュース収集ではなく、以下を目的とする。

- AI関連の脅威を継続的に収集する
- Prompt Injection、AI Supply Chain、MCP / Pluginリスクなどに分類する
- 自社で利用しているAIサービス・ツールとの関係を判定する
- High / Unknownリスクを早期に発見する
- Security / IT / AI Teamがレビュー・対応できる形にする

---

## 背景

AIセキュリティでは、従来の情報セキュリティに加えて、以下のような新しい脅威が増えている。

1. AIによる脆弱性発見・悪用の高速化
2. Prompt InjectionからTool実行・RCEにつながるリスク
3. MCP、Agent、Plugin、Tool連携のサプライチェーン化
4. 防御側でもAI活用が進む流れ
5. NIST / OWASP / MITRE ATLASベースのガバナンス要求

そのため、会社としてはAI利用ポリシーだけでなく、AI関連の外部脅威を能動的に探索し、自社影響を評価する仕組みが必要である。

---

## コンセプト

### AI Threat Watch

AI Threat Watchは、AI関連の脅威情報を収集・分類・影響判定・通知する軽量なセキュリティインテリジェンス運用である。

```text
External Sources
  ↓
Collector
  ↓
Normalizer
  ↓
AI Classifier
  ↓
Company Impact Scoring
  ↓
AI Threat Register
  ↓
Notification / Report
```

重要なのは、完全自動で最終判断しないことである。

推奨する設計は以下である。

```text
自動収集
  ↓
自動要約
  ↓
自動分類
  ↓
自社影響の一次判定
  ↓
人間レビュー
  ↓
対策判断
```

---

## 対象とする情報源

### 公的機関・標準

- CISA
- NIST
- IPA
- ENISA
- OWASP LLM Top 10
- MITRE ATLAS

### AI / Security Vendor

- Microsoft Security Blog
- Google Threat Intelligence / Mandiant
- OpenAI
- Anthropic
- GitHub Security
- Palo Alto Networks
- Wiz
- Snyk
- Trend Micro

### 脆弱性・OSS情報

- CVE / NVD
- GitHub Advisory Database
- npm advisories
- PyPI advisories
- Docker image advisories
- GitHub Releases

### AI / Agent / MCP関連

- MCP server repositories
- VS Code AI extensions
- Browser AI extensions
- GitHub Actions
- AI coding assistant tools
- RAG / Vector DB related advisories

---

## 収集対象カテゴリ

AI Threat Watchでは、以下のカテゴリで分類する。

```text
1. Prompt Injection
2. Sensitive Information Disclosure
3. AI Supply Chain
4. Tool Poisoning / MCP Risk
5. Data Poisoning / Model Poisoning
6. AI-generated Code Vulnerability
7. Agent Excessive Agency
8. RAG / Vector DB Risk
9. AI-enabled Phishing / Social Engineering
10. AI-assisted Vulnerability Discovery / Exploitation
```

---

## MVPアーキテクチャ

最初のMVPは、Python + SQLite / CSV + Markdown Report + Teams通知で十分である。

```text
ai-threat-watch/
  collectors/
    cisa.py
    nist.py
    owasp.py
    mitre.py
    github_advisory.py
    vendor_rss.py

  classifiers/
    ai_threat_classifier.py
    impact_scorer.py

  data/
    threat_register.sqlite
    threat_register.csv

  reports/
    weekly_report.md

  config/
    sources.yaml
    company_assets.yaml

  main.py
```

---

## データフロー

```text
[1] 情報収集
    RSS / API / GitHub Advisory / Web metadata

[2] 正規化
    title, date, source, url, summary, tags を統一形式に変換

[3] 重複排除
    URL, title類似度, source, published_atでdeduplication

[4] AI要約
    脅威概要、影響、関係する技術を短く要約

[5] AI分類
    AI Threat Categoryに分類

[6] 自社影響判定
    company_assets.yamlと照合し、Yes / No / Unknownを判定

[7] 優先度付け
    severity, exploitability, company impactでHigh / Medium / Lowに分類

[8] 保存
    AI Threat Registerに保存

[9] 通知
    High / Critical / UnknownのみTeamsやEmailへ通知

[10] 週次レポート
    Markdownで週次サマリーを生成
```

---

## company_assets.yaml

自社影響判定のためには、自社で利用しているAIサービス・AIツール・関連システムを定義する。

```yaml
company_ai_assets:
  - name: Microsoft 365 Copilot
    category: enterprise_ai
    data_access:
      - email
      - teams
      - sharepoint
      - office_documents
    risk_level: high
    owner: IT

  - name: GitHub Copilot Business
    category: coding_ai
    data_access:
      - source_code
      - repositories
    risk_level: high
    owner: Engineering

  - name: ChatGPT Enterprise
    category: general_ai
    data_access:
      - internal_documents
      - business_documents
    risk_level: medium
    owner: AI Team

  - name: MCP Servers
    category: agent_tools
    data_access:
      - local_files
      - internal_api
      - tool_execution
    risk_level: high
    owner: AI Team

  - name: RAG Knowledge Base
    category: rag
    data_access:
      - internal_documents
      - knowledge_base
      - vector_db
    risk_level: medium
    owner: AI Team
```

---

## sources.yaml

収集対象の情報源を定義する。

```yaml
sources:
  - name: CISA Alerts
    type: rss
    url: https://www.cisa.gov/news-events/cybersecurity-advisories.xml
    category: public_sector

  - name: Microsoft Security Blog
    type: rss
    url: https://www.microsoft.com/en-us/security/blog/feed/
    category: vendor

  - name: GitHub Advisory Database
    type: api
    url: https://api.github.com/advisories
    category: vulnerability

  - name: Google Threat Intelligence Blog
    type: rss
    url: https://cloud.google.com/blog/topics/threat-intelligence/rss
    category: vendor

  - name: OpenAI Blog
    type: rss
    url: https://openai.com/news/rss.xml
    category: ai_vendor

  - name: Anthropic News
    type: rss
    url: https://www.anthropic.com/news/rss.xml
    category: ai_vendor
```

---

## AI Threat Register

収集・分類・判定した結果はAI Threat Registerに保存する。

| Field | Description |
|---|---|
| threat_id | AI-THREAT-0001 |
| collected_at | 収集日時 |
| published_at | 公開日 |
| source | CISA / Microsoft / GitHub など |
| title | タイトル |
| url | 元情報URL |
| summary | 要約 |
| category | Prompt Injection / AI Supply Chain など |
| affected_asset | Copilot / MCP / GitHub / RAGなど |
| severity | Low / Medium / High / Critical |
| company_impact | Yes / No / Unknown |
| reason | 判定理由 |
| recommended_action | 推奨アクション |
| owner | 対応担当 |
| status | New / Reviewing / Actioned / Closed |

---

## 影響判定ロジック

### High

以下に該当する場合はHighとする。

- 自社利用サービスに直接関係する
- RCE、credential theft、data leakageに関係する
- GitHub、Copilot、M365、MCP、Cloud credentialに関係する
- PoCが公開されている
- 悪用が確認されている
- Agent / Tool実行と関係する

### Medium

- 類似技術を利用している
- Agent / Plugin / AI SaaSに関係する
- 設定次第で影響する
- 自社利用は限定的だが注意が必要

### Low

- 理論的リスク
- 自社利用がない
- 直接影響が薄い

### Unknown

- 自社利用状況が不明
- 影響範囲が不明
- 情報が不足している

重要なのは、Unknownを安全扱いしないことである。Unknownは調査対象として残す。

---

## 通知ルール

### 即時通知

以下の場合は即時通知する。

```text
- severity = Critical
- severity = High
- company_impact = Yes
- company_impact = Unknown かつ categoryがHigh risk
- RCE
- credential leakage
- active exploitation
- MCP / Tool / Agent実行に関係
```

### 週次レポート

以下は週次レポートに含める。

```text
- Medium
- Unknown
- 新しいAI脅威トレンド
- 未対応のHigh Risk
- 自社AI利用との関係がありそうなもの
```

### 月次レポート

月次では、傾向と運用改善を整理する。

```text
- カテゴリ別件数
- High / Critical件数
- Unknown件数
- 対応済み件数
- 未対応リスク
- 新たに必要なポリシー変更
```

---

## Teams通知例

```text
[AI Threat Watch] High Risk

Title:
Prompt Injection leading to tool misuse in AI agent framework

Category:
Prompt Injection / Agent Tool Risk

Company Impact:
Unknown

Reason:
Our company uses Microsoft 365 Copilot and GitHub Copilot. Need to confirm whether similar tool execution paths exist.

Recommended Action:
Review approved AI tools and check whether agent/tool execution is enabled.
```

---

## AI分類プロンプト例

```text
You are an AI security analyst.

Classify the following threat intelligence item into one of the categories below:

- Prompt Injection
- Sensitive Information Disclosure
- AI Supply Chain
- Tool Poisoning / MCP Risk
- Data or Model Poisoning
- AI-generated Code Vulnerability
- Agent Excessive Agency
- RAG / Vector DB Risk
- AI-enabled Phishing
- AI-assisted Vulnerability Exploitation

Then estimate company impact using the following company AI assets:
{company_assets}

Return JSON only:
{
  "category": "...",
  "severity": "Low/Medium/High/Critical",
  "company_impact": "Yes/No/Unknown",
  "affected_asset": "...",
  "reason": "...",
  "recommended_action": "..."
}

Threat intelligence item:
{threat_item}
```

---

## 運用設計

### Daily

```text
- 外部ソースから自動収集
- 重複排除
- AI要約・分類
- High / Criticalのみ通知
```

### Weekly

```text
- AI Threat Registerレビュー
- Unknown判定の確認
- Highリスクの対応状況確認
- Weekly report生成
```

### Monthly

```text
- 傾向分析
- 未対応リスクレビュー
- AI利用ポリシーへの反映
- Security / IT / AI Teamへの報告
```

### Quarterly

```text
- Prompt Injection演習
- AI Incident対応演習
- Approved AI Tool List見直し
- AI Security Register更新
```

---

## 体制

| Role | Responsibility |
|---|---|
| AI Threat Lead | 全体運用、分類基準、月次報告 |
| Security Reviewer | 影響判定、インシデント接続 |
| IT Admin | M365 / Endpoint / Network観点の確認 |
| Dev Representative | GitHub / CI/CD / Code観点の確認 |
| Legal / Compliance | データ保護、契約、規制観点の確認 |

最初は専任チームでなくてよい。AI TeamとSecurity Teamの兼務で、週次30分から開始できる。

---

## 実装フェーズ

## Phase 1: 手動 + 半自動

期間目安: 1〜2週間

### 実施内容

```text
- 情報源リスト作成
- RSS / APIで取得
- SQLite / CSVに保存
- AIで要約・分類
- 週次Markdownレポート生成
```

### 成果物

```text
- AI Threat Register v0.1
- Weekly AI Threat Report
- sources.yaml
- company_assets.yaml 初版
```

---

## Phase 2: 自社影響判定

期間目安: 2〜4週間

### 実施内容

```text
- company_assets.yamlを整備
- 自社AI利用状況と照合
- company_impactをYes / No / Unknownで判定
- High / UnknownのみTeams通知
- GitHub Issue / Planner / Jiraに起票
```

### 成果物

```text
- Company Impact Scoring
- Teams Alert
- Action Tracking
- AI Threat Register v0.2
```

---

## Phase 3: 運用化

期間目安: 1〜3か月

### 実施内容

```text
- 月次レポート
- Security定例への接続
- AIインシデント報告ルートとの連携
- Approved AI Tool Listとの連携
- DLP / CASB / EDRログとの照合検討
```

### 成果物

```text
- AI Threat Watch Operation
- AI Security Monthly Report
- AI Risk Backlog
- AI Policy Feedback Loop
```

---

## 最初に作るMVP

```text
AI Threat Watch MVP

Input:
- OWASP
- MITRE ATLAS
- CISA
- NIST
- Microsoft Security Blog
- Google Threat Intelligence
- OpenAI / Anthropic / GitHub Blog
- GitHub Advisory

Process:
- daily collection
- deduplication
- AI summary
- AI category classification
- company impact scoring

Output:
- ai_threat_register.csv
- weekly_report.md
- High / Unknown only Teams notification
```

---

## 成功指標

| KPI | Description |
|---|---|
| Collection Coverage | 主要ソースの収集率 |
| Classification Accuracy | 人間レビュー後の分類精度 |
| Unknown Reduction | Unknown判定の削減率 |
| Time to Awareness | 脅威公開から社内認知までの時間 |
| Time to Triage | 影響判定までの時間 |
| Action Completion | チケット対応完了率 |
| Noise Ratio | 通知のうち対応不要だった割合 |

---

## 注意点

- AIによる分類は最終判断ではなく、一次判定とする
- High / Critical / Unknownは必ず人間が確認する
- ニュース記事だけでなく、一次情報を優先する
- 誤検知を減らすため、自社AI Asset情報を継続的に更新する
- 収集した情報は社内ポリシー、教育、Approved AI Tool Listに反映する

---

## 社内提案用サマリー

AIセキュリティは、利用ルールを作るだけでは不十分である。AI関連の脅威は変化が速く、Prompt Injection、AI Supply Chain、MCP / Pluginリスク、AIを用いた脆弱性探索などを継続的に確認する必要がある。

そのため、外部のAI脅威情報を自動収集し、自社利用AIとの関連を一次判定し、High / Unknownリスクだけを人間が確認する **AI Threat Watch** を構築する。

最初は大規模なSOCではなく、Python、CSV / SQLite、Markdown Report、Teams通知を用いた軽量MVPから開始する。これにより、AI活用を止めるのではなく、安全に進めるための早期警戒システムを会社として持つことができる。

---

## 一言での定義

**AI Threat Watchとは、AI関連脅威のRSS / Advisory収集システムではなく、自社AI利用状況と照合して「対応すべきもの」だけを浮かび上がらせるAI Security Intelligence基盤である。**
