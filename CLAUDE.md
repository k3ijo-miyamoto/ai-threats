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
AI Classifier (rule-based / Claude API 切替式)
  ↓
Company Impact Scoring (AI関連を必須条件とする優先度ゲート)
  ↓
AI Threat Register
  ↓
Per-item Mitigation Advisor (HighアイテムにClaudeで個別対策を生成)
  ↓
Notification (Slack / Teams) / Weekly Report
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
5. Data or Model Poisoning
6. AI-generated Code Vulnerability
7. Agent Excessive Agency
8. RAG / Vector DB Risk
9. AI-enabled Phishing
10. AI-assisted Vulnerability Exploitation
11. Other Security        # AI関連ではあるが上記10カテゴリに当てはまらないもの
12. Not AI-related         # AI関連でない一般セキュリティ脅威（判定保留・低優先度扱い）
```

カテゴリ定義は [classifiers/ai_threat_classifier.py:AI_THREAT_CATEGORIES](classifiers/ai_threat_classifier.py) を正とする。

---

## MVPアーキテクチャ

実装は、Python + SQLite / CSV + Markdown Report + Slack / Teams通知。

```text
threat_watch/
  collectors/
    base.py              # ThreatItem, Collector基底クラス
    rss_collector.py     # 汎用RSS（CISA / Microsoft / Google TI / GitHub Blog / Anthropic 等）
    github_advisory.py   # GitHub Advisory Database API

  classifiers/
    ai_threat_classifier.py    # 分類器（rule-based / Claude 切替）
    impact_scorer.py           # 自社影響＋優先度判定（AI関連必須ゲート）
    mitigation_advisor.py      # HighアイテムにClaudeで個別対策を生成

  storage/
    db.py                # SQLite + CSVミラー、スキーママイグレーション

  notifiers/
    teams.py             # Microsoft Teams MessageCard
    slack.py             # Slack Block Kit

  reports/
    weekly.py            # 週次Markdownレポート

  config/
    sources.yaml         # 情報源定義
    company_assets.yaml  # 自社AIアセット + high_risk_categories + critical_keywords

  data/
    threat_register.sqlite
    threat_register.csv

  main.py                # CLI: collect / advise / notify / report / stats / run
```

`collectors/cisa.py` 等のソース別ファイル分割は実装で不要となり、汎用 `rss_collector.py` 1つに集約した（情報源定義は `config/sources.yaml` 側で完結する）。

---

## データフロー

```text
[1] 情報収集 (collectors/)
    RSS / GitHub Advisory API。.envのGITHUB_TOKEN設定でrate limit緩和

[2] 正規化 (collectors/base.py:ThreatItem)
    title, date, source, url, summary, tags を統一形式に変換

[3] 重複排除 (storage/db.py:fingerprint)
    URL + titleのSHA-256先頭16文字を fingerprint としてUNIQUE制約

[4] AI分類 (classifiers/ai_threat_classifier.py)
    rule-based: キーワードマッチ（オフライン・API不要・低精度）
    claude:     Claude API（高精度・要ANTHROPIC_API_KEY）
    THREAT_WATCH_CLASSIFIER 環境変数 or --classifier 引数で切替
    Claude失敗時は自動的にrule-basedへフォールバック

[5] 自社影響判定 (classifiers/impact_scorer.py)
    company_assets.yamlのkeywords（単語境界マッチ）と照合し、Yes / No / Unknownを判定

[6] 優先度付け (classifiers/impact_scorer.py:_priority)
    AI関連必須ゲート: 非AI関連はCritical/HighでもMedium止まり
    例外: company_impact == Yes（自社アセット直撃）は AI関連でなくてもHigh維持

[7] 保存 (storage/db.py)
    SQLite (threat_register.sqlite) + CSVミラー (threat_register.csv)
    threat_id = AI-THREAT-NNNN を自動採番

[8] 個別対策生成 (classifiers/mitigation_advisor.py)
    priority=Highの未生成アイテムに対し、Claudeで3-5個の具体的対策bullets を生成
    company_assets.yamlの自社アセット名を踏まえる
    情報のみの記事（脅威でない）は NO_ACTION として除外
    tailored_action カラムに保存

[9] 通知 (notifiers/)
    priority=High かつ notified=0 を Slack / Teams へ送信
    両方設定すれば両方に送信、片方ならその片方のみ
    notified=1 へ更新して二重送信防止

[10] 週次レポート (reports/weekly.py)
    Markdownで週次サマリー＋High個別対策セクションを生成
```

`python main.py run` で[1]〜[10]を一括実行する。

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

収集・分類・判定した結果はAI Threat Registerに保存する。スキーマ定義は [storage/db.py](storage/db.py) を正とする。

| Field | Description |
|---|---|
| threat_id | AI-THREAT-0001（自動採番） |
| fingerprint | URL + titleのSHA-256先頭16文字（重複排除用、UNIQUE） |
| collected_at | 収集日時 (ISO 8601) |
| published_at | 公開日時 |
| source / source_category | 情報源と分類 |
| title / url / summary | タイトル・URL・要約 |
| category | Prompt Injection / AI Supply Chain / Other Security 等 |
| severity | Low / Medium / High / Critical（分類器が判定） |
| company_impact | Yes / No / Unknown |
| affected_asset | Copilot / MCP / RAG 等、マッチした自社アセット名 |
| reason | 影響判定の理由 |
| recommended_action | カテゴリ別の汎用アクション（フォールバック） |
| **tailored_action** | **`advise` で生成された個別対策（HighアイテムのみClaude生成）** |
| priority | High / Medium / Low |
| classifier_used | rule-based / claude |
| is_ai_related | 0 / 1 |
| status | New / Reviewing / Actioned / Closed |
| notified | 0 / 1（通知済みフラグ） |

---

## 影響判定ロジック

優先度は `severity / company_impact / critical_hit / is_high_risk_category / is_ai_related` から算出する。
判定本体は [classifiers/impact_scorer.py:_priority()](classifiers/impact_scorer.py) を正とする。

### 設計思想

- **AI関連を必須条件にする**: AI Threat Watch のテーマがAIセキュリティであるため、非AI関連の脆弱性はCriticalでもMedium止まり（ノイズ削減）
- **自社アセット直撃時は例外**: company_impact = Yes（自社利用品のキーワードマッチ）の場合は、AI関連でなくともHighを維持（AI周辺インフラのOS脆弱性等を取りこぼさない）
- **Unknownを安全扱いしない**: 影響不明＋severeなら積極的にHigh扱いし、人間トリアージへ回す

### High（即時対応）

以下のいずれかを満たすこと:

- `company_impact == Yes` かつ `severity in (Critical, High, Medium)`
  → 自社利用品（Copilot / MCP / ChatGPT Enterprise 等）に直接関係する
- `is_ai_related == True` かつ `severity == Critical`
- `is_ai_related == True` かつ `company_impact == Unknown` かつ次のいずれか:
  - `severity == High`
  - `critical_keywords` (RCE / credential theft / active exploitation 等) を含む
  - `high_risk_categories` (Prompt Injection / Tool Poisoning / Agent / AI Supply Chain) に属する

### Medium（週次レビュー）

- `is_ai_related == True` かつ `company_impact == Unknown`（Highに該当しないもの）
- `is_ai_related == True` かつ `severity == High`（直接影響なし）
- `is_ai_related == False` かつ `severity in (Critical, High)` — 非AIだが重大なため記録
- `company_impact == Yes` かつ `severity == Low`

### Low

- `is_ai_related == False` の軽微なもの
- AI関連だが影響なし・severeでもない

### Unknown（company_impact値）

- 自社利用状況が不明
- 影響範囲が不明
- 情報が不足している

Unknownは安全扱いしない。is_ai_related や severity と組み合わせて、必要ならHighへ昇格させる。

---

## 通知ルール

通知先は Slack / Microsoft Teams の Incoming Webhook。両方設定すれば両方に送信。
`.env` の `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL` で個別有効化する。

### 即時通知

`python main.py notify`（`run`にも含まれる）は以下の条件で送信する:

```text
priority == High AND notified == 0
```

priority算出ロジックに「AI関連必須＋自社アセット例外」が組み込まれているため、severity=Critical/Highでも非AI関連で自社アセット非マッチなら通知対象外（Medium扱い）になる。
通知後 `notified=1` に更新し、二重送信を防ぐ。

通知メッセージには `tailored_action`（Highアイテムの個別対策）が含まれている場合、そちらを優先的に表示する。

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

## Slack / Teams 通知例

Slack（Block Kit）:

```text
:warning: [AI Threat Watch] High Risk — Prompt Injection

When prompts become shells: RCE vulnerabilities in AI agent frameworks

Severity:        Critical
Company Impact:  Unknown
Affected Asset:  -
Source:          Microsoft Security Blog

Reason:
Critical keyword detected (RCE / active exploitation). Category falls under high_risk_categories.

Recommended Action (tailored):
- On GitHub Copilot Business and MCP Servers, audit any agent frameworks for
  the affected pattern and disable tool execution until reviewed.
- Restrict AI agent tool-calling scope to allow-listed actions; require
  human-in-the-loop for shell/system command tools.
- Patch agent frameworks immediately if a fix is available; until then,
  block agent traffic to untrusted external prompts.
```

Teams（MessageCard）も同等のフィールドで送信される。

---

## AI分類プロンプト例

実装では分類と影響判定を分離している。分類器プロンプトは
[classifiers/ai_threat_classifier.py:_CLAUDE_SYSTEM_PROMPT](classifiers/ai_threat_classifier.py)
を正とする。

```text
You are an AI security analyst.
Classify the given threat intelligence item into EXACTLY ONE of these categories:
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
- Other Security
- Not AI-related

Return ONLY a JSON object with these exact keys:
{
  "category": "<one of the categories above>",
  "severity": "Low|Medium|High|Critical",
  "summary": "<<=400 chars, plain text, English>",
  "is_ai_related": true|false
}
```

`company_impact / affected_asset / reason / recommended_action` は分類器の出力ではなく、
別途 [classifiers/impact_scorer.py](classifiers/impact_scorer.py) が
`company_assets.yaml` と照合して決定する（コード上の処理に責任を分離する設計）。

個別対策（tailored_action）プロンプトは
[classifiers/mitigation_advisor.py:_SYSTEM_PROMPT](classifiers/mitigation_advisor.py)
を参照。3〜5個のbulletを生成し、自社アセット名を踏まえる。

---

## 運用設計

### Daily

```text
- python main.py run を cron で1日1回実行（CLAUDE/README参照）
- 外部ソースから自動収集
- 重複排除（fingerprint）
- AI分類（rule-based or Claude）
- 自社影響判定 + 優先度算出（AI関連必須ゲート）
- HighアイテムにClaudeで個別対策生成
- High優先度を Slack / Teams へ通知
- 週次レポートを再生成
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

実装済み（[README.md](README.md) 参照）。

```text
AI Threat Watch MVP (実装版)

Input:
- CISA Cybersecurity Advisories (RSS)
- Microsoft Security Blog (RSS)
- Google Threat Intelligence (RSS)
- GitHub Security Blog (RSS)
- OpenAI / Anthropic News (RSS; OpenAIはノイズ源のためデフォルトdisable)
- GitHub Advisory Database (API)

Process:
- daily collection (collectors/)
- deduplication (SHA-256 fingerprint)
- AI classification (rule-based or Claude API, switchable)
- company impact scoring with word-boundary matching
- AI-relevance gated priority (non-AI items demoted unless asset-matched)
- per-item Claude mitigation generation for High items

Output:
- data/threat_register.sqlite + .csv
- reports/weekly_report.md (個別対策セクション込み)
- Slack / Teams notification (High priority only)
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
