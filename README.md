# AI Threat Watch (MVP)

AI関連の脅威情報を収集・分類・自社影響判定・通知する軽量Pythonツール。
詳細な背景・運用設計は [CLAUDE.md](CLAUDE.md) を参照。

## 構成

```
threat_watch/
  collectors/          # 収集 (RSS / GitHub Advisory)
  classifiers/         # AI分類 (rule-based / Claude) + 自社影響判定
  storage/             # SQLite + CSVミラー
  notifiers/           # Teams Webhook
  reports/             # 週次Markdownレポート
  config/
    sources.yaml       # 収集対象
    company_assets.yaml# 自社AIアセット定義
  data/                # threat_register.sqlite / .csv (gitignored)
  main.py              # CLIエントリポイント
```

## セットアップ

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# .env を編集: ANTHROPIC_API_KEY, TEAMS_WEBHOOK_URL, GITHUB_TOKEN, THREAT_WATCH_CLASSIFIER
```

## 基本コマンド

```bash
# 収集 → 分類 → 影響判定 → SQLite/CSVへ保存
python main.py collect

# 高優先度の未通知アイテムをTeamsへ送信
python main.py notify

# 週次レポート生成 (reports/weekly_report.md)
python main.py report --days 7

# High優先度の各脅威に対し、Claudeで個別の対策を生成
python main.py advise [--limit N]

# 一括実行（collect → advise → notify → report）— 通常はこれを使う
python main.py run

# 統計
python main.py stats

# 人間レビュー記録（status / category / priority / note）
python main.py review AI-THREAT-0042 \
    --status Reviewing \
    --correct-category "Not AI-related" \
    --priority Low \
    --note "誤検知。実際は IoT 機器の問題で AI 経路なし"
```

## 典型的な運用フロー

### 日次

```bash
python main.py run
```

これで以下が実行される:

1. 8つの情報源からRSS/APIを取得
2. 新規分のみ分類器で分類（既存はfingerprintで重複排除）
3. `company_assets.yaml` と照合して影響判定
4. High優先度の各脅威に対し、Claudeで個別の対策（tailored_action）を生成
5. High優先度を Slack / Teams へ通知
6. 週次レポートを更新

### 週次レビュー（人間が手動で）

1. [reports/weekly_report.md](reports/weekly_report.md) を開く
2. 「Company Impact = Unknown」セクションを人間が確認
3. 必要に応じて [data/threat_register.csv](data/threat_register.csv) をExcel等で開いて精査

## 結果の見方

### Priority（優先度）

| 値 | 対応方針 |
|---|---|
| **High** | 即時対応 — 自社アセット直撃 or 重大脆弱性＋AI関連 |
| **Medium** | 週次レビューで確認 |
| **Low** | レポート集計のみ |

### Company Impact

| 値 | 意味 |
|---|---|
| **Yes** | `company_assets.yaml` のキーワードにマッチ — 確実に影響 |
| **Unknown** | 影響不明 — **人間トリアージ必須**（安全扱いしない） |
| **No** | AI関連でなく自社アセットとも無関係 |

## 分類器の切替

`.env` または環境変数で指定:

```
THREAT_WATCH_CLASSIFIER=claude       # Claude API使用（推奨。ANTHROPIC_API_KEY必須）
THREAT_WATCH_CLASSIFIER=rule-based   # オフライン動作（精度低、API不要）
```

コマンドラインから一時的に上書き:

```bash
python main.py collect --classifier rule-based
```

ClaudeClassifierはAPI失敗時、自動的にrule-basedへフォールバックする。

## カスタマイズ

### 自社AIツールの追加

[config/company_assets.yaml](config/company_assets.yaml) を編集。例: GitLab Duoを追加する場合:

```yaml
  - name: GitLab Duo
    category: coding_ai
    keywords:
      - gitlab duo
      - gitlab ai
    data_access:
      - source_code
    risk_level: high
    owner: Engineering
```

精度の鍵はこのファイルの整備度。短すぎる `keywords`（3文字以下）は誤マッチを起こしやすいので避ける。

### 情報源の追加・除外

[config/sources.yaml](config/sources.yaml) を編集。`enabled: false` で一時除外可能。

### Teams / Slack 通知の有効化

`.env` に Incoming Webhook URL を追加（片方でも両方でも可）:

```
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
```

両方設定すると **両方のサービスに送信** する。未設定の通知先は自動でスキップ。

#### Slack Webhook 取得手順

1. [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From scratch**
2. 左メニュー **Incoming Webhooks** を **Activate**
3. **Add New Webhook to Workspace** → 通知先チャンネルを選択して許可
4. 表示された `https://hooks.slack.com/services/...` を `.env` の `SLACK_WEBHOOK_URL` にコピー

#### Teams Webhook 取得手順

1. 通知したいチャンネルの「…」→ **コネクタ** → **Incoming Webhook** を **構成**
2. 名前を設定（例: `AI Threat Watch`）→ **作成**
3. 表示されたURLを `.env` の `TEAMS_WEBHOOK_URL` にコピー

## 出力フィールド (Threat Register)

| 列 | 説明 |
|---|---|
| threat_id | `AI-THREAT-NNNN` 形式の連番 |
| collected_at / published_at | 収集日時 / 公開日時 (ISO 8601) |
| source / source_category | 情報源と分類 |
| title / url / summary | タイトル・URL・要約 |
| category | AI Threat Category (Prompt Injection 等) |
| severity | Low / Medium / High / Critical |
| company_impact | Yes / No / Unknown |
| affected_asset | マッチした自社AIアセット |
| reason | 影響判定の理由 |
| recommended_action | 推奨アクション（カテゴリ汎用） |
| tailored_action | High優先度に対するClaude生成の個別対策 |
| priority | High / Medium / Low |
| classifier_used | rule-based / claude |
| status | New / Reviewing / Actioned / Closed / FalsePositive |
| notified | Teams/Slack通知済みフラグ |
| cve_ids | 検出されたCVE ID（カンマ区切り） |
| in_kev | CISA KEV（実環境で悪用中）に掲載されているか |
| kev_due_date | 米連邦機関向けKEV対応期限 |
| epss_max_score | EPSSスコア最大値（0.0-1.0、悪用予測確率） |
| epss_max_cve | epss_max_scoreに対応するCVE |
| reviewed_at / reviewer / review_note | 人間レビューの記録 |
| corrected_category | レビュアーが修正したカテゴリ |

## 通知ルール

`main.py notify` は `priority = High` かつ `notified = 0` のレコードを送信する。
判定ロジックは [classifiers/impact_scorer.py](classifiers/impact_scorer.py) を参照。

## CVE エンリッチメント

`collect` は各脅威からCVE ID (`CVE-YYYY-NNNN`形式) を自動抽出し、以下と突合する:

- **CISA KEV** (Known Exploited Vulnerabilities) — 実環境で悪用中のCVE一覧。1日1回 [data/cache/kev.json](data/cache/kev.json) にキャッシュ
- **EPSS API** (FIRST.org) — 30日以内の悪用予測スコア（0.0-1.0）

`in_kev=True` または `epss>=0.7` を検出すると、`impact_scorer` の `critical_hit` フラグが立ち、優先度がHighに昇格する（AI関連必須ゲートは適用）。

## 人間レビューのフィードバック

AI判定は一次判定のため、レビュアーが修正できる仕組みを用意:

```bash
python main.py review AI-THREAT-0042 \
    --status FalsePositive \
    --correct-category "Not AI-related" \
    --priority Low \
    --note "Cisco IOSの脆弱性で、AI関連ではない"
```

- `status`: New / Reviewing / Actioned / Closed / FalsePositive
- `corrected_category`: 元の `category` は変えず、別カラムに記録（学習データとして活用予定）
- `reviewer`: 未指定時は `$USER` 環境変数を使用

## トラブルシューティング

| 症状 | 対処 |
|---|---|
| `new=0 duplicate=N` ばかり | 正常。新着がないだけ。fingerprintで重複排除されている |
| 特定RSSが warning を出す | サーバー側XML不備が多い（CISA Alerts等）。他フィードは動作するので無視可。長期的に問題ならsources.yamlで `enabled: false` |
| Claude API エラー | `rule-based` に自動フォールバックする。`.env` のキーを確認 |
| 全件やり直したい | `rm data/threat_register.sqlite data/threat_register.csv` してから `collect` |
| 誤分類が多い | `THREAT_WATCH_CLASSIFIER=claude` で精度向上。`company_assets.yaml` のキーワードを単語境界で考慮（短すぎるキーワードを避ける） |

## 自動化

cron で毎朝8時に回す例:

```cron
0 8 * * * cd /home/hacker/Project/threat_watch && .venv/bin/python main.py run >> /var/log/threat-watch.log 2>&1
```

## 注意

- AI分類・影響判定は**一次判定**である。High/Critical/Unknownは必ず人間レビューする
- 一次情報を優先する。RSSの要約だけで結論しない
- `company_assets.yaml` を継続的に最新化することが精度の鍵
- **Unknownを安全扱いしない**。Unknownは「調査対象」として残す
