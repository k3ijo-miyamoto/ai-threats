# 外部アクセス・API 利用の整理

本プロジェクトが外部ネットワークへ出ていく経路を一覧化したもの。 社内 Security / IT / 法務にレビュー依頼する際の説明資料として使う。

## 1. 外部エンドポイント一覧

| 宛先 | 種類 | 目的 | 認証 | 送信データ | 受信データ |
|---|---|---|---|---|---|
| `api.github.com/advisories` | REST API | GitHub Advisory DB の取得 | `GITHUB_TOKEN` (optional; rate-limit 緩和用) | クエリパラメータのみ | 公開 advisory JSON |
| `api.first.org/data/v1/epss` | REST API | EPSS スコア取得 | なし | CVE ID リスト (URL クエリ) | EPSS スコア JSON |
| `www.cisa.gov/.../known_exploited_vulnerabilities.json` | ファイル DL | CISA KEV カタログ (6h キャッシュ) | なし | (GET のみ) | 公開 JSON |
| 各 RSS フィード — CISA / Microsoft / Google TI / GitHub Security Blog / OpenAI / Anthropic / IPA / JPCERT / JVN | RSS | 脅威情報収集 | なし | (GET のみ) | RSS/Atom XML |
| 各記事ページ URL (`article_fetcher.py` 経由) | HTML scrape | RSS summary が短い時に本文取得 | なし | (GET のみ) | HTML |
| **`api.anthropic.com`** | **REST API** | **Claude による分類・対策生成** | **`ANTHROPIC_API_KEY`** | **脅威タイトル + 本文 + `company_assets.yaml` の内容** | 分類結果 / 対策テキスト |
| `hooks.slack.com/...` | webhook | High 通知 | webhook URL 自体が認証 | 脅威タイトル + 自社アセット名 + 推奨アクション | (なし) |
| `outlook.office.com/...` | webhook | High 通知 (Teams) | webhook URL 自体が認証 | 同上 | (なし) |

## 2. 感度別の分類

### 🟢 一般 web アクセス相当 (低感度)

- RSS フィード各種
- HTML 本文取得 (trafilatura)
- CISA KEV ファイル DL

→ 一般的な curl / web ブラウジングと同じ性質。 社内 proxy 通過していれば追加の承認は基本不要。

### 🟡 防御側情報が間接的に漏れる (中感度)

- **EPSS API**: 「自社が気にしている CVE 群」 が外部に露見する
- **GitHub Advisory API (with token)**: API rate 監査ログでクエリ内容が記録される

→ センシティブ度は低い (防御側情報) が、 監査の観点で記録残す価値あり。

### 🔴 内部情報を含む送信 (要承認)

- **`api.anthropic.com`**: 分類 prompt に脅威本文 + 対策生成 prompt に `company_assets.yaml` 内容 (= 自社利用 AI アセット名) を含む
- **Slack / Teams webhook**: 通知本文に自社アセット名が出る (が、 webhook URL の宛先 = 自社管理下なので外部漏洩ではない)

→ Slack / Teams は自社管理下のため実質内部通信。 **論点は Anthropic API のみ**。

## 3. Anthropic API のグレーゾーン分析

このプロジェクトで唯一「組織として承認確認が必要」 と判断する経路。

### 何が送られるか

- `classifiers/ai_threat_classifier.py:_CLAUDE_SYSTEM_PROMPT` 経由:
  - 脅威 advisory のタイトルと本文 (= 公開情報)
  - 過去のレビュー結果 (few-shot 例) — 自社固有の分類判断が含まれる
- `classifiers/mitigation_advisor.py:_SYSTEM_PROMPT` 経由:
  - 上記に加えて `company_assets.yaml` の自社アセット名 (例: 「GitHub Copilot Business」「MCP Servers」「ChatGPT Enterprise」)

### 比較: GitHub Copilot (会社で承認済の場合)

| 観点 | GitHub Copilot Business | このプロジェクトの Claude API |
|---|---|---|
| 承認対象 | "IDE のコード補完機能" | (個別承認が必要) |
| 送信データ | 編集中のコード / context | 脅威本文 + 自社アセット名 |
| トリガー | 開発者の編集 (人間 in the loop) | cron 自動実行 (人間介在なし) |
| 送信先 | `api.githubcopilot.com` | `api.anthropic.com` |
| 契約上の data handling | Copilot Business 契約 | Anthropic API 契約 (別途締結要) |

**Copilot 承認は前例にはなるが、 自動的に Anthropic API 承認には繋がらない**。 ベンダー単位ではなく、 サービス + 用途単位の承認が原則。

### Security に確認すべき項目

1. Anthropic との DPA (Data Processing Agreement) の有無
   - 既に Claude Code を会社配給で使っているなら多分締結済み
2. Zero data retention 設定の有無
   - 既定の Anthropic API は学習に使わないが、 zero-retention は別途申請が必要
3. `company_assets.yaml` の内容 (自社アセット名 ≒ 情報資産インベントリの一部) を Claude API に送ることが許容範囲か

## 4. リスク回避オプション

Anthropic API 承認が下りない / 待ちの場合の選択肢:

| 方法 | 設定 | トレードオフ |
|---|---|---|
| **rule-based 分類器のみ使用** | `THREAT_WATCH_CLASSIFIER=rule-based` | Claude API を一切使わない。 分類精度が落ちる |
| **個別対策 (mitigation_advisor) 無効化** | `python main.py run` から `advise` ステップを外す | 分類は Claude、 対策生成だけ無効化。 中間案 |
| **SovereignClassifier (社内 LLM) 経由** | (commit 7ca2842 で追加された機能) | 内部の sovereign-agent CLI を使う。 外部送信ゼロ。 ただし社内 LLM 環境のセットアップが必要 |

## 5. 監査・記録のための補足

- 全ての外部 HTTP 通信は `requests` ライブラリ経由 — proxy 設定 (`HTTP_PROXY` / `HTTPS_PROXY`) が効く
- `ANTHROPIC_API_KEY` / `GITHUB_TOKEN` / `SLACK_WEBHOOK_URL` / `TEAMS_WEBHOOK_URL` は `.env` で管理、 git に commit しない (`.gitignore` 済み)
- Anthropic API の呼び出しログは httpx INFO レベルで `python main.py run` 実行時に標準ログに出る — 必要なら `logs/cron.log` を SIEM 取り込み対象に

## 6. Security への提案文 (テンプレ)

レビュー依頼時に貼り付け可能なテキスト:

> AI セキュリティ脅威の継続監視を目的とする内部ツールについて、 以下の外部 API 利用を申請します。
>
> 1. **`api.anthropic.com`** (Claude API) — 公開脅威 advisory の分類 + 自社利用 AI アセット名 (`company_assets.yaml`) を踏まえた対策テキスト生成のため。 既存 Claude Code 利用範囲と同じ送信先・契約を想定。
> 2. **`api.first.org`** (EPSS) — 脆弱性悪用予測スコア取得。 CVE ID のみ送信、 認証不要、 防御側情報の照会のみ。
> 3. **`api.github.com/advisories`** — 公開 advisory DB の取得。 オプションで GITHUB_TOKEN による rate limit 緩和。
>
> 残りは公開 RSS / web ページの GET のみで、 一般 web ブラウジングと同等の性質です。 Slack / Teams webhook は自社管理下の通知チャネル宛のため内部通信扱い。

## 関連

- [docs/architecture.md](../architecture.md) — システム全体図
- [docs/design/post-mythos.md](post-mythos.md) — Mythos 世界線での観測対象拡張案 (= 外部アクセス先が増える方向)
- [CLAUDE.md](../../CLAUDE.md) — グローバル / プロジェクトのセキュリティルール
