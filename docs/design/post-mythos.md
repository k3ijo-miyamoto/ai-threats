# Post-Mythos Roadmap — AI Threat Watch をどう延伸するか

Anthropic の [Project Glasswing / Claude Mythos Preview](https://www.anthropic.com/glasswing) が示した能力 (パッチ未公表の OpenBSD/FFmpeg の長年バグ自動発見、Linux kernel の権限昇格チェーン自動生成、CVE → working exploit までを分単位で構成可能) を前提に、本プロジェクトの設計をどう延伸すべきかを整理したメモ。 実装ではなく**論点と優先順位の固定**が目的。

## 背景となる前提変化

Mythos 級モデルが攻撃側にも回った世界線では、以下が定性的に変わる:

1. **時間軸の崩壊** — ベンダーがパッチを出した瞬間に patch diff から working exploit を再構成できる。 KEV の「14 日以内」「30 日以内」という単位は遅すぎる
2. **在庫戦争** — 27 年前の OpenBSD バグが対象になる、ということは現在稼働している全ソフトの歴史的負債が実弾化する。 「アドバイザリすら出していないベンダー」も例外なくターゲットになる
3. **対称性** — 同じモデルが攻撃にも防御にも効く。 持っている組織と持っていない組織の差は技術ではなく**調達と展開の差**

これは「将来こうなる」ではなく、 Glasswing の主張通りなら**既に成立フェーズに入っている**と扱うべき。

## 5 つのレンズ

本プロジェクトをどう延伸するかは、 以下 5 つの軸で独立に議論できる。 どれも別個に進められる。

### 1. 時間軸 — 「どこが遅いか」

- 現状: 1 日 1 回 cron → Slack
- 問い: ボトルネックは収集間隔 (cron) か、 分類 (LLM call latency) か、 個別対策生成 (advise) か、 通知か
- やるなら: 収集を event-driven に切り替える (RSS poll → webhook / GitHub Action / patch-diff stream)
- トレードオフ: API レート / コスト / 誤検知通知の頻度が跳ねる

### 2. 観測対象軸 — 「何を見るか」

- 現状: CVE / Advisory (= ベンダーが書いた説明文)
- Mythos 世界の追加対象:
  - **patch-diff** — ベンダーの commit そのもの。 説明文より早く・正確
  - **自社 SBOM / 在庫** — 守るべき対象の現在地。 これが古いと外側の速度が上がっても無意味
  - **内向き telemetry** — Agent / MCP / Copilot の振る舞いログ
- やるなら: `collectors/github_patch_watcher.py` 追加、 storage に SBOM テーブル追加
- トレードオフ: SBOM は組織横断データで本プロジェクト単独では持てない → IT との合流地点が必要

### 3. アクション軸 — 「人間の判断範囲を狭める」

- 現状: High → 人間が読んで対応
- Mythos 世界: 判断は人間でも、 **判断材料を機械可読アーティファクトで提示**しないと間に合わない
- やるなら: `tailored_action` を自然文の bullet から **実行可能な PR テンプレ / Ansible playbook / k8s patch** へ昇格
- トレードオフ: 誤った自動アクションは悪化要因。 「提案するが実行はしない」のラインをどう引くか

### 4. 信頼軸 — 「これは本物か」

- Mythos 世界では PR の説明文、 メール、 commit message、 npm パッケージのメタデータ、 全部が**生成可能**
- 問い: 自社が受け取る externally-generated コンテンツ (PR, npm, MCP tool, 拡張機能) の **provenance verification** をどこに置くか
- やるなら: classifier に「この情報源が本物か」軸を追加 (署名 / SLSA レベル / メンテナ履歴の長さ等)
- トレードオフ: 一次情報源の取捨選択そのものが攻撃対象になる (ベンダーの blog 自体が改ざんされる、 等)

### 5. 対称性軸 — 「自分にも Mythos を撃つ」

- 防御だけでなく **自社 AI Asset の脆弱性を Mythos 級で自分で探す**観点
- やるなら: 出口を「外部脅威の watch」だけでなく**社内 Prompt Injection 演習 / MCP server の自動ファジング**に伸ばす
- トレードオフ: スコープが Threat Intelligence から Offensive Security に半分はみ出す。 別プロジェクト化するべきかも

## 優先順位 (現時点の見立て)

**2 → 1 → 4 → 3 → 5** を推す。

- **2 (観測対象)** が一番ボトルネック。 外側が速くなっても自社 SBOM が古ければ意味がない。 ここを整えると 1 / 4 が自然に効いてくる
- **1 (時間軸)** は技術的にすぐ手が付くが、 観測対象を増やさず polling を速くしてもコストが増えるだけ
- **5 (対称性)** は戦略的に重要だが、 本プロジェクトのスコープを越える。 別の場に置く方がよい

## 直近の MVP 候補: Phase 2.5

> **ベンダーのセキュリティ commit を patch-diff レベルで監視 → 自社 SBOM と照合 → 該当があれば即 High**

つまり:

```
GitHub Security Advisory commit feed
       ↓
patch_watcher.py (新規 collector)
       ↓
diff から影響範囲を Claude で抽出
       ↓
SBOM (新規テーブル: package_name, version, where_used)
       ↓
照合 → match なら priority=High で即通知
       ↓
tailored_action は「該当バージョンを X に上げる PR テンプレート」を生成
```

これだけで「ベンダーがパッチを書いた瞬間に自社の該当箇所が High として上がる」が実現できる。 SBOM の整備が前提条件として浮上するため、 IT / Engineering との合意形成が同時に必要になる。

## 既知の論点・未解決

- **SBOM をどこから取るか** — `npm ls --json`, `pip freeze`, `cargo tree`, `syft`, ... 言語別に複数。 集約レイヤをどこに置くか未決
- **patch-diff の取得元** — GitHub Advisory API には commit リンクがあるが、 ベンダー独自リポでは推測が必要
- **コスト試算** — Claude API での diff 解析を毎 commit やると月額が読みづらい。 「security-labeled commit のみ」で絞る選別ロジックが先に要る
- **アクション提案 (PR テンプレ生成) の検証** — 自動 PR が誤った内容を提案した場合の責任分界点。 「マージは必ず人間」を初期不変条件として明示するか

## 関連レコード

- AI-THREAT-0238 (Mini Shai Hulud, @antv npm 汚染) — Mythos 不要でも起きた、 が、 Mythos 世界では汚染パッケージの**追加バックドア発見**まで自動化される
- AI-THREAT-0244 (VS Code 拡張による GitHub 内部リポ流出) — 流出した内部コードを Mythos に読ませることで二次攻撃用 0-day を抽出する**サイクル**が回り始める

## メモ

- このドキュメントは「決定」ではなく**論点の固定**。 実装着手前に各レンズで議論されることを想定
- 5 つのレンズすべてを同時にやるのは過剰。 まず Phase 2.5 (= レンズ 2 の最小実装) のスコープを切ることから
