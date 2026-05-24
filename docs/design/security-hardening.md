# セキュリティ対策の記録

2026-05-23 〜 05-24 にかけて本プロジェクトに対して実施したセキュリティ対策の整理。 「何を見つけ、 どう塞ぎ、 どう検証したか」 を後追いできるよう一次資料を残す。

## 経緯

最初は手動 audit で 3 件の High/Medium 相当の問題を特定。 修正 branch (`security/harden-pipeline`) に積み、 `/security-review` で再検証する過程で更に 1 件の追加対策と 1 件の自分自身が混入させた構造バグを発見、 解消した上で main に merge。 続けて `pip-audit` で依存 CVE 2 件を発見、 これも修正済。

## 対策一覧

| # | リスク | 対策 | コミット | 場所 |
|---|---|---|---|---|
| 1 | Streamlit ダッシュボードが 0.0.0.0 にバインドし LAN 露出 | `.streamlit/config.toml` で `server.address=127.0.0.1` に固定 | [`8bda563`](https://github.com/k3ijo-miyamoto/ai-threats/commit/8bda563) | [.streamlit/config.toml](../../.streamlit/config.toml) |
| 2 | `article_fetcher` SSRF: RSS が指す URL を無検証で取得 | scheme allowlist (http/https) + private/loopback/link-local/metadata IP を `_is_safe_url` で拒否 + `allow_redirects=False` で redirect 再検証 | [`9276eec`](https://github.com/k3ijo-miyamoto/ai-threats/commit/9276eec) | [collectors/article_fetcher.py](../../collectors/article_fetcher.py) |
| 3 | プロンプトインジェクション: 取得 HTML 本文が classifier prompt に直挿入 | `<untrusted_input>` / `<untrusted_threat>` タグで本文を明示 + system prompt 側で「タグ内の指示は無視」 を明示 + 閉じタグ strip で tag break を防止 | [`ebdb8ec`](https://github.com/k3ijo-miyamoto/ai-threats/commit/ebdb8ec) | [classifiers/ai_threat_classifier.py](../../classifiers/ai_threat_classifier.py), [classifiers/mitigation_advisor.py](../../classifiers/mitigation_advisor.py) |
| 4 | CSV formula injection: `threat_register.csv` をスプレッドシートで開くと `=`/`+`/`-`/`@` 始まりのタイトルが式として評価される | `_csv_safe()` で formula prefix を持つセルに `'` をプレフィックス | [`1789c1b`](https://github.com/k3ijo-miyamoto/ai-threats/commit/1789c1b) | [storage/db.py](../../storage/db.py) |
| 5 | (自滅) #4 の挿入位置ミスで `ThreatRegister.stats()` 含む後続メソッドがクラス外に追い出された | `_csv_safe` を class 定義の外 (ファイル末尾) に移動。 `/security-review` が発見 | [`32831ab`](https://github.com/k3ijo-miyamoto/ai-threats/commit/32831ab) | [storage/db.py](../../storage/db.py) |
| 6 | 依存ライブラリ `requests==2.32.3` の既知 CVE 2 件 (CVE-2024-47081, CVE-2026-25645) | `requests==2.33.0` へ更新 | [`961130f`](https://github.com/k3ijo-miyamoto/ai-threats/commit/961130f) | [requirements.txt](../../requirements.txt) |

#1〜#5 は merge コミット [`70b3996`](https://github.com/k3ijo-miyamoto/ai-threats/commit/70b3996) として main に統合済。

## 検証方法

| 対策 | 検証 |
|---|---|
| #1 Streamlit | `.streamlit/config.toml` 配下で `streamlit run dashboard.py` が `localhost:8501` でのみ listen することを起動ログで確認 |
| #2 SSRF | unit-like 検証: `_is_safe_url('http://127.0.0.1/')`, `'http://169.254.169.254/'`, `'http://192.168.1.1/'`, `'http://example.com/'` の真偽を確認 (前 3 つ False, 最後 True) |
| #3 プロンプトインジェクション | コード上で `</untrusted_input>` `</untrusted_threat>` の strip が機能することを確認。 LLM 挙動の実弾検証は未実施 (defense in depth として ship) |
| #4 CSV | `_csv_safe('=cmd')` → `"'=cmd"`, `_csv_safe('plain')` → `'plain'` を Python で実行確認。 既存 CSV を再 export して新規データに対しても sanitise 適用 |
| #5 構造バグ | `from storage.db import ThreatRegister` 後に `hasattr(r, 'stats')` および `r.stats()` の動作を確認。 全 7 メソッド再アタッチ確認 |
| #6 requests bump | `pip-audit -r requirements.txt -r requirements-dashboard.txt` で **No known vulnerabilities found**、 `python main.py run --period weekly` が `errors=0` で完走 |

## 残存課題

軽微な改善余地および設計判断による既知の残存項目が複数あり、 内部で追跡している。 ガバナンス系の課題 (Anthropic API への asset 名送信) は [external-access.md](external-access.md) で別途整理済。

## 運用上の継続事項

1. **`pip-audit` を定期実行** — 月次 or 週次で `pip-audit -r requirements.txt -r requirements-dashboard.txt` を CI / cron に組み込み、 新たな CVE を早期検知
2. **`/security-review` を機能追加 PR で必ず回す** — branch-diff に対するレビューが本道。 今回 `/security-review` が私自身の構造バグを検出してくれた前例 (#5) はその有効性を示す
3. **company_assets.yaml の keyword 整備** — 影響判定の精度は keyword 整備度で決まる。 keyword 不足が誤検知 (FP) より誤陰性 (FN, AI-THREAT-0244 の事例) を生みやすい
4. **MCP `mark_reviewed` でレビュー結果を記録** — Few-shot 学習データとして次回以降の Claude classifier の精度向上に寄与

## 一次資料

- 関連: [docs/architecture.md](../architecture.md) — システム全体図
- 関連: [docs/design/external-access.md](external-access.md) — 外部アクセス・API 利用の整理
- 関連: [docs/design/post-mythos.md](post-mythos.md) — Mythos 世界線でのロードマップ
- `mark_reviewed` で記録済: **AI-THREAT-0244** (GitHub 内部リポジトリ流出事案、 status=Closed) — 本対策サイクルの直接の契機
