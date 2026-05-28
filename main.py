#!/usr/bin/env python3
"""AI Threat Watch — orchestrator CLI.

Usage:
    python main.py collect           # 収集 + 分類 + 影響判定 + 保存
    python main.py notify            # 未通知のHigh PriorityをTeamsへ
    python main.py report [--days 7] # 週次Markdownレポート生成
    python main.py run               # collect -> notify -> report を一括実行
    python main.py stats             # レジスタの統計を表示
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any

import yaml

from classifiers import (
    CVEEnricher,
    ImpactScorer,
    MitigationAdvisor,
    build_classifier,
    extract_iocs,
    iocs_to_json_string,
)
from collectors import ArticleFetcher, GitHubAdvisoryCollector, RSSCollector, ThreatItem
from notifiers import SlackNotifier, TeamsNotifier
from reports import (
    generate_dashboard,
    generate_periodic_report,
    generate_weekly_report,
)
from storage import ThreatRecord, ThreatRegister
from storage.db import now_iso

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"

DEFAULT_SQLITE = DATA_DIR / "threat_register.sqlite"
DEFAULT_CSV = DATA_DIR / "threat_register.csv"

log = logging.getLogger("threat_watch")


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        example = path.with_suffix(".example" + path.suffix)
        if example.exists():
            log.warning("Config %s not found, falling back to %s", path.name, example.name)
            path = example
        else:
            log.warning("Config not found: %s", path)
            return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _build_collectors(sources_cfg: dict[str, Any]) -> list[Any]:
    collectors: list[Any] = []
    for src in sources_cfg.get("sources", []):
        if src.get("enabled", True) is False:
            continue
        kind = (src.get("type") or "").lower()
        name = src.get("name") or "unnamed"
        url = src.get("url") or ""
        category = src.get("category") or "uncategorized"
        if not url:
            log.warning("Skipping source without url: %s", name)
            continue
        if kind == "rss":
            collectors.append(RSSCollector(name=name, url=url, category=category))
        elif kind in ("github_advisory", "api"):
            collectors.append(
                GitHubAdvisoryCollector(
                    name=name, url=url, category=category, params=src.get("params") or {}
                )
            )
        else:
            log.warning("Unknown source type %r for %s", kind, name)
    return collectors


def cmd_collect(args: argparse.Namespace) -> int:
    sources_cfg = _load_yaml(CONFIG_DIR / "sources.yaml")
    company_cfg = _load_yaml(CONFIG_DIR / "company_assets.yaml")

    register = ThreatRegister(DEFAULT_SQLITE, DEFAULT_CSV)
    classifier = build_classifier(args.classifier, sqlite_path=str(DEFAULT_SQLITE))
    scorer = ImpactScorer(company_cfg)
    enricher = CVEEnricher(cache_dir=DATA_DIR / "cache")
    fetcher = ArticleFetcher() if not args.no_fetch_body else None

    log.info("Classifier: %s; article-fetch: %s", classifier.name, "on" if fetcher else "off")

    new_count = 0
    dup_count = 0
    err_count = 0

    for collector in _build_collectors(sources_cfg):
        try:
            items: list[ThreatItem] = collector.collect()
        except Exception as exc:  # noqa: BLE001
            log.exception("Collector %s failed: %s", collector.name, exc)
            err_count += 1
            continue

        for item in items:
            if register.fingerprint_exists(item.fingerprint):
                dup_count += 1
                continue
            # Attempt to extend the summary by fetching the article body.
            if fetcher is not None:
                item.summary = fetcher.enrich_summary(item.url, item.summary)
            try:
                classification = classifier.classify(item.title, item.summary)
                enrichment = enricher.enrich({
                    "title": item.title,
                    "summary": item.summary,
                    "extra": {"source_extra": item.extra},
                })
                iocs = extract_iocs(item.title, item.summary)
                # Match assets/keywords against the classifier's curated summary
                # (or the truncated original if no classifier summary). Matching
                # against the full fetched article body produces false positives
                # — e.g., a GitHub Advisory page that incidentally mentions
                # "Copilot" in unrelated context would otherwise be tagged as
                # affecting GitHub Copilot Business.
                # Also append raw_tags (= package names from GitHub Advisory
                # `vulnerabilities[].package.name`) so an advisory like
                # Starlette BadHost — whose body never mentions "starlette"
                # but whose package tag does — still matches the asset
                # keyword and reaches the impact_scorer.
                matching_text = classification.summary or item.summary[:400]
                if item.raw_tags:
                    matching_text = f"{matching_text}\n[tags: {' '.join(item.raw_tags)}]"
                decision = scorer.score(
                    item.title,
                    matching_text,
                    classification.category,
                    classification.severity,
                    is_ai_related=classification.is_ai_related,
                    in_kev=enrichment.in_kev,
                    epss_score=enrichment.epss_max_score,
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("Classification failed for %s: %s", item.url, exc)
                err_count += 1
                continue

            record = ThreatRecord(
                threat_id=register.next_threat_id(),
                fingerprint=item.fingerprint,
                collected_at=item.collected_at or now_iso(),
                published_at=item.published_at or "",
                source=item.source,
                source_category=item.source_category,
                title=item.title,
                url=item.url,
                summary=classification.summary or item.summary[:400],
                category=classification.category,
                severity=classification.severity,
                company_impact=decision.company_impact,
                affected_asset=decision.affected_asset,
                reason=decision.reason,
                recommended_action=decision.recommended_action,
                priority=decision.priority,
                classifier_used=classification.classifier_used,
                is_ai_related=classification.is_ai_related,
                cve_ids=",".join(enrichment.cve_ids),
                in_kev=enrichment.in_kev,
                kev_due_date=enrichment.kev_due_date,
                kev_known_ransomware=enrichment.kev_known_ransomware,
                epss_max_score=enrichment.epss_max_score,
                epss_max_cve=enrichment.epss_max_cve,
                iocs_json=iocs_to_json_string(iocs),
                extra={"raw_tags": item.raw_tags, "source_extra": item.extra},
            )
            if register.insert(record):
                new_count += 1
            else:
                dup_count += 1

    register.export_csv()
    log.info("Collect done: new=%d duplicate=%d errors=%d", new_count, dup_count, err_count)
    print(f"new={new_count} duplicate={dup_count} errors={err_count}")
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    register = ThreatRegister(DEFAULT_SQLITE, DEFAULT_CSV)
    teams = TeamsNotifier()
    slack = SlackNotifier()

    rows = register.pending_notifications(priorities=("High",))
    if not rows:
        print("No pending High priority notifications.")
        return 0

    if not (teams.enabled or slack.enabled):
        print(f"No notifier configured (teams={teams.enabled} slack={slack.enabled}); pending={len(rows)}")
        return 0

    notified_ids: list[str] = []
    cve_suppressed_ids: list[str] = []
    teams_ok = teams_fail = slack_ok = slack_fail = 0

    for row in rows:
        record = dict(row)
        # CVE-based deduplication: skip if the same CVE has already been notified.
        cve_ids = record.get("cve_ids") or ""
        if cve_ids and not getattr(args, "no_dedup_cve", False):
            prev = register.cve_already_notified(cve_ids)
            if prev:
                cve_suppressed_ids.append(row["threat_id"])
                # Still mark as notified so we don't retry forever, but don't actually send.
                notified_ids.append(row["threat_id"])
                continue

        sent = False
        if teams.enabled:
            if teams.notify(record):
                teams_ok += 1
                sent = True
            else:
                teams_fail += 1
        if slack.enabled:
            if slack.notify(record):
                slack_ok += 1
                sent = True
            else:
                slack_fail += 1
        if sent:
            notified_ids.append(row["threat_id"])

    register.mark_notified(notified_ids)
    print(
        f"sent={len(notified_ids) - len(cve_suppressed_ids)} "
        f"cve_dedup_skipped={len(cve_suppressed_ids)} / pending={len(rows)} "
        f"(teams: ok={teams_ok} fail={teams_fail} enabled={teams.enabled}; "
        f"slack: ok={slack_ok} fail={slack_fail} enabled={slack.enabled})"
    )
    return 0


def cmd_advise(args: argparse.Namespace) -> int:
    """Generate tailored mitigation actions for High-priority items via Claude."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY not set; cannot generate advice. Aborting.")
        return 2

    company_cfg = _load_yaml(CONFIG_DIR / "company_assets.yaml")
    register = ThreatRegister(DEFAULT_SQLITE, DEFAULT_CSV)
    advisor = MitigationAdvisor(company_assets=company_cfg.get("company_ai_assets") or [])

    import sqlite3
    with sqlite3.connect(DEFAULT_SQLITE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT * FROM threat_register "
            "WHERE priority = 'High' AND (tailored_action IS NULL OR tailored_action = '') "
            "ORDER BY collected_at DESC"
        )
        rows = list(cur.fetchall())
        if args.limit:
            rows = rows[: args.limit]

        log.info("Generating tailored actions for %d items", len(rows))
        generated = 0
        for row in rows:
            advice = advisor.advise(dict(row))
            conn.execute(
                "UPDATE threat_register SET tailored_action = ? WHERE threat_id = ?",
                (advice, row["threat_id"]),
            )
            generated += 1
            log.info("  %s: %d chars", row["threat_id"], len(advice))
        conn.commit()

    register.export_csv()
    print(f"advised={generated} (priority=High, missing tailored_action)")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    register = ThreatRegister(DEFAULT_SQLITE, DEFAULT_CSV)
    period = (args.period or "weekly").lower()
    if period == "weekly":
        out_path = REPORTS_DIR / "weekly_report.md"
        path = generate_weekly_report(register, out_path, days=args.days)
    elif period in ("monthly", "quarterly"):
        out_path = REPORTS_DIR / f"{period}_report.md"
        path = generate_periodic_report(register, out_path, period=period)
    else:
        print(f"Unknown period: {period}. Use weekly|monthly|quarterly.")
        return 2
    print(f"report={path}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Render the aggregate Mermaid dashboard to docs/dashboard.md.

    Default output is the tracked `docs/dashboard.md`. The content is
    aggregate-only — counts, generic categories, public source names — and
    intentionally excludes `affected_asset`, individual threat_ids, and
    `company_assets.yaml` contents, so it is safe to publish to the OSS repo
    and link from the README. Override with `--out` if you want a local-only
    copy under `docs/share-*.md`.
    """
    register = ThreatRegister(DEFAULT_SQLITE, DEFAULT_CSV)
    out_path = Path(args.out) if args.out else (ROOT / "docs" / "dashboard.md")
    path = generate_dashboard(register, out_path)
    print(f"dashboard={path}")
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    """Surface CVE/KEV-due-soon items that may slip through normal triage."""
    register = ThreatRegister(DEFAULT_SQLITE, DEFAULT_CSV)
    rows = register.kev_due_within(days=args.kev_due_within)
    if not rows:
        print(f"No KEV-listed items with due date within {args.kev_due_within} days.")
        return 0

    print(f"KEV-listed items with due date <= {args.kev_due_within} days:\n")
    for r in rows:
        d = dict(r)
        ransom = " [RANSOMWARE]" if d.get("kev_known_ransomware") else ""
        print(
            f"  {d['threat_id']} | due={d['kev_due_date']} | "
            f"CVE={d.get('cve_ids') or '-'}{ransom} | priority={d['priority']} | "
            f"status={d['status']} | {d['title'][:60]}"
        )
    return 0


_ALLOWED_STATUSES = {"New", "Reviewing", "Actioned", "Closed", "FalsePositive"}


def cmd_review(args: argparse.Namespace) -> int:
    """Record human review on a threat: status, correction, note."""
    import sqlite3
    from datetime import datetime, timezone

    threat_id = args.threat_id
    updates: list[tuple[str, Any]] = []

    if args.status:
        if args.status not in _ALLOWED_STATUSES:
            print(f"Invalid status. Allowed: {sorted(_ALLOWED_STATUSES)}")
            return 2
        updates.append(("status", args.status))
    if args.correct_category is not None:
        updates.append(("corrected_category", args.correct_category))
    if args.note is not None:
        updates.append(("review_note", args.note))
    if args.priority is not None:
        if args.priority not in ("High", "Medium", "Low"):
            print("Invalid priority. Allowed: High, Medium, Low")
            return 2
        updates.append(("priority", args.priority))

    if not updates:
        print("Nothing to update. Provide at least one of --status / --correct-category / --note / --priority.")
        return 2

    updates.append(("reviewed_at", datetime.now(timezone.utc).isoformat()))
    updates.append(("reviewer", args.reviewer or os.environ.get("USER") or "unknown"))

    set_clause = ", ".join(f"{col} = ?" for col, _ in updates)
    values = [v for _, v in updates] + [threat_id]

    with sqlite3.connect(DEFAULT_SQLITE) as conn:
        cur = conn.execute(f"UPDATE threat_register SET {set_clause} WHERE threat_id = ?", values)
        if cur.rowcount == 0:
            print(f"Threat not found: {threat_id}")
            return 1
        conn.commit()

    register = ThreatRegister(DEFAULT_SQLITE, DEFAULT_CSV)
    register.export_csv()
    print(f"reviewed: {threat_id} ({', '.join(c for c, _ in updates if c not in ('reviewed_at','reviewer'))})")
    return 0


def cmd_stats(_args: argparse.Namespace) -> int:
    register = ThreatRegister(DEFAULT_SQLITE, DEFAULT_CSV)
    stats = register.stats()
    print(f"total: {stats['total']}")
    print("by_priority:")
    for k, v in (stats.get("by_priority") or {}).items():
        print(f"  {k}: {v}")
    print("by_company_impact:")
    for k, v in (stats.get("by_company_impact") or {}).items():
        print(f"  {k}: {v}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    rc = cmd_collect(args)
    if rc != 0:
        return rc
    # Generate tailored advice before notify so Teams/Slack/report all see it.
    if os.environ.get("ANTHROPIC_API_KEY"):
        cmd_advise(args)
    rc = cmd_notify(args)
    if rc != 0:
        return rc
    return cmd_report(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AI Threat Watch")
    parser.add_argument(
        "--log-level",
        default=os.environ.get("THREAT_WATCH_LOG", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_collect = sub.add_parser("collect", help="Collect, classify, score, store")
    p_collect.add_argument("--classifier", default=None, help="rule-based|claude (default: env)")
    p_collect.add_argument("--no-fetch-body", action="store_true", help="Skip article body fetch")
    p_collect.set_defaults(func=cmd_collect)

    p_notify = sub.add_parser("notify", help="Send High priority items to Slack / Teams")
    p_notify.add_argument(
        "--no-dedup-cve",
        action="store_true",
        help="Disable CVE-based deduplication (send even if same CVE was notified before)",
    )
    p_notify.set_defaults(func=cmd_notify)

    p_advise = sub.add_parser("advise", help="Generate tailored mitigations for High items (Claude)")
    p_advise.add_argument("--limit", type=int, default=0, help="Max items (0 = all pending)")
    p_advise.set_defaults(func=cmd_advise)

    p_report = sub.add_parser("report", help="Generate Markdown report (weekly/monthly/quarterly)")
    p_report.add_argument("--period", choices=["weekly", "monthly", "quarterly"], default="weekly")
    p_report.add_argument("--days", type=int, default=7, help="Override window (weekly only)")
    p_report.set_defaults(func=cmd_report)

    p_stats = sub.add_parser("stats", help="Show register statistics")
    p_stats.set_defaults(func=cmd_stats)

    p_dash = sub.add_parser(
        "dashboard",
        help="Render Mermaid dashboard (aggregate counts) to docs/dashboard.md",
    )
    p_dash.add_argument(
        "--out",
        default=None,
        help="Override output path (default: docs/dashboard.md, tracked)",
    )
    p_dash.set_defaults(func=cmd_dashboard)

    p_alerts = sub.add_parser("alerts", help="Show KEV due-date alerts and similar urgencies")
    p_alerts.add_argument(
        "--kev-due-within",
        type=int,
        default=7,
        help="Days until KEV due date to consider urgent (default: 7)",
    )
    p_alerts.set_defaults(func=cmd_alerts)

    p_review = sub.add_parser("review", help="Record human review on a threat record")
    p_review.add_argument("threat_id", help="e.g., AI-THREAT-0042")
    p_review.add_argument("--status", help="New|Reviewing|Actioned|Closed|FalsePositive")
    p_review.add_argument("--correct-category", dest="correct_category", help="Reviewer-corrected category")
    p_review.add_argument("--priority", help="High|Medium|Low (override)")
    p_review.add_argument("--note", help="Free-form review note")
    p_review.add_argument("--reviewer", help="Reviewer identifier (defaults to $USER)")
    p_review.set_defaults(func=cmd_review)

    p_run = sub.add_parser("run", help="collect -> advise (if API key) -> notify -> report")
    p_run.add_argument("--classifier", default=None, help="rule-based|claude (default: env)")
    p_run.add_argument("--period", choices=["weekly", "monthly", "quarterly"], default="weekly")
    p_run.add_argument("--days", type=int, default=7)
    p_run.add_argument("--limit", type=int, default=0, help="Advice limit (0 = all High items)")
    p_run.add_argument("--no-fetch-body", action="store_true", help="Skip article body fetch")
    p_run.set_defaults(func=cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    _load_dotenv(ROOT / ".env")
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
