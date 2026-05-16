"""Storage layer tests: schema migration, fingerprint dedup, CSV export."""

from __future__ import annotations

import csv
import sqlite3

import pytest

from storage import ThreatRecord, ThreatRegister
from storage.db import now_iso


def _make_record(threat_id="AI-THREAT-0001", fingerprint="abc123", **overrides):
    base = dict(
        threat_id=threat_id,
        fingerprint=fingerprint,
        collected_at=now_iso(),
        published_at="",
        source="test",
        source_category="test",
        title="Test title",
        url="https://example.com/1",
        summary="Test summary",
        category="Other Security",
        severity="Medium",
        company_impact="Unknown",
        affected_asset="",
        reason="Test",
        recommended_action="Test action",
        priority="Medium",
        classifier_used="rule-based",
        is_ai_related=False,
    )
    base.update(overrides)
    return ThreatRecord(**base)


class TestInsertAndDedup:
    def test_insert_new_record(self, tmp_register):
        ok = tmp_register.insert(_make_record(fingerprint="fp-1"))
        assert ok is True

    def test_duplicate_fingerprint_rejected(self, tmp_register):
        tmp_register.insert(_make_record(threat_id="A-1", fingerprint="dup"))
        ok = tmp_register.insert(_make_record(threat_id="A-2", fingerprint="dup"))
        assert ok is False

    def test_fingerprint_exists(self, tmp_register):
        tmp_register.insert(_make_record(fingerprint="known-fp"))
        assert tmp_register.fingerprint_exists("known-fp") is True
        assert tmp_register.fingerprint_exists("missing-fp") is False

    def test_next_threat_id_increments(self, tmp_register):
        assert tmp_register.next_threat_id() == "AI-THREAT-0001"
        tmp_register.insert(_make_record(threat_id="AI-THREAT-0001", fingerprint="fp-1"))
        assert tmp_register.next_threat_id() == "AI-THREAT-0002"


class TestCSVExport:
    def test_csv_export_writes_header(self, tmp_register):
        tmp_register.export_csv()
        assert tmp_register.csv_path.exists()
        rows = list(csv.reader(tmp_register.csv_path.open()))
        assert "threat_id" in rows[0]

    def test_csv_export_contains_record(self, tmp_register):
        tmp_register.insert(_make_record(threat_id="AI-THREAT-0042", fingerprint="fp-42"))
        tmp_register.export_csv()
        text = tmp_register.csv_path.read_text()
        assert "AI-THREAT-0042" in text


class TestSchemaMigration:
    def test_migration_idempotent(self, tmp_path):
        path = tmp_path / "mig.sqlite"
        # First init creates fresh schema.
        ThreatRegister(path)
        # Re-opening must not fail or duplicate columns.
        ThreatRegister(path)
        with sqlite3.connect(path) as conn:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(threat_register)")]
        # Columns added by migrations must be present.
        for c in ("tailored_action", "cve_ids", "in_kev", "kev_due_date",
                  "epss_max_score", "reviewer", "reviewed_at"):
            assert c in cols, f"missing column after migration: {c}"


class TestQueries:
    def test_cve_already_notified(self, tmp_register):
        r = _make_record(
            threat_id="A-1", fingerprint="fp-cve",
            cve_ids="CVE-2024-3094",
        )
        tmp_register.insert(r)
        tmp_register.mark_notified(["A-1"])

        # Same CVE should match.
        matches = tmp_register.cve_already_notified("CVE-2024-3094")
        assert len(matches) == 1

        # Different CVE should not.
        matches = tmp_register.cve_already_notified("CVE-1999-0001")
        assert matches == []

    def test_kev_due_within_filters_by_date(self, tmp_register):
        from datetime import datetime, timedelta, timezone
        soon = (datetime.now(timezone.utc) + timedelta(days=3)).date().isoformat()
        far = (datetime.now(timezone.utc) + timedelta(days=60)).date().isoformat()

        tmp_register.insert(_make_record(
            threat_id="A-soon", fingerprint="fp-soon",
            in_kev=True, kev_due_date=soon,
        ))
        tmp_register.insert(_make_record(
            threat_id="A-far", fingerprint="fp-far",
            in_kev=True, kev_due_date=far,
        ))

        within7 = tmp_register.kev_due_within(7)
        ids = [r["threat_id"] for r in within7]
        assert "A-soon" in ids
        assert "A-far" not in ids
