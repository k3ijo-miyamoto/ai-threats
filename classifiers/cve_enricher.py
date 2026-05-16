from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger(__name__)


CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

KEV_CACHE_TTL_SECONDS = 6 * 3600  # 6 hours


@dataclass
class CVEEnrichment:
    cve_ids: list[str] = field(default_factory=list)
    in_kev: bool = False
    kev_due_date: str = ""
    kev_known_ransomware: bool = False
    epss_max_score: float = 0.0
    epss_max_cve: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CVEEnricher:
    """Extract CVE IDs and enrich each item with CISA KEV / EPSS data.

    - KEV: full feed cached locally; lookup is O(1)
    - EPSS: batched HTTP queries with a small in-memory cache for the session
    """

    REQUEST_TIMEOUT = 30

    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._kev: dict[str, dict[str, Any]] | None = None
        self._epss_cache: dict[str, float] = {}

    # ------------------------------------------------------------------ #
    # KEV
    # ------------------------------------------------------------------ #

    def _kev_cache_path(self) -> Path:
        return self.cache_dir / "kev.json"

    def _load_kev(self) -> dict[str, dict[str, Any]]:
        if self._kev is not None:
            return self._kev

        path = self._kev_cache_path()
        fresh_enough = path.exists() and (time.time() - path.stat().st_mtime) < KEV_CACHE_TTL_SECONDS

        if not fresh_enough:
            try:
                resp = requests.get(
                    KEV_URL,
                    timeout=self.REQUEST_TIMEOUT,
                    headers={"User-Agent": "AIThreatWatch/0.1"},
                )
                resp.raise_for_status()
                path.write_bytes(resp.content)
                log.info("KEV catalog refreshed (%d bytes)", len(resp.content))
            except requests.RequestException as exc:
                log.warning("KEV refresh failed (%s); using stale cache if present", exc)
                if not path.exists():
                    self._kev = {}
                    return self._kev

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("KEV parse failed: %s", exc)
            self._kev = {}
            return self._kev

        index: dict[str, dict[str, Any]] = {}
        for v in data.get("vulnerabilities") or []:
            cve = v.get("cveID")
            if cve:
                index[cve.upper()] = v
        self._kev = index
        log.info("KEV indexed: %d entries", len(index))
        return index

    # ------------------------------------------------------------------ #
    # EPSS
    # ------------------------------------------------------------------ #

    def _fetch_epss(self, cves: list[str]) -> dict[str, float]:
        unknown = [c for c in cves if c.upper() not in self._epss_cache]
        if not unknown:
            return {c: self._epss_cache.get(c.upper(), 0.0) for c in cves}

        # API accepts comma-separated list; chunk to avoid URL length limits.
        for chunk_start in range(0, len(unknown), 50):
            chunk = unknown[chunk_start : chunk_start + 50]
            try:
                resp = requests.get(
                    EPSS_URL,
                    params={"cve": ",".join(chunk)},
                    timeout=self.REQUEST_TIMEOUT,
                    headers={"User-Agent": "AIThreatWatch/0.1"},
                )
                resp.raise_for_status()
                payload = resp.json()
            except (requests.RequestException, ValueError) as exc:
                log.warning("EPSS lookup failed for %s: %s", chunk[:3], exc)
                # Mark them as 0.0 so we don't keep retrying within the session
                for c in chunk:
                    self._epss_cache[c.upper()] = 0.0
                continue

            for entry in payload.get("data") or []:
                cve = (entry.get("cve") or "").upper()
                try:
                    score = float(entry.get("epss") or 0.0)
                except ValueError:
                    score = 0.0
                self._epss_cache[cve] = score
            # Anything not returned is implicitly 0.0
            for c in chunk:
                self._epss_cache.setdefault(c.upper(), 0.0)

        return {c: self._epss_cache.get(c.upper(), 0.0) for c in cves}

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #

    @staticmethod
    def extract_cves(*texts: str) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for t in texts:
            if not t:
                continue
            for match in CVE_PATTERN.findall(t):
                cid = match.upper()
                if cid not in seen:
                    seen.add(cid)
                    ordered.append(cid)
        return ordered

    def enrich(self, record: dict[str, Any]) -> CVEEnrichment:
        title = record.get("title") or ""
        summary = record.get("summary") or ""
        extra = record.get("extra") or {}
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except json.JSONDecodeError:
                extra = {}
        extra_cve = (extra.get("source_extra") or {}).get("cve_id") if isinstance(extra, dict) else ""

        cves = self.extract_cves(title, summary, extra_cve or "")
        if not cves:
            return CVEEnrichment()

        kev = self._load_kev()
        in_kev = False
        kev_due = ""
        kev_ransom = False
        for c in cves:
            entry = kev.get(c)
            if entry:
                in_kev = True
                kev_due = kev_due or (entry.get("dueDate") or "")
                if str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known":
                    kev_ransom = True
                break

        epss_scores = self._fetch_epss(cves)
        max_cve, max_score = "", 0.0
        for cve, score in epss_scores.items():
            if score > max_score:
                max_score = score
                max_cve = cve

        return CVEEnrichment(
            cve_ids=cves,
            in_kev=in_kev,
            kev_due_date=kev_due,
            kev_known_ransomware=kev_ransom,
            epss_max_score=max_score,
            epss_max_cve=max_cve,
        )
