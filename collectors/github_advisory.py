from __future__ import annotations

import logging
import os
from typing import Any

import requests

from .base import Collector, ThreatItem

log = logging.getLogger(__name__)


class GitHubAdvisoryCollector(Collector):
    """Collect security advisories from the public GitHub Advisory Database API."""

    REQUEST_TIMEOUT = 30
    DEFAULT_PER_PAGE = 50
    # Do NOT filter by severity at the API call. GitHub's `severity` query
    # parameter accepts only one value (e.g. "high"), so passing "high"
    # silently drops every Medium/Moderate (CVSS 4–6.9) advisory — and many
    # AI-relevant issues land in that band (Starlette CVE-2026-48710 BadHost
    # is a textbook case: CVSS 6.5 Medium, but as the routing layer beneath
    # FastAPI/MCP/vLLM/LiteLLM it is effectively High in our environment).
    # Let the impact_scorer make the priority call after asset matching and
    # the AI-relevance gate, instead of cutting at the API.
    DEFAULT_SEVERITY = ""

    def collect(self) -> list[ThreatItem]:
        log.info("GitHub Advisory collect: %s", self.url)
        params = self.options.get("params") or {}
        per_page = int(params.get("per_page", self.DEFAULT_PER_PAGE))
        severity = params.get("severity", self.DEFAULT_SEVERITY)

        query: dict[str, Any] = {"per_page": per_page}
        if severity:
            query["severity"] = severity

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AIThreatWatch/0.1",
        }
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            resp = requests.get(
                self.url, headers=headers, params=query, timeout=self.REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException as exc:
            log.warning("GitHub Advisory request failed: %s", exc)
            return []
        except ValueError as exc:
            log.warning("GitHub Advisory JSON decode failed: %s", exc)
            return []

        if not isinstance(payload, list):
            log.warning("GitHub Advisory unexpected payload type: %s", type(payload))
            return []

        items: list[ThreatItem] = []
        for adv in payload:
            ghsa = adv.get("ghsa_id") or adv.get("id") or ""
            title = adv.get("summary") or ghsa or "GitHub Advisory"
            url = adv.get("html_url") or adv.get("url") or ""
            if not url:
                continue
            description = adv.get("description") or ""
            cve = adv.get("cve_id") or ""
            severity_val = adv.get("severity") or ""
            published = adv.get("published_at") or adv.get("updated_at") or ""

            summary_parts = [description[:3500]]
            if cve:
                summary_parts.append(f"CVE: {cve}")
            if severity_val:
                summary_parts.append(f"Severity: {severity_val}")
            summary = " | ".join(p for p in summary_parts if p)

            extra = {
                "ghsa_id": ghsa,
                "cve_id": cve,
                "severity": severity_val,
                "cvss_score": (adv.get("cvss") or {}).get("score"),
            }

            tags: list[str] = []
            for v in adv.get("vulnerabilities") or []:
                pkg = (v.get("package") or {}).get("name")
                if pkg:
                    tags.append(pkg)

            items.append(
                ThreatItem(
                    source=self.name,
                    source_category=self.category,
                    title=str(title)[:500],
                    url=str(url),
                    summary=summary,
                    published_at=str(published),
                    raw_tags=tags,
                    extra=extra,
                )
            )

        log.info("GitHub Advisory collected %d items", len(items))
        return items
