"""Extract Indicators of Compromise (IOCs) from threat text.

Detected types:
- IPv4 addresses (excluding RFC1918 / loopback / link-local / multicast / TEST-NET)
- Domains (excluding common false positives)
- URLs (http/https/ftp)
- SHA256 / SHA1 / MD5 hashes
- Bitcoin addresses (legacy P2PKH/P2SH; Bech32 not yet)

Defanged forms commonly used in threat reports are normalised:
    1.2.3[.]4  → 1.2.3.4
    hxxps://   → https://
    evil[.]com → evil.com
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field, asdict
from typing import Any


# --------------------------------------------------------------------------- #
# Defang normalisation
# --------------------------------------------------------------------------- #

_DEFANG_DOT = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\s+\.\s+")
_DEFANG_SCHEME = re.compile(r"\bhxxps?://", re.IGNORECASE)
_DEFANG_AT = re.compile(r"\[at\]|\(at\)", re.IGNORECASE)


def _refang(text: str) -> str:
    if not text:
        return ""
    text = _DEFANG_SCHEME.sub(lambda m: m.group(0).lower().replace("hxxp", "http"), text)
    text = _DEFANG_DOT.sub(".", text)
    text = _DEFANG_AT.sub("@", text)
    return text


# --------------------------------------------------------------------------- #
# Patterns
# --------------------------------------------------------------------------- #

# IPv4: 4 groups of 0-255 (validated separately).
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# URLs
_URL_RE = re.compile(r"\bhttps?://[^\s<>'\"\)\]]+", re.IGNORECASE)

# Hashes (strict word boundaries)
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# Bitcoin addresses (legacy P2PKH start with 1, P2SH start with 3)
_BTC_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

# Domains: token with at least one dot and a TLD-like end.
# Conservative: require 2+ letters in TLD, max 63 chars per label.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

# Domains we never want to flag (project sites, code hosts, etc.)
_DOMAIN_BLOCKLIST: frozenset[str] = frozenset({
    "example.com", "example.org", "example.net",
    "github.com", "gitlab.com", "bitbucket.org",
    "google.com", "microsoft.com", "anthropic.com",
    "openai.com", "cloudflare.com", "amazon.com",
    "twitter.com", "x.com", "youtube.com",
    "linkedin.com", "facebook.com",
    "wikipedia.org", "schema.org",
    "schemas.org", "w3.org",
    "first.org",  # EPSS — we hit it ourselves
    "cisa.gov", "nist.gov", "ipa.go.jp", "jpcert.or.jp", "jvn.jp",
    "mitre.org",
})


def _is_public_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return True


def _is_useful_domain(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    if domain in _DOMAIN_BLOCKLIST:
        return False
    # Strip subdomain for blocklist check (e.g., "blog.github.com")
    parts = domain.split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in _DOMAIN_BLOCKLIST:
        return False
    # Skip pure numeric TLD-ish junk (catches some false positives)
    if parts[-1].isdigit():
        return False
    return True


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


@dataclass
class IOCSet:
    ipv4: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    btc: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return sum(len(v) for v in self.to_dict().values())

    def to_dict(self) -> dict[str, list[str]]:
        return asdict(self)


def _uniq(seq):
    seen: set = set()
    out: list = []
    for x in seq:
        key = x.lower() if isinstance(x, str) else x
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out


def extract_iocs(*texts: str) -> IOCSet:
    """Extract IOCs from one or more text blobs. Returns an IOCSet."""
    iocs = IOCSet()
    blob = "\n".join(_refang(t) for t in texts if t)
    if not blob:
        return iocs

    # Hashes — must come before domain/IP to avoid the hash hex being
    # mis-matched as something else.
    sha256_matches = _SHA256_RE.findall(blob)
    iocs.sha256 = _uniq(h.lower() for h in sha256_matches)
    # Remove SHA256 hits from the blob before SHA1/MD5 to avoid overlap.
    blob_no_sha256 = _SHA256_RE.sub(" ", blob)
    sha1_matches = _SHA1_RE.findall(blob_no_sha256)
    iocs.sha1 = _uniq(h.lower() for h in sha1_matches)
    blob_no_sha1 = _SHA1_RE.sub(" ", blob_no_sha256)
    md5_matches = _MD5_RE.findall(blob_no_sha1)
    iocs.md5 = _uniq(h.lower() for h in md5_matches)

    # URLs (extract first so we can strip the URL bodies from domain matching).
    urls = _URL_RE.findall(blob)
    iocs.urls = _uniq(urls)

    # IPs — keep only public addresses.
    candidate_ips = _IPV4_RE.findall(blob)
    iocs.ipv4 = _uniq(ip for ip in candidate_ips if _is_public_ip(ip))

    # Domains — drop the URL portions so we don't double-count host parts.
    blob_for_domains = _URL_RE.sub(" ", blob)
    domains = _DOMAIN_RE.findall(blob_for_domains)
    iocs.domains = _uniq(d.lower() for d in domains if _is_useful_domain(d))

    # BTC
    iocs.btc = _uniq(_BTC_RE.findall(blob_no_sha1))

    return iocs


def iocs_to_json_string(iocs: IOCSet) -> str:
    """Produce a compact JSON representation suitable for DB storage."""
    import json
    d = iocs.to_dict()
    # Drop empty lists to keep storage compact.
    compact = {k: v for k, v in d.items() if v}
    return json.dumps(compact, ensure_ascii=False) if compact else ""
