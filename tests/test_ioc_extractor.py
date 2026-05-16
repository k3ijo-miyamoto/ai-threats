"""Tests for IOC extractor."""

from __future__ import annotations

import json

from classifiers.ioc_extractor import IOCSet, extract_iocs, iocs_to_json_string


class TestIPv4Extraction:
    def test_extracts_public_ipv4(self):
        r = extract_iocs("C2 server at 45.33.32.156 contacted host.")
        assert "45.33.32.156" in r.ipv4

    def test_skips_private_ipv4(self):
        r = extract_iocs("Internal host 10.0.0.5 and 192.168.1.1 affected.")
        assert "10.0.0.5" not in r.ipv4
        assert "192.168.1.1" not in r.ipv4

    def test_skips_loopback(self):
        r = extract_iocs("Connection from 127.0.0.1 detected.")
        assert "127.0.0.1" not in r.ipv4

    def test_skips_documentation_ranges(self):
        # 198.51.100.x is RFC5737 documentation — not a real IOC.
        r = extract_iocs("Example shows 198.51.100.42 only.")
        assert "198.51.100.42" not in r.ipv4

    def test_skips_invalid_octet(self):
        r = extract_iocs("Not an IP: 999.1.1.1")
        assert "999.1.1.1" not in r.ipv4


class TestDefangNormalisation:
    def test_bracket_defang_ip(self):
        r = extract_iocs("Beacon to 45[.]33[.]32[.]156 observed.")
        assert "45.33.32.156" in r.ipv4

    def test_defang_url_scheme(self):
        r = extract_iocs("Drops payload from hxxps://malicious-site.test/payload.exe")
        assert any(u.startswith("https://") for u in r.urls)

    def test_defang_dot_domain(self):
        r = extract_iocs("Exfil to evil[.]example[.]test reported.")
        assert any("evil.example.test" in d for d in r.domains)


class TestDomainExtraction:
    def test_extracts_simple_domain(self):
        r = extract_iocs("Resolves to bad-actor.example-domain.test")
        assert "bad-actor.example-domain.test" in r.domains

    def test_skips_common_blocklist(self):
        r = extract_iocs("See github.com/foo/bar and google.com/search.")
        assert "github.com" not in r.domains
        assert "google.com" not in r.domains

    def test_skips_subdomain_of_blocklist(self):
        r = extract_iocs("Forked from blog.github.com/security article.")
        assert all("github.com" not in d for d in r.domains)


class TestURLExtraction:
    def test_extracts_https_url(self):
        r = extract_iocs("PoC at https://attacker.test/exploit.py")
        assert "https://attacker.test/exploit.py" in r.urls

    def test_strips_trailing_punctuation(self):
        # URL_RE stops at whitespace/closing brackets/quotes.
        r = extract_iocs("See (https://attacker.test/page) for more.")
        assert "https://attacker.test/page" in r.urls


class TestHashExtraction:
    SAMPLE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    SAMPLE_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    SAMPLE_MD5 = "d41d8cd98f00b204e9800998ecf8427e"

    def test_sha256(self):
        r = extract_iocs(f"Sample hash: {self.SAMPLE_SHA256}")
        assert self.SAMPLE_SHA256 in r.sha256

    def test_sha1_not_double_counted_as_md5(self):
        r = extract_iocs(f"SHA1 = {self.SAMPLE_SHA1}")
        assert self.SAMPLE_SHA1 in r.sha1
        # SHA1 is 40 hex chars, MD5 is 32 — they must not collide
        assert self.SAMPLE_SHA1 not in r.md5

    def test_md5(self):
        r = extract_iocs(f"MD5: {self.SAMPLE_MD5}")
        assert self.SAMPLE_MD5 in r.md5

    def test_sha256_inside_sha1_match(self):
        # SHA256 hits should be removed BEFORE searching for SHA1,
        # otherwise a SHA256 would also match the 40-char SHA1 regex.
        r = extract_iocs(self.SAMPLE_SHA256)
        # The first 40 chars of SHA256 would otherwise match SHA1 regex.
        assert r.sha1 == []


class TestBTC:
    def test_extracts_btc(self):
        r = extract_iocs("Payment to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa demanded.")
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in r.btc


class TestJSONSerialization:
    def test_empty_iocs_serialise_to_empty_string(self):
        r = IOCSet()
        assert iocs_to_json_string(r) == ""

    def test_only_populated_fields_present(self):
        r = extract_iocs("45.33.32.156 only")
        out = iocs_to_json_string(r)
        d = json.loads(out)
        assert "ipv4" in d
        assert "sha256" not in d  # not present so should be omitted

    def test_total_count(self):
        r = extract_iocs(
            "45.33.32.156 reached out to attacker.test from 91.198.174.192. "
            "MD5: d41d8cd98f00b204e9800998ecf8427e"
        )
        assert r.total >= 3


class TestMixedInput:
    def test_realistic_threat_blob(self):
        text = (
            "Malware sample c2: hxxps://malicious[.]example[.]test/loader\n"
            "C2 IPs: 45.33.32.156 and 91.198.174.192\n"
            "Internal hop seen at 10.1.2.3 (filtered)\n"
            "SHA256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "Payment address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        )
        r = extract_iocs(text)
        assert "45.33.32.156" in r.ipv4
        assert "91.198.174.192" in r.ipv4
        assert "10.1.2.3" not in r.ipv4  # private, filtered
        # Domain may appear in URL form rather than standalone domain list.
        assert any("malicious.example.test" in u for u in r.urls)
        assert any("https://" in u for u in r.urls)
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in r.sha256
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in r.btc
