import hashlib

import pytest

from tipipeline.extract.iocs import extract_text, normalise, refang


def observed(text):
    return {(item.type, item.value): item for item in extract_text(text)}


def test_refangs_domains_urls_email_and_ipv6_without_network():
    text = """Indicators of Compromise
hXXps[:]//Evil[.]com/a.zip?q=1
bad(.)net
analyst [at] evil [dot] org
8[.]8[.]4[.]4
2606:4700:4700::1111
"""
    items = observed(text)
    assert ("url", "https://evil.com/a.zip?q=1") in items
    assert ("domain", "evil.com") in items
    assert ("domain", "bad.net") in items
    assert ("email", "analyst@evil.org") in items
    assert ("ipv4", "8.8.4.4") in items
    assert ("ipv6", "2606:4700:4700::1111") in items
    assert ("domain", "a.zip") not in items
    assert all(item.context == "ioc_section" for item in items.values())
    assert refang("hxxp://x{.}net hxxps[:]//z.net")[0] == "http://x.net https://z.net"


def test_filename_and_code_field_heuristics_require_strong_evidence():
    items = observed("payload.exe run.ps1 x.dll archive.zip script.sh source.py video.mov System.IO process.name subprocess.run ordinary.com.\n"
                     "Defanged invoice[.]zip, and URL https://host.sh/payload.zip.\n"
                     "## IoCs\nlisted.py\n## References\nnot-listed.mov")
    values = {value for type_, value in items if type_ == "domain"}
    assert values == {"ordinary.com", "invoice.zip", "host.sh", "listed.py"}
    assert items["domain", "ordinary.com"].context == "body"
    assert items["domain", "listed.py"].context == "ioc_section"


@pytest.mark.parametrize("value", ["10.0.0.1", "127.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1",
                                   "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
                                   "0.0.0.0", "::1", "fe80::1", "fd00::1", "ff02::1", "2001:db8::1"])
def test_non_public_ips_are_dropped_even_from_explicit_iocs(value):
    assert not any(item.type in {"ipv4", "ipv6", "url"} for item in extract_text(f"IOCs\n{value}\nhttp://[{value}]/x"))


def test_cve_hash_normalization_placeholders_and_section_preference():
    md5 = hashlib.md5(b"sample malware").hexdigest()
    sha1 = hashlib.sha1(b"sample malware").hexdigest()
    sha256 = hashlib.sha256(b"sample malware").hexdigest()
    empty = hashlib.sha256(b"").hexdigest()
    text = f"evil.net cve-2025-12345 {md5.upper()} {sha1.upper()} {sha256.upper()} {empty} {'0'*32}\nIOCs\nevil.net\nReferences\n8.8.8.8"
    items = observed(text)
    assert items["domain", "evil.net"].context == "ioc_section"
    assert items["ipv4", "8.8.8.8"].context == "body"
    assert ("cve", "CVE-2025-12345") in items
    assert {value for type_, value in items if type_ in {"md5", "sha1", "sha256"}} == {md5, sha1, sha256}
    assert len(items["domain", "evil.net"].snippet) <= 200
    assert not observed("version 8.8.8.8 v9.9.9.9 1.2.3.4.5")


@pytest.mark.parametrize("value,expected", [("8.8.8.8:443", ("ipv4", "8.8.8.8")),
                                          ("[2606:4700::1111]:8443", ("ipv6", "2606:4700::1111")),
                                          ("2606:4700::1111", ("ipv6", "2606:4700::1111")),
                                          ("192.168.1.1:443", None), ("8.8.8.8:99999", None)])
def test_threatfox_ip_port_normalization(value, expected):
    assert normalise("ip:port", value) == expected
