"""Offline IOC parsing, normalization and provenance.

A public suffix is necessary but not sufficient: .zip/.sh/.py/.mov and
similar extensions, and dotted code-field names, require defanging, an IOC
heading, or a URL hostname. This avoids promoting ordinary filenames/code
into threat indicators without losing explicitly presented indicators.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

import tldextract

SUFFIXES = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
FILE_SUFFIXES = frozenset("zip sh py mov pl rs md ps so one app run ai cc ms ml mk tf bz gs ws mp cab".split())
CODE_OBJECTS = frozenset("self window document process file host event user node object source request response config os sys socket console".split())
CODE_FIELDS = frozenset("name id info type data host code path net io".split())
EMPTY_HASHES = {hashlib.md5(b"").hexdigest(), hashlib.sha1(b"").hexdigest(), hashlib.sha256(b"").hexdigest()}
DEFANG = re.compile(
    r"hxxps?|hxps?|fxp|\[\s*:\s*\]|\(\s*:\s*\)|\{\s*:\s*\}|"
    r"\s*\[\s*(?:\.|dot)\s*\]\s*|\s*\(\s*(?:\.|dot)\s*\)\s*|\s*\{\s*(?:\.|dot)\s*\}\s*|"
    r"\s*\[\s*at\s*\]\s*|\s*\(\s*at\s*\)\s*|\s*\{\s*at\s*\}\s*", re.I
)
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"`]+", re.I)
DOMAIN_RE = re.compile(r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![\w-]|\.[a-z0-9])", re.I)
EMAIL_RE = re.compile(r"(?<![\w@])([a-z0-9.!#$%&'*+/=?^_`{|}~-]+)@((?:[a-z0-9-]+\.)+[a-z][a-z0-9-]+)(?![\w-]|\.[a-z0-9])", re.I)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*(?![\w:])", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
HASH_RE = re.compile(r"(?<![a-z0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-z0-9])", re.I)
IOC_HEADING = re.compile(r"^(?:appendix\s*[:a-z0-9-]*\s*)?(?:(?:network|host|file|host-based|network-based)\s+)?(?:indicators(?:\s+of\s+compromise)?|iocs)(?:\s*\([^)]*\))?$", re.I)
END_HEADING = re.compile(r"^(?:references|conclusions?|recommendations?|mitigations?|detections?|detection rules?|hunting(?: queries)?|yara(?: rules)?|sigma(?: rules)?|mitre att&ck|att&ck|acknowledgements?|related (?:content|articles)|summary)$", re.I)


@dataclass(frozen=True)
class IOC:
    type: str
    value: str
    context: str
    snippet: str


def timestamp(value: str | None, fallback: str | None = None) -> str:
    """UTC ISO timestamps preserve SQLite MIN/MAX ordering."""
    try:
        dt = datetime.fromisoformat((value or "").replace("Z", "+00:00").replace(" UTC", "+00:00"))
    except ValueError:
        dt = datetime.fromisoformat((fallback or datetime.now(UTC).isoformat()).replace("Z", "+00:00"))
    return dt.replace(tzinfo=dt.tzinfo or UTC).astimezone(UTC).isoformat(timespec="seconds")


def refang(text: str) -> tuple[str, list[tuple[int, int]]]:
    chunks: list[str] = []
    changed: list[tuple[int, int]] = []
    end = length = 0
    for match in DEFANG.finditer(text):
        prefix = text[end:match.start()]
        token = match.group().strip().lower()
        replacement = "@" if "at" in token else ":" if ":" in token else "."
        if token in {"hxxp", "hxp"}: replacement = "http"
        elif token in {"hxxps", "hxps"}: replacement = "https"
        elif token == "fxp": replacement = "ftp"
        chunks.extend((prefix, replacement))
        length += len(prefix)
        changed.append((length, length + len(replacement)))
        length += len(replacement)
        end = match.end()
    chunks.append(text[end:])
    return "".join(chunks), changed


def public_ip(value: str) -> tuple[str, str] | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not addr.is_global or addr.is_multicast or addr.is_reserved or addr.is_loopback or addr.is_link_local:
        return None
    return ("ipv4" if addr.version == 4 else "ipv6", str(addr))


def domain(value: str) -> str | None:
    try:
        value = value.rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        return None
    result = SUFFIXES(value)
    return value if result.suffix and result.domain else None


def source_domain(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    result = SUFFIXES(host, include_psl_private_domains=True)
    return result.top_domain_under_public_suffix or host


def clean_url(value: str) -> tuple[str, str, str] | None:
    value = value.rstrip(".,;!?'\"")
    for left, right in (("(", ")"), ("[", "]"), ("{", "}")):
        while value.endswith(right) and value.count(right) > value.count(left): value = value[:-1]
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https", "ftp"} or not host:
        return None
    ip = public_ip(host)
    if ip:
        type_, host = ip
    elif domain(host):
        type_, host = "domain", domain(host)
    else:
        return None
    authority = f"[{host}]" if type_ == "ipv6" else host
    if port is not None: authority += f":{port}"
    # Credentials are part of the URL's observable value, not discarded.
    if "@" in parts.netloc: authority = parts.netloc.rsplit("@", 1)[0] + "@" + authority
    normalized = urlunsplit((parts.scheme.lower(), authority, parts.path, parts.query, ""))
    return normalized, type_, host


def normalise(type_: str, value: str) -> tuple[str, str] | None:
    value = refang(str(value).strip())[0]
    if type_ == "ip:port":
        ip = public_ip(value)
        if ip: return ip
        match = re.fullmatch(r"\[([^]]+)\]:(\d+)", value)
        if match: return public_ip(match.group(1)) if int(match.group(2)) <= 65535 else None
        if ":" in value:
            host, port = value.rsplit(":", 1)
            if port.isdigit() and int(port) <= 65535: return public_ip(host)
        return None
    type_ = {"md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256"}.get(type_, type_)
    if type_ in {"ipv4", "ipv6"}:
        ip = public_ip(value)
        return ip if ip and ip[0] == type_ else None
    if type_ == "domain":
        host = domain(value)
        return (type_, host) if host else None
    if type_ == "url":
        result = clean_url(value)
        return (type_, result[0]) if result else None
    if type_ in {"md5", "sha1", "sha256"}:
        length = {"md5": 32, "sha1": 40, "sha256": 64}[type_]
        value = value.lower()
        if not re.fullmatch(f"[a-f0-9]{{{length}}}", value) or len(set(value)) == 1 or value in EMPTY_HASHES: return None
        return type_, value
    if type_ == "email":
        match = EMAIL_RE.fullmatch(value)
        return (type_, value.lower()) if match and domain(match.group(2)) else None
    if type_ == "cve":
        return (type_, value.upper()) if CVE_RE.fullmatch(value) else None
    return None


def section_ranges(text: str) -> list[tuple[int, int]]:
    start: int | None = None
    ranges: list[tuple[int, int]] = []
    offset = 0
    for line in text.splitlines(keepends=True):
        heading = re.sub(r"^[\s#>*\-\d.)]+", "", line).strip().strip(" :*#")
        if IOC_HEADING.fullmatch(heading):
            if start is None: start = offset + len(line)
        elif start is not None and END_HEADING.fullmatch(heading):
            ranges.append((start, offset)); start = None
        offset += len(line)
    if start is not None: ranges.append((start, len(text)))
    return ranges


def extract_text(raw: str) -> list[IOC]:
    text, changed = refang(raw)
    sections = section_ranges(text)
    found: dict[tuple[str, str], IOC] = {}
    masked = list(text)

    def context(pos: int) -> str:
        return "ioc_section" if any(a <= pos < b for a, b in sections) else "body"

    def strong(start: int, end: int) -> bool:
        return context(start) == "ioc_section" or any(a < end and b > start for a, b in changed)

    def add(type_: str, value: str, start: int, end: int) -> None:
        normalized = normalise(type_, value)
        if not normalized: return
        key = normalized
        # Prefer IOC-section evidence over body mentions, retaining the first
        # occurrence within the preferred context.
        existing = found.get(key)
        ctx = context(start)
        if existing and (existing.context == "ioc_section" or ctx != "ioc_section"): return
        snippet = " ".join(text[max(0, start - 80):min(len(text), end + 80)].split())
        found[key] = IOC(*key, ctx, snippet)

    for match in URL_RE.finditer(text):
        parsed = clean_url(match.group())
        if parsed:
            value, host_type, host = parsed
            add("url", value, *match.span())
            add(host_type, host, *match.span())
        masked[match.start():match.end()] = " " * len(match.group())
    rest = "".join(masked)
    for match in EMAIL_RE.finditer(rest):
        add("email", match.group(), *match.span())
        masked[match.start():match.end()] = " " * len(match.group())
    rest = "".join(masked)
    for match in DOMAIN_RE.finditer(rest):
        value = match.group()
        labels = value.split(".")
        weak = labels[-1].lower() in FILE_SUFFIXES or any(re.search(r"[A-Z]", label[1:]) for label in labels)
        weak |= len(labels) == 2 and labels[0].lower() in CODE_OBJECTS and labels[-1].lower() in CODE_FIELDS
        if not weak or strong(*match.span()): add("domain", value, *match.span())
    for regex, type_ in ((IPV4_RE, "ipv4"), (IPV6_RE, "ipv6")):
        for match in regex.finditer(rest):
            if not strong(*match.span()) and re.search(r"(?:version|build|release|v)\s*$", text[max(0, match.start() - 16):match.start()], re.I): continue
            add(type_, match.group(), *match.span())
    for match in HASH_RE.finditer(text):
        add({32: "md5", 40: "sha1", 64: "sha256"}[len(match.group())], match.group(), *match.span())
    for match in CVE_RE.finditer(text): add("cve", match.group(), *match.span())
    return list(found.values())
