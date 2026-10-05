"""Text helpers shared by the markdown reports and the HTML dashboard.

Everything that reaches a report is attacker-influenced (titles, quotes,
indicator values), so these helpers make two guarantees:

* indicators are displayed defanged (``hxxps://evil[.]com``) so nothing in a
  brief is clickable or auto-linked;
* markdown output cannot smuggle raw HTML, links or table breaks out of the
  text it renders.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

# A dot that is not already wrapped as "[.]".
_BARE_DOT = re.compile(r"(?<!\[)\.(?!\])")
_BARE_COLON = re.compile(r"(?<!\[):(?!\])")
_SCHEMES = {"http": "hxxp", "https": "hxxps", "ftp": "fxp", "sftp": "sfxp"}
_SCHEME_RE = re.compile(r"^(?P<scheme>[a-z][a-z0-9+.-]*)(?P<sep>(?:\[?:\]?)//)", re.IGNORECASE)
_URL_IN_TEXT = re.compile(r"\b(https?|ftp)://", re.IGNORECASE)


def _defang_host(host: str) -> str:
    return _BARE_DOT.sub("[.]", host)


def defang(type_: str, value: str) -> str:
    """Return a non-clickable display form of an indicator.

    Idempotent: defanging an already defanged value returns it unchanged.
    Hashes and CVE IDs are returned as-is.
    """
    value = value.strip()
    if not value:
        return value
    if type_ in {"domain", "ipv4"}:
        return _defang_host(value)
    if type_ == "ipv6":
        return _BARE_COLON.sub("[:]", value)
    if type_ == "email":
        local, sep, domain = value.rpartition("[@]" if "[@]" in value else "@")
        if not sep:
            return _defang_host(value)
        return f"{local}[@]{_defang_host(domain)}"
    if type_ == "url":
        return _defang_url(value)
    return value


def _defang_url(value: str) -> str:
    rest = value
    prefix = ""
    match = _SCHEME_RE.match(value)
    if match:
        scheme = match.group("scheme")
        mapped = _SCHEMES.get(scheme.lower(), scheme)
        if scheme.isupper():
            mapped = mapped.upper()
        prefix = mapped + "://"
        rest = value[match.end():]
    # Host (with optional userinfo/port) runs up to the first path, query or fragment delimiter.
    cut = len(rest)
    for delimiter in "/?#":
        index = rest.find(delimiter)
        if index != -1:
            cut = min(cut, index)
    netloc, tail = rest[:cut], rest[cut:]
    if netloc.startswith("[") and "]" in netloc and not netloc.startswith("[.]"):
        # IPv6 literal host, e.g. [2001:db8::1]:8080 — break it like an ipv6 indicator.
        end = netloc.rindex("]")
        host = "[" + _BARE_COLON.sub("[:]", netloc[1:end]) + "]"
        netloc = host + netloc[end + 1:]
    else:
        netloc = _defang_host(netloc)
    return prefix + netloc + tail


def defang_text(text: str, values: list[str] | tuple[str, ...] = ()) -> str:
    """Defang known indicator ``values`` and any URL schemes inside free text (e.g. snippets)."""
    for value in sorted({v for v in values if v}, key=len, reverse=True):
        if value in text:
            text = text.replace(value, _defang_guess(value))
    return _URL_IN_TEXT.sub(lambda m: _SCHEMES.get(m.group(1).lower(), m.group(1)) + "://", text)


def _defang_guess(value: str) -> str:
    if "://" in value:
        return _defang_url(value)
    if "@" in value:
        return defang("email", value)
    if value.count(":") >= 2:
        return defang("ipv6", value)
    return _defang_host(value)


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------

# Characters that can start markdown/HTML constructs inline. Escaping them
# keeps attacker text as text: no raw HTML, no links/images, no emphasis
# spill-over, no table cell breaks.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~])")
_WS = re.compile(r"\s+")


def md_inline(text: object) -> str:
    """Escape text for a single-line markdown context (paragraph, list item or table cell)."""
    if text is None:
        return ""
    collapsed = _WS.sub(" ", str(text)).strip()
    escaped = _MD_SPECIAL.sub(r"\\\1", collapsed)
    # A leading '#', '>', '-', '+', '=' or 'N.' would start a block construct.
    return re.sub(r"^([#>+=-]|\d+[.)])", r"\\\1", escaped)


def md_code(text: object) -> str:
    """Inline code span that survives backticks inside the value."""
    value = _WS.sub(" ", str(text)).strip()
    if not value:
        return ""
    longest = max((len(run) for run in re.findall(r"`+", value)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if value.startswith("`") or value.endswith("`") or longest else ""
    return f"{fence}{pad}{value}{pad}{fence}"


def md_fence(content: str, lang: str = "") -> str:
    """Fenced code block whose fence is longer than any backtick run in ``content``."""
    longest = max((len(run) for run in re.findall(r"`{3,}", content)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{content.rstrip()}\n{fence}"


def safe_url(url: str | None) -> str | None:
    """Return ``url`` if it is a plain http(s) URL safe to place in a link, else None."""
    if not url:
        return None
    url = url.strip()
    if any(ch.isspace() or ch in "<>\"'`" for ch in url):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return None
    return url


def md_url(url: str | None) -> str:
    """Markdown autolink for a safe URL; anything else is shown as inert code."""
    safe = safe_url(url)
    if safe:
        return f"<{safe}>"
    return md_code(url) if url else "—"


def md_link(label: object, href: str) -> str:
    """Link to an internal (generated) path with escaped label text."""
    return f"[{md_inline(label)}]({href})"


# --------------------------------------------------------------------------
# Misc formatting
# --------------------------------------------------------------------------


def slugify(text: str, max_length: int = 60) -> str:
    normalized = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", normalized.lower()).strip("-")
    slug = slug[:max_length].rstrip("-")
    return slug or "hunt"


def truncate(text: str | None, limit: int) -> str:
    if not text:
        return ""
    text = _WS.sub(" ", text).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def first_sentence(text: str | None, limit: int = 220) -> str:
    if not text:
        return ""
    text = _WS.sub(" ", text).strip()
    match = re.search(r"(?<=[.!?])\s", text)
    sentence = text[: match.start()] if match else text
    return truncate(sentence, limit)


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=ZoneInfo("UTC"))
    return parsed


def format_time(value: str | None, tz: ZoneInfo, *, with_zone: bool = False) -> str:
    """Render an ISO timestamp in the configured timezone, e.g. ``2026-10-05 08:04``."""
    parsed = parse_iso(value)
    if parsed is None:
        return value or "—"
    local = parsed.astimezone(tz)
    text = local.strftime("%Y-%m-%d %H:%M")
    return f"{text} {local.tzname()}" if with_zone else text


def format_date(value: str | None, tz: ZoneInfo) -> str:
    parsed = parse_iso(value)
    if parsed is None:
        return value or "—"
    return parsed.astimezone(tz).strftime("%Y-%m-%d")


INDICATOR_LABELS = {
    "ipv4": "IPv4 address",
    "ipv6": "IPv6 address",
    "domain": "Domain",
    "url": "URL",
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "email": "Email address",
    "cve": "CVE",
}
INDICATOR_ORDER = list(INDICATOR_LABELS)

CONTEXT_LABELS = {
    "ioc_section": "IOC section",
    "body": "body text",
    "feed": "feed",
    "metadata": "metadata",
}

PYRAMID_LABELS = {
    "hash_values": "Hash values (trivial for the adversary to change)",
    "ip_addresses": "IP addresses (easy)",
    "domain_names": "Domain names (simple)",
    "network_host_artifacts": "Network/host artefacts (annoying)",
    "tools": "Tools (challenging)",
    "ttps": "TTPs (tough)",
}
PYRAMID_ORDER = list(PYRAMID_LABELS)
