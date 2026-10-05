"""MISP warninglists: transparent flags, never deletion of observations.

The chosen, verified list names cover popular destinations, major cloud/CDN
infrastructure, DNS resolvers, shortened URLs, reporting/reference sites,
empty/common benign hashes, and IP-discovery services. Broad hosting,
dynamic-DNS and Tor lists are deliberately not included: these are commonly
attacker controlled. The 10k popularity list avoids the million-domain list's
size and excessive coverage. Flags are refreshed even for unchanged documents.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

WARNINGLIST_NAMES = (
    "empty-hashes", "common-ioc-false-positive", "ti-falsepositives", "sinkholes",
    "public-dns-v4", "public-dns-v6", "public-dns-hostname",
    "security-provider-blogpost", "url-shortener", "whats-my-ip", "crl-hostname",
    "microsoft", "microsoft-office365", "microsoft-office365-ip", "microsoft-azure",
    "google", "google-gcp", "amazon-aws", "cloudflare", "akamai", "fastly", "tranco10k",
)
BASE_URL = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"
MAX_AGE_SECONDS = 7 * 24 * 60 * 60
SUPPORTED_TYPES = frozenset({"string", "hostname", "cidr", "substring", "regex"})


@dataclass
class WarningList:
    name: str
    type: str
    values: frozenset[str]
    attributes: frozenset[str] = frozenset()
    networks: dict[tuple[int, int], set[int]] = field(default_factory=dict)
    patterns: tuple[re.Pattern, ...] = ()

    @classmethod
    def from_json(cls, name: str, data: dict) -> "WarningList":
        if data.get("type") not in SUPPORTED_TYPES or not isinstance(data.get("list"), list):
            raise ValueError(f"invalid warninglist {name}: missing list or unsupported type")
        values = frozenset(str(value).strip() if data["type"] == "regex" else str(value).strip().lower()
                           for value in data["list"] if str(value).strip())
        result = cls(name, data["type"], values, frozenset(data.get("matching_attributes", [])))
        if result.type == "cidr":
            for value in values:
                network = ipaddress.ip_network(value, strict=False)
                result.networks.setdefault((network.version, network.prefixlen), set()).add(int(network.network_address))
        if result.type == "regex": result.patterns = tuple(re.compile(value, re.I) for value in values)
        return result

    def matches(self, type_: str, value: str) -> bool:
        host = (urlsplit(value).hostname or "").lower() if type_ == "url" else value.lower().rstrip(".")
        if self.type == "cidr":
            if type_ not in {"ipv4", "ipv6", "url"}: return False
            try: addr = ipaddress.ip_address(host)
            except ValueError: return False
            bits = addr.max_prefixlen
            number = int(addr)
            return any(version == addr.version and (number >> (bits - prefix) << (bits - prefix)) in members
                       for (version, prefix), members in self.networks.items())
        if self.type == "hostname":
            if type_ not in {"domain", "url"}: return False
            labels = host.split(".")
            return any(".".join(labels[index:]) in self.values for index in range(len(labels)))
        if self.type == "string":
            if value.lower() in self.values: return True
            # Domain/hostname string lists use a leading dot to specify a
            # suffix (e.g. Microsoft's .aadrm.com), not arbitrary substrings.
            if type_ in {"domain", "url"}:
                if host in self.values: return True
                labels = host.split(".")
                return any("." + ".".join(labels[index:]) in self.values for index in range(len(labels)))
            return False
        if self.type == "substring": return any(entry in value.lower() for entry in self.values)
        if self.type == "regex": return any(pattern.search(value) for pattern in self.patterns)
        return False


class WarningLists:
    def __init__(self, lists: list[WarningList], unavailable: list[str] | None = None, stale: list[str] | None = None):
        self.lists = lists
        self.unavailable = unavailable or []
        self.stale = stale or []
        self._cache: dict[tuple[str, str], str | None] = {}

    def match(self, type_: str, value: str) -> str | None:
        key = type_, value
        if key not in self._cache:
            self._cache[key] = next((item.name for item in self.lists if item.matches(type_, value)), None)
        return self._cache[key]


def load(ctx, names: tuple[str, ...] | None = None) -> WarningLists:
    names = WARNINGLIST_NAMES if names is None else names
    directory = ctx.cache_dir / "warninglists"
    directory.mkdir(parents=True, exist_ok=True)
    unavailable: list[str] = []
    stale: list[str] = []

    def fetch(name: str):
        path = directory / f"{name}.json"
        cached = None
        if path.exists():
            try: cached = WarningList.from_json(name, json.loads(path.read_text()))
            except (ValueError, OSError): pass
        if cached is not None and time.time() - path.stat().st_mtime < MAX_AGE_SECONDS:
            return cached, "fresh"
        try:
            # A successful raw-path fetch verifies the selected name exists;
            # list metadata uses human-readable titles, not directory names.
            response = httpx.get(f"{BASE_URL}/{name}/list.json", headers={"User-Agent": ctx.settings.user_agent},
                                 timeout=ctx.settings.http_timeout_seconds, follow_redirects=True)
            response.raise_for_status()
            item = WarningList.from_json(name, response.json())
            temporary = path.with_suffix(".tmp")
            temporary.write_text(response.text)
            temporary.replace(path)
            return item, "downloaded"
        except (httpx.HTTPError, ValueError, OSError) as exc:
            ctx.log.warning("warninglist %s unavailable; %s: %s", name, "using stale cache" if cached else "flag coverage incomplete", exc)
            return cached, "stale" if cached else "unavailable"

    with ThreadPoolExecutor(max_workers=min(6, max(1, len(names)))) as pool:
        results = list(pool.map(fetch, names))
    lists = []
    for name, (item, state) in zip(names, results, strict=True):
        if item: lists.append(item)
        if state == "unavailable": unavailable.append(name)
        if state == "stale": stale.append(name)
    return WarningLists(lists, unavailable, stale)
