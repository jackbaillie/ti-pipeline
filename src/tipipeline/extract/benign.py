"""Benign flags for extracted indicators, stored in document_indicators.warninglist.

A MISP warninglist name wins. Otherwise "publisher" marks a value on the
reporting source's own registered domain (Talos linking talosintelligence.com),
and "allowlist" marks a value on a domain in config/allowlist.yaml. Flags never
delete an observation; a flagged value is not used as an IOC.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from tipipeline.extract import warninglists
from tipipeline.extract.iocs import indicator_host, registered_domain, source_domain


@dataclass(frozen=True)
class Allowlist:
    # Flag the domain and URLs/email addresses on it.
    domains: frozenset[str] = frozenset()
    # Flag the bare domain only: URLs and accounts on these platforms can be attacker content.
    platforms: frozenset[str] = frozenset()

    @classmethod
    def load(cls, path: Path) -> Allowlist:
        data = (yaml.safe_load(path.read_text()) if path.exists() else None) or {}
        sections = {}
        for key in ("domains", "platforms"):
            entries = frozenset(str(entry).strip().lower() for entry in data.get(key) or [])
            for entry in entries:
                if registered_domain(entry) != entry:
                    raise ValueError(f"{path}: {key} entry {entry!r} is not a registered domain")
            sections[key] = entries
        return cls(**sections)


class Benign:
    def __init__(self, warnings: warninglists.WarningLists, allowlist: Allowlist):
        self.warnings = warnings
        self.allowlist = allowlist
        self._sources: dict[str, str] = {}

    def reason(self, type_: str, value: str, source_url: str) -> str | None:
        flag = self.warnings.match(type_, value)
        if flag: return flag
        host = indicator_host(type_, value)
        if not host: return None
        registered = registered_domain(host)
        bare = type_ == "domain"
        if source_url not in self._sources: self._sources[source_url] = source_domain(source_url)
        if registered == self._sources[source_url] and (bare or registered not in self.allowlist.platforms):
            return "publisher"
        if registered in self.allowlist.domains or (bare and registered in self.allowlist.platforms):
            return "allowlist"
        return None


def load(ctx) -> Benign:
    return Benign(warninglists.load(ctx), Allowlist.load(ctx.root / "config" / "allowlist.yaml"))
