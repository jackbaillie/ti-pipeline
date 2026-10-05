"""MITRE ATT&CK Enterprise lookup, cached from the official STIX bundle."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str
    deprecated: bool


class Attack:
    def __init__(self, techniques: dict[str, Technique]) -> None:
        self._techniques = techniques

    def get(self, technique_id: str) -> Technique | None:
        return self._techniques.get(technique_id.strip().upper())

    def is_valid(self, technique_id: str) -> bool:
        """True for an existing, non-deprecated technique or sub-technique."""
        technique = self.get(technique_id)
        return technique is not None and not technique.deprecated

    def techniques(self) -> Iterator[Technique]:
        """Iterate current techniques for prompt grounding and coverage displays."""
        return (technique for technique in self._techniques.values() if not technique.deprecated)

    def __len__(self) -> int:
        return len(self._techniques)


def parse_bundle(bundle: dict) -> Attack:
    techniques: dict[str, Technique] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        ref = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ref or not ref.get("external_id"):
            continue
        tactics = tuple(
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        )
        techniques[ref["external_id"]] = Technique(
            id=ref["external_id"],
            name=obj.get("name", ""),
            tactics=tactics,
            url=ref.get("url", ""),
            deprecated=bool(obj.get("x_mitre_deprecated")),
        )
    return Attack(techniques)


def load(cache_dir: Path, user_agent: str, timeout: float = 120) -> Attack:
    """Load ATT&CK, downloading the bundle once into ``cache_dir``."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / "enterprise-attack.json"
    if not path.exists():
        response = httpx.get(ATTACK_URL, headers={"User-Agent": user_agent}, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        path.write_bytes(response.content)
    return parse_bundle(json.loads(path.read_text()))
