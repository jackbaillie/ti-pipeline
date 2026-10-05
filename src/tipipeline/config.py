"""Load settings, sources and customer profiles from ``config/``."""

from __future__ import annotations

from pathlib import Path

import yaml

from tipipeline.models import Profile, Settings, SourceConfig


def repo_root() -> Path:
    """Repository root: the nearest ancestor of this file containing ``config/settings.yaml``."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "config" / "settings.yaml").exists():
            return parent
    return Path.cwd()


def load_settings(root: Path) -> Settings:
    path = root / "config" / "settings.yaml"
    data = yaml.safe_load(path.read_text()) if path.exists() else {}
    return Settings.model_validate(data or {})


def load_sources(root: Path) -> list[SourceConfig]:
    path = root / "config" / "sources.yaml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    return [SourceConfig.model_validate(item) for item in data.get("sources", [])]


def load_profiles(root: Path) -> list[Profile]:
    profiles_dir = root / "config" / "profiles"
    if not profiles_dir.exists():
        return []
    return [
        Profile.model_validate(yaml.safe_load(path.read_text()))
        for path in sorted(profiles_dir.glob("*.yaml"))
    ]


def load_table_schemas(root: Path) -> dict[str, list[str]]:
    """Sentinel / Defender XDR table name -> column names, from ``config/schemas/tables.yaml``."""
    path = root / "config" / "schemas" / "tables.yaml"
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    return {name: list(spec.get("columns", [])) for name, spec in data.get("tables", {}).items()}
