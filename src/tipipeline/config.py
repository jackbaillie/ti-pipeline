"""Load settings, sources, priority themes and customer profiles from ``config/``."""

from __future__ import annotations

from pathlib import Path

import yaml

from tipipeline.models import Profile, Settings, SourceConfig, Theme


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


def load_themes(root: Path) -> list[Theme]:
    """Shared priority themes from ``config/priorities.yaml``."""
    path = root / "config" / "priorities.yaml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    return [Theme.model_validate(item) for item in data.get("themes", [])]


def load_profiles(root: Path, themes: list[Theme] | None = None) -> list[Profile]:
    """Customer profiles; every PIR theme must be a theme id from ``config/priorities.yaml``."""
    profiles_dir = root / "config" / "profiles"
    if not profiles_dir.exists():
        return []
    known = {t.id for t in (load_themes(root) if themes is None else themes)}
    profiles = []
    for path in sorted(profiles_dir.glob("*.yaml")):
        profile = Profile.model_validate(yaml.safe_load(path.read_text()))
        for pir in profile.pirs:
            if pir.theme not in known:
                raise ValueError(
                    f"{path.name}: PIR {pir.id} has unknown theme {pir.theme!r}; "
                    f"use one of {', '.join(sorted(known)) or '(none defined)'} from config/priorities.yaml"
                )
        profiles.append(profile)
    return profiles


def load_table_schemas(root: Path) -> dict[str, list[str]]:
    """Sentinel / Defender XDR table name -> column names, from ``config/schemas/tables.yaml``."""
    path = root / "config" / "schemas" / "tables.yaml"
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    return {name: list(spec.get("columns", [])) for name, spec in data.get("tables", {}).items()}
