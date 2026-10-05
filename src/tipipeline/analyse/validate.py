"""Deterministic checks on an LLM report analysis.

Two things are verified without trusting the model:

* every evidence quote must occur in the source text (after normalising
  Unicode, quotes, dashes, whitespace and case); a quote containing an
  ellipsis verifies only if all of its fragments occur in order;
* every technique ID must exist in MITRE ATT&CK Enterprise and not be
  deprecated. Steps with invalid IDs are kept but flagged.
"""

from __future__ import annotations

import re
import unicodedata

from tipipeline.attack import TECHNIQUE_ID_RE, Attack
from tipipeline.models import AnalysisValidation, ReportAnalysis, StepValidation

_TRANSLATE = str.maketrans(
    {
        "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'", "\u2032": "'", "\u00b4": "'", "`": "'",
        "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"', "\u2033": '"', "\u00ab": '"', "\u00bb": '"',
        "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-", "\u2015": "-", "\u2212": "-",
        # Invisible characters that survive copy/paste and HTML extraction.
        "\u00ad": None, "\u200b": None, "\u200c": None, "\u200d": None, "\u2060": None, "\ufeff": None,
    }
)
_WHITESPACE_RE = re.compile(r"\s+")
_ELLIPSIS_RE = re.compile(r"\[?\s*\.{3,}\s*\]?")


def normalise(text: str) -> str:
    """Canonical form for quote matching. NFKC also turns '…' into '...'."""
    text = unicodedata.normalize("NFKC", text).translate(_TRANSLATE)
    return _WHITESPACE_RE.sub(" ", text).strip().casefold()


def verify_quote(quote: str, source: str, *, normalised_source: str | None = None) -> bool:
    """True if ``quote`` occurs in ``source``.

    Pass ``normalised_source`` (from :func:`normalise`) when checking many
    quotes against the same document.
    """
    haystack = normalised_source if normalised_source is not None else normalise(source)
    needle = normalise(quote)
    if not needle:
        return False
    if needle in haystack:
        return True
    if "..." not in needle:
        return False
    fragments = [f.strip() for f in _ELLIPSIS_RE.split(needle)]
    fragments = [f for f in fragments if f]
    if not fragments:
        return False
    position = 0
    for fragment in fragments:
        found = haystack.find(fragment, position)
        if found < 0:
            return False
        position = found + len(fragment)
    return True


def normalise_technique_id(technique_id: str) -> str:
    return technique_id.strip().upper()


def is_wellformed_technique_id(technique_id: str) -> bool:
    return TECHNIQUE_ID_RE.fullmatch(technique_id) is not None


def validate_analysis(analysis: ReportAnalysis, source_text: str, attack: Attack) -> AnalysisValidation:
    haystack = normalise(source_text)
    steps: list[StepValidation] = []
    invalid: list[str] = []
    for step in analysis.attack_steps:
        technique_id = normalise_technique_id(step.technique_id)
        valid = is_wellformed_technique_id(technique_id) and attack.is_valid(technique_id)
        technique = attack.get(technique_id) if technique_id else None
        if not valid and technique_id not in invalid:
            invalid.append(technique_id)
        steps.append(
            StepValidation(
                order=step.order,
                technique_valid=valid,
                official_technique_name=technique.name if technique else None,
                quote_verified=verify_quote(step.evidence_quote, source_text, normalised_source=haystack),
            )
        )
    technology_quotes = [
        verify_quote(tech.evidence_quote, source_text, normalised_source=haystack)
        for tech in analysis.affected_technologies
    ]
    verified = sum(s.quote_verified for s in steps) + sum(technology_quotes)
    return AnalysisValidation(
        steps=steps,
        technology_quotes_verified=technology_quotes,
        quotes_total=len(steps) + len(technology_quotes),
        quotes_verified=verified,
        invalid_techniques=invalid,
    )
