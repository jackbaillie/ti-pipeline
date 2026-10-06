"""Deterministic relevance signals and rules-based assessments.

Matching works on a word-normalised form of every string (lowercase, NFKC,
punctuation to spaces) so 'PAN-OS' and 'pan os' compare equal and keywords
only match on word boundaries. Vendor and product names go through small
alias tables covering renames that real KEV entries and vendor reports use
(e.g. 'Citrix ADC' became 'NetScaler ADC', 'Pulse Connect Secure' became
'Ivanti Connect Secure').
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Collection, Iterable, Mapping
from dataclasses import asdict, dataclass, field

from tipipeline.models import Profile, ProfileAssessment, ReportAnalysis, Technology

_NON_WORD_RE = re.compile(r"[^0-9a-z]+")
_VERSION_TOKEN_RE = re.compile(r"^v?\d[\dx]*$")

# Phrase -> canonical vendor (checked longest first against the padded, normalised vendor).
VENDOR_ALIASES: dict[str, str] = {
    "cloud software group": "citrix",
    "citrix": "citrix",
    "netscaler": "citrix",
    "palo alto": "paloalto",
    "paloalto": "paloalto",
    "pulse secure": "ivanti",
    "ivanti": "ivanti",
    "broadcom": "vmware",
    "vmware": "vmware",
    "manageengine": "zoho",
    "zoho": "zoho",
    "ipswitch": "progress",
    "progress": "progress",
    "check point": "checkpoint",
    "checkpoint": "checkpoint",
    "sonic wall": "sonicwall",
    "rockwell": "rockwell",
    "schneider": "schneider",
    "apache": "apache",
    "connectwise": "connectwise",
    "microsoft": "microsoft",
    "ms": "microsoft",
}
_VENDOR_ALIAS_ORDER = sorted(VENDOR_ALIASES, key=len, reverse=True)
_VENDOR_SUFFIXES = frozenset(
    "inc corp corporation ltd limited llc plc gmbh ag co company software systems networks "
    "technologies technology group international holdings labs the".split()
)

# Phrase rewrites applied to product names and free text before matching.
PRODUCT_SYNONYMS: dict[str, str] = {
    "citrix adc": "netscaler adc",
    "citrix gateway": "netscaler gateway",
    "citrix netscaler": "netscaler",
    "application delivery controller": "adc",
    "pulse connect secure": "connect secure",
    "ivanti connect secure": "connect secure",
    "fortios": "fortigate",
    "panos": "pan os",
    "office 365": "microsoft 365",
    "o365": "microsoft 365",
    "m365": "microsoft 365",
    "azure active directory": "entra id",
    "azure ad": "entra id",
    "microsoft entra id": "entra id",
    "connectwise control": "screenconnect",
    "adaptive security appliance": "asa",
}
_SYNONYM_ORDER = sorted(PRODUCT_SYNONYMS, key=len, reverse=True)

_STOP_TOKENS = frozenset("and or the for of with a an by to in on multiple products product software various".split())
# Words that appear in many unrelated product names: a shared common word alone is not a match.
_COMMON_TOKENS = frozenset(
    "server servers gateway gateways client manager management center centre cloud web enterprise "
    "security secure endpoint online desktop mobile os service services access connect portal app apps "
    "application applications edition platform suite system agent console network remote data file mail "
    "email admin policy control framework driver extensions protection firewall vpn identity premium "
    "standard pro professional express".split()
)

SECTOR_GROUPS: dict[str, tuple[str, ...]] = {
    "legal": (
        "legal", "law firm", "law firms", "law practice", "law practices", "solicitor", "solicitors",
        "lawyer", "lawyers", "attorney", "attorneys", "barrister", "barristers", "professional services",
    ),
    "finance": (
        "finance", "financial", "financials", "banking", "bank", "banks", "fintech", "payment", "payments",
        "credit union", "credit unions", "building society", "building societies", "insurance", "investment",
        "lending", "lender", "lenders", "cryptocurrency exchange",
    ),
    "manufacturing": (
        "manufacturing", "manufacturer", "manufacturers", "industrial", "industrials", "ics", "ot",
        "operational technology", "critical manufacturing", "engineering", "factory", "factories",
        "automotive",
    ),
}
BROAD_SECTOR_PHRASES = (
    "all sectors", "multiple sectors", "various sectors", "cross sector", "many sectors", "all industries",
    "multiple industries", "various industries", "many industries", "wide range of",
)
REGION_GROUPS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # region -> (direct phrases, broader phrases that include it)
    "uk": (
        ("uk", "united kingdom", "britain", "great britain", "british", "england", "scotland", "wales",
         "northern ireland", "gb"),
        ("europe", "european", "emea", "western europe", "global", "worldwide"),
    ),
}

_EXPOSURE_RANK = {"internet_facing": 4, "cloud_service": 3, "endpoint": 2, "internal": 1, "ot": 1}


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------


def norm_words(text: str) -> str:
    """Lowercase words separated by single spaces (no punctuation)."""
    text = unicodedata.normalize("NFKC", text).casefold()
    return _NON_WORD_RE.sub(" ", text).strip()


def _padded(text: str) -> str:
    return f" {text} "


def contains_phrase(padded_text: str, phrase: str) -> bool:
    """Word-boundary phrase test; ``padded_text`` is `` norm_words(text) `` with spaces at both ends."""
    phrase = norm_words(phrase)
    return bool(phrase) and f" {phrase} " in padded_text


def apply_synonyms(normalised: str) -> str:
    padded = _padded(normalised)
    for phrase in _SYNONYM_ORDER:
        if f" {phrase} " in padded:
            padded = padded.replace(f" {phrase} ", f" {PRODUCT_SYNONYMS[phrase]} ")
    return padded.strip()


def prepare_text(*parts: str) -> str:
    """Normalised, synonym-rewritten, space-padded text for repeated phrase searches."""
    return _padded(apply_synonyms(norm_words(" \n ".join(p for p in parts if p))))


def canonical_vendor(vendor: str) -> str:
    normalised = norm_words(vendor)
    if not normalised:
        return ""
    padded = _padded(normalised)
    for phrase in _VENDOR_ALIAS_ORDER:
        if f" {phrase} " in padded:
            return VENDOR_ALIASES[phrase]
    tokens = [t for t in normalised.split() if t not in _VENDOR_SUFFIXES]
    return " ".join(tokens) or normalised


def product_tokens(product: str, vendor: str = "") -> frozenset[str]:
    """Significant product tokens: synonyms applied, vendor words, stop words and versions removed."""
    vendor_words = set(norm_words(vendor).split()) | set(canonical_vendor(vendor).split())
    tokens = apply_synonyms(norm_words(product)).split()
    return frozenset(
        t for t in tokens
        if t not in _STOP_TOKENS and t not in vendor_words and not _VERSION_TOKEN_RE.match(t) and len(t) > 1
    )


def tech_label(tech: Technology) -> str:
    return f"{tech.vendor} {tech.product}".strip()


# --------------------------------------------------------------------------
# Technology matching
# --------------------------------------------------------------------------


def vendors_compatible(a: str, b: str) -> bool:
    """Same canonical vendor; an unknown (empty) vendor is compatible with anything."""
    ca, cb = canonical_vendor(a), canonical_vendor(b)
    return not ca or not cb or ca == cb


def products_match(tokens_a: frozenset[str], tokens_b: frozenset[str]) -> bool:
    if not tokens_a or not tokens_b:
        return False
    # A server product's vulnerability is not evidence against its SaaS counterpart.
    if ("online" in tokens_a and "server" in tokens_b) or ("online" in tokens_b and "server" in tokens_a):
        return False
    if tokens_a <= tokens_b or tokens_b <= tokens_a:
        return True
    return bool((tokens_a & tokens_b) - _COMMON_TOKENS)


def technology_matches(tech: Technology, vendor: str, product: str) -> bool:
    """Does a (vendor, product) pair from reporting refer to the profile technology?"""
    if not vendors_compatible(tech.vendor, vendor):
        return False
    return products_match(product_tokens(tech.product, tech.vendor), product_tokens(product, vendor or tech.vendor))


def mention_phrase(tech: Technology) -> str:
    """Product phrase searched for in free text: synonyms applied, leading vendor
    words dropped, cut at the first version token ('Exchange Server 2019' -> 'exchange server')."""
    words = apply_synonyms(norm_words(tech.product)).split()
    vendor_words = set(norm_words(tech.vendor).split())
    while len(words) > 1 and words[0] in vendor_words:
        words = words[1:]
    for index, word in enumerate(words):
        if _VERSION_TOKEN_RE.match(word):
            words = words[:index]
            break
    return " ".join(words)


def technology_mentioned(tech: Technology, prepared_text: str) -> bool:
    """Is the technology named in free text (from :func:`prepare_text`)?

    The product phrase must appear; when the product name is made only of
    common words (e.g. 'Endpoint Manager') the vendor must appear too.
    """
    phrase = mention_phrase(tech)
    if not phrase or f" {phrase} " not in prepared_text:
        return False
    significant = [t for t in phrase.split() if t not in _STOP_TOKENS]
    if all(t in _COMMON_TOKENS for t in significant):
        return any(contains_phrase(prepared_text, v) for v in (tech.vendor, canonical_vendor(tech.vendor)) if v)
    return True


def mentioned_technologies(prepared_text: str, technologies: Iterable[Technology]) -> list[Technology]:
    return [t for t in technologies if technology_mentioned(t, prepared_text)]


# --------------------------------------------------------------------------
# Sector, region and PIR matching
# --------------------------------------------------------------------------


def sector_groups(sector: str) -> set[str]:
    padded = _padded(norm_words(sector))
    return {group for group, phrases in SECTOR_GROUPS.items() if any(contains_phrase(padded, p) for p in phrases)}


def match_sectors(profile_sector: str, targeted_sectors: Iterable[str]) -> list[str]:
    """Targeted sectors (as written in the reporting) that correspond to the profile's sector."""
    groups = sector_groups(profile_sector)
    phrases = [p for g in groups for p in SECTOR_GROUPS[g]] or [profile_sector]
    matched = []
    for target in targeted_sectors:
        padded = _padded(norm_words(target))
        if any(contains_phrase(padded, p) for p in phrases):
            matched.append(target)
    return matched


def broad_targeting(targeted_sectors: Iterable[str]) -> bool:
    return any(contains_phrase(_padded(norm_words(t)), p) for t in targeted_sectors for p in BROAD_SECTOR_PHRASES)


def match_regions(profile_region: str, targeted_regions: Iterable[str]) -> tuple[list[str], list[str]]:
    """(direct, broader) targeted regions that include the profile's region."""
    padded_region = _padded(norm_words(profile_region))
    direct_phrases: list[str] = [profile_region]
    broad_phrases: list[str] = []
    for direct, broad in REGION_GROUPS.values():
        if any(contains_phrase(padded_region, p) for p in direct):
            direct_phrases, broad_phrases = list(direct), list(broad)
            break
    direct_hits, broad_hits = [], []
    for target in targeted_regions:
        padded = _padded(norm_words(target))
        if any(contains_phrase(padded, p) for p in direct_phrases):
            direct_hits.append(target)
        elif any(contains_phrase(padded, p) for p in broad_phrases):
            broad_hits.append(target)
    return direct_hits, broad_hits


def pir_hits(profile: Profile, prepared_text: str) -> dict[str, list[str]]:
    """PIR id -> keywords found in the text."""
    hits: dict[str, list[str]] = {}
    for pir in profile.pirs:
        found = [k for k in pir.keywords if contains_phrase(prepared_text, apply_synonyms(norm_words(k)))]
        if found:
            hits[pir.id] = found
    return hits


# --------------------------------------------------------------------------
# Signals for analysed reports
# --------------------------------------------------------------------------


@dataclass
class TechMatch:
    technology: str
    exposure: str
    matched: str
    via: str  # 'analysis' (affected technology), 'kev', or 'text' (mentioned only)


@dataclass
class RuleSignals:
    profile_id: str
    technology_matches: list[TechMatch] = field(default_factory=list)
    sector_matches: list[str] = field(default_factory=list)
    broad_sector_targeting: bool = False
    region_matches: list[str] = field(default_factory=list)
    broad_region_matches: list[str] = field(default_factory=list)
    pir_hits: dict[str, list[str]] = field(default_factory=dict)
    # KEV CVEs named in the report whose KEV vendor/product is a profile technology the report affects.
    kev_cves: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def analysis_text(analysis: ReportAnalysis) -> str:
    """Analysis fields worth keyword-matching (the model's own wording)."""
    parts = [analysis.summary, *analysis.threat_actors, *analysis.malware, *analysis.tools, *analysis.cves]
    parts += [f"{s.technique_id} {s.technique_name} {s.description}" for s in analysis.attack_steps]
    return "\n".join(parts)


def _best_by_exposure(matches: list[TechMatch]) -> TechMatch | None:
    return max(matches, key=lambda m: _EXPOSURE_RANK.get(m.exposure, 0), default=None)


def signals_for_analysis(
    profile: Profile,
    analysis: ReportAnalysis,
    prepared_document: str,
    kev: Mapping[str, dict[str, str]] | None = None,
) -> RuleSignals:
    """Rule signals for one profile. ``prepared_document`` is :func:`prepare_text` of title + text;
    ``kev`` maps CVE ID to its :func:`kev_record`."""
    signals = RuleSignals(profile_id=profile.id)
    matched_techs: set[str] = set()
    for tech in profile.technologies:
        for affected in analysis.affected_technologies:
            if technology_matches(tech, affected.vendor, affected.product):
                signals.technology_matches.append(
                    TechMatch(tech_label(tech), tech.exposure, f"{affected.vendor} {affected.product}".strip(), "analysis")
                )
                matched_techs.add(tech_label(tech))
                break
    for tech in mentioned_technologies(prepared_document, profile.technologies):
        if tech_label(tech) not in matched_techs:
            signals.technology_matches.append(TechMatch(tech_label(tech), tech.exposure, tech_label(tech), "text"))
    signals.sector_matches = match_sectors(profile.sector, analysis.targeted_sectors)
    signals.broad_sector_targeting = broad_targeting(analysis.targeted_sectors)
    signals.region_matches, signals.broad_region_matches = match_regions(profile.region, analysis.targeted_regions)
    combined = prepared_document + prepare_text(analysis_text(analysis))
    signals.pir_hits = pir_hits(profile, combined)
    kev = kev or {}
    signals.kev_cves = sorted(
        cve for cve in {c.upper() for c in analysis.cves} & kev.keys()
        if any(m.technology in matched_techs for m in kev_technology_matches(profile, kev[cve]))
    )
    return signals


def assess_from_signals(profile: Profile, signals: RuleSignals, analysis: ReportAnalysis) -> ProfileAssessment:
    """Rules-only assessment of an analysed report (used when the LLM omits a profile)."""
    affected = [m for m in signals.technology_matches if m.via == "analysis"]
    mentioned = [m for m in signals.technology_matches if m.via == "text"]
    best = _best_by_exposure(affected)
    reasons: list[str] = []
    unknowns: list[str] = []
    if best is not None:
        exposed = best.exposure == "internet_facing" or bool(signals.kev_cves)
        priority, score = ("high", 80) if exposed else ("medium", 60)
        reasons.append(
            f"Reporting concerns {best.matched}, which matches {profile.name}'s {best.technology} ({best.exposure})."
        )
        if signals.kev_cves:
            reasons.append(f"{', '.join(signals.kev_cves)} {'is' if len(signals.kev_cves) == 1 else 'are'} in CISA KEV.")
        unknowns.append(f"Deployed version and configuration of {best.technology} not known.")
    elif signals.sector_matches:
        priority, score = ("medium", 55) if analysis.huntable else ("low", 35)
        reasons.append(f"Reporting targets {', '.join(signals.sector_matches)}, matching the profile sector ({profile.sector}).")
        unknowns.append(f"Whether {profile.name} itself is targeted is not known; the link is sector-level.")
    elif signals.pir_hits or mentioned or signals.region_matches:
        priority, score = "low", 25
        if mentioned:
            reasons.append(f"Mentions {', '.join(m.technology for m in mentioned)} without describing it as affected.")
        if signals.region_matches:
            reasons.append(f"Targets {', '.join(signals.region_matches)}.")
    else:
        priority, score = "none", 5
        reasons.append("No overlap with the profile's technologies, sector, region or PIR keywords.")
    if signals.pir_hits:
        reasons.append(f"PIR keyword hits: {', '.join(sorted(signals.pir_hits))}.")
    return ProfileAssessment(
        profile_id=profile.id,
        priority=priority,
        score=score,
        rationale="Rules-based: " + " ".join(reasons),
        matched_pirs=sorted(signals.pir_hits),
        matched_technologies=[m.technology for m in affected],
        unknowns=unknowns,
    )


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------

KEV_FIELDS = (
    "cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription",
    "knownRansomwareCampaignUse", "dateAdded", "dueDate", "requiredAction",
)


def kev_record(meta: dict) -> dict[str, str]:
    """KEV fields from a vulnerability document's meta_json (the raw CISA record)."""
    return {key: str(meta.get(key) or "").strip() for key in KEV_FIELDS}


def kev_technology_matches(profile: Profile, kev: dict[str, str]) -> list[TechMatch]:
    """Profile technologies affected by a KEV entry.

    Matches on vendorProject + product, or — for entries such as Fortinet
    'Multiple Products' — on the same vendor plus the profile product being
    named in the vulnerability name or description.
    """
    described = prepare_text(kev["vulnerabilityName"], kev["shortDescription"])
    kev_label = f"{kev['vendorProject']} {kev['product']}".strip()
    matches = []
    for tech in profile.technologies:
        if technology_matches(tech, kev["vendorProject"], kev["product"]) or (
            canonical_vendor(kev["vendorProject"])
            and vendors_compatible(tech.vendor, kev["vendorProject"])
            and technology_mentioned(tech, described)
        ):
            matches.append(TechMatch(tech_label(tech), tech.exposure, kev_label, "kev"))
    return matches


def assess_kev(profile: Profile, kev: dict[str, str], document_text: str = "") -> ProfileAssessment:
    """Rules-only relevance of a CISA KEV entry to one profile."""
    matches = kev_technology_matches(profile, kev)
    cve = kev["cveID"] or "this CVE"
    ransomware = kev["knownRansomwareCampaignUse"].casefold() == "known"
    prepared = prepare_text(kev["vendorProject"], kev["product"], kev["vulnerabilityName"], kev["shortDescription"], document_text)
    pirs = pir_hits(profile, prepared)
    best = _best_by_exposure(matches)
    unknowns: list[str] = []
    if best is None:
        rationale = (
            f"CISA KEV {cve} ({kev['vendorProject']} {kev['product']}) does not match any technology "
            f"in {profile.name}'s inventory."
        )
        priority, score = "none", 0
    else:
        internet_facing = best.exposure == "internet_facing"
        if internet_facing or ransomware:
            priority, score = "high", 75 + 10 * internet_facing + 10 * ransomware
        else:
            priority, score = "medium", 55
        parts = [
            f"CISA KEV: {cve} in {best.matched} is exploited in the wild and matches {profile.name}'s "
            f"{best.technology} ({best.exposure.replace('_', '-')})."
        ]
        if ransomware:
            parts.append("CISA records known use in ransomware campaigns.")
        if kev["dueDate"]:
            parts.append(f"US federal remediation deadline {kev['dueDate']}.")
        rationale = " ".join(parts)
        unknowns.append(f"Deployed version of {best.technology} not known; confirm it is in the affected range.")
        unknowns.append("Patch or mitigation status not known.")
        if not ransomware and kev["knownRansomwareCampaignUse"]:
            unknowns.append("Ransomware campaign use not known (KEV: Unknown).")
    return ProfileAssessment(
        profile_id=profile.id,
        priority=priority,
        score=score,
        rationale=rationale,
        matched_pirs=sorted(pirs),
        matched_technologies=[m.technology for m in matches],
        unknowns=unknowns,
    )


# --------------------------------------------------------------------------
# Patch bulletins
# --------------------------------------------------------------------------

BULLETIN_MIN_CVES = 10
BULLETIN_TITLE_PHRASES = ("patch tuesday", "critical patch update", "patch day", "security bulletin", "security updates")
_LOW_MAX_SCORE = 44


def is_patch_bulletin(title: str, report_type: str, cves: Collection[str]) -> bool:
    """Is this report a vendor patch release or bulletin rather than a threat to hunt?

    A bulletin is a report the analysis typed 'vulnerability' that either lists at least
    ``BULLETIN_MIN_CVES`` distinct CVEs or has patch-release wording in its title
    (``BULLETIN_TITLE_PHRASES``, e.g. "Patch Tuesday" or "Critical Patch Update").
    Relevance caps bulletins at low (:func:`cap_patch_bulletin`); exploited CVEs in them get
    their urgency from their own CISA KEV entries.
    """
    if report_type != "vulnerability":
        return False
    title_text = _padded(norm_words(title))
    return len(cves) >= BULLETIN_MIN_CVES or any(contains_phrase(title_text, p) for p in BULLETIN_TITLE_PHRASES)


def cap_patch_bulletin(assessment: ProfileAssessment) -> ProfileAssessment:
    """Cap a patch bulletin's high/medium assessment at 'low' with a rule-based rationale."""
    if assessment.priority not in ("high", "medium"):
        return assessment
    return assessment.model_copy(update={
        "priority": "low", "score": min(assessment.score, _LOW_MAX_SCORE),
        "rationale": "Patch bulletin for vulnerability management. Exploited CVEs are tracked through their KEV entries.",
    })
