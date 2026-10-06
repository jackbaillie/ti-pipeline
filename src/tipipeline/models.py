"""Shared data contracts.

Three groups live here:

* configuration (settings, sources, customer profiles);
* LLM structured outputs (report analysis, relevance, hunt drafts) — every
  field is required so the JSON schema can be enforced in strict mode;
* stored records rendered by reports and the dashboard (validation results,
  PEAK hunt packages).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

SourceKind = Literal["rss", "cisa_kev", "threatfox"]
SourceTier = Literal["research", "government", "news", "ioc_feed", "manual"]


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    kind: SourceKind
    url: str
    tier: SourceTier
    enabled: bool = True
    max_items: int = 20
    fetch_full_text: bool = True


class Technology(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: str
    product: str
    exposure: Literal["internet_facing", "internal", "cloud_service", "endpoint", "ot"]
    notes: str = ""


class Theme(BaseModel):
    """A shared priority theme (``config/priorities.yaml``) that PIRs belong to."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str


class PIR(BaseModel):
    """Priority Intelligence Requirement: a decision-relevant question."""

    model_config = ConfigDict(extra="forbid")

    id: str
    question: str
    # Theme id from config/priorities.yaml; checked when profiles are loaded.
    theme: str
    keywords: list[str] = []


class Profile(BaseModel):
    """A customer environment the pipeline assesses intelligence against."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    # Shorter label for navigation and tables; defaults to ``name``.
    short_name: str = ""
    sector: str
    region: str
    description: str
    crown_jewels: list[str]
    technologies: list[Technology]
    pirs: list[PIR]

    @model_validator(mode="after")
    def _default_short_name(self) -> Profile:
        self.short_name = self.short_name or self.name
        return self


class LLMSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: Literal["codex", "fake"] = "codex"
    model: str = "gpt-6.1-sol"
    effort: dict[str, str] = {"analysis": "medium", "relevance": "medium", "hunt": "high"}
    timeout_seconds: int = 600
    max_concurrency: int = 3
    max_documents_per_run: int = 12


class HuntSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # One window for behavioural queries and IOC sweeps.
    lookback_days: int = 30
    # Sweep for IOCs found only in article bodies, not just IOC sections and feeds.
    include_scraped_iocs: bool = False


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_dir: str = "data"
    output_dir: str = "output"
    db_path: str = "data/ti.db"
    user_agent: str = "ti-pipeline/0.1 (+https://github.com/jackbaillie/ti-pipeline)"
    http_timeout_seconds: int = 30
    initial_lookback_days: int = 14
    kev_lookback_days: int = 30
    timezone: str = "Europe/London"
    llm: LLMSettings = LLMSettings()
    hunt: HuntSettings = HuntSettings()


# --------------------------------------------------------------------------
# LLM structured outputs (strict: every field required, no defaults)
# --------------------------------------------------------------------------

ReportType = Literal[
    "threat_research", "campaign", "incident", "vulnerability", "advisory", "news", "roundup", "other"
]
Priority = Literal["high", "medium", "low", "none"]
PyramidLevel = Literal[
    "hash_values", "ip_addresses", "domain_names", "network_host_artifacts", "tools", "ttps"
]


class AffectedTechnology(BaseModel):
    vendor: str
    product: str
    versions: str = Field(description="Affected versions if the source states them, otherwise an empty string.")
    evidence_quote: str = Field(description="Exact sentence from the source supporting this.")


class AttackStep(BaseModel):
    order: int
    description: str
    tactic: str = Field(description="ATT&CK tactic name, e.g. 'Persistence'.")
    technique_id: str = Field(description="ATT&CK Enterprise technique or sub-technique ID, e.g. T1059.001.")
    technique_name: str
    basis: Literal["stated", "inferred"] = Field(
        description="'stated' if the source explicitly describes this behaviour; 'inferred' if it is the analyst's reading."
    )
    evidence_quote: str = Field(description="Exact sentence copied verbatim from the source.")
    observables: list[str] = Field(
        description="Concrete huntable details from the source: commands, process names, paths, registry keys, services, user agents."
    )


class ReportAnalysis(BaseModel):
    summary: str
    report_type: ReportType
    huntable: bool
    huntable_reason: str
    threat_actors: list[str]
    malware: list[str]
    tools: list[str]
    affected_technologies: list[AffectedTechnology]
    cves: list[str]
    targeted_sectors: list[str]
    targeted_regions: list[str]
    attack_steps: list[AttackStep]


class ProfileAssessment(BaseModel):
    profile_id: str
    priority: Priority
    score: int = Field(description="0-100.")
    rationale: str
    matched_pirs: list[str] = Field(description="IDs of the profile's PIRs this intelligence answers.")
    matched_technologies: list[str]
    unknowns: list[str] = Field(description="What would change the assessment but is not known, e.g. exact versions deployed.")


class RelevanceResult(BaseModel):
    assessments: list[ProfileAssessment]


class DraftQuery(BaseModel):
    title: str
    purpose: str
    technique_ids: list[str]
    tables: list[str]
    kql: str
    benign_explanations: list[str]
    pivots: list[str]


class HuntDraft(BaseModel):
    title: str
    hypothesis: str
    scope: str
    pyramid_levels: list[PyramidLevel]
    queries: list[DraftQuery]


class QueryRepair(BaseModel):
    """Corrected versions of the draft queries that failed the schema check, in the same order."""

    queries: list[DraftQuery]


class InvestigationTerms(BaseModel):
    """Search terms for a free-text hunting hypothesis (manual investigations)."""

    keywords: list[str] = Field(description="Threat actors, malware, tools or behaviours named or implied; one to three words each.")
    products: list[str] = Field(description="Vendor and product names the hypothesis concerns.")
    technique_ids: list[str] = Field(description="ATT&CK Enterprise technique or sub-technique IDs the hypothesis describes.")
    cves: list[str] = Field(description="CVE IDs written in the hypothesis; empty if none.")


# --------------------------------------------------------------------------
# Stored records
# --------------------------------------------------------------------------


class StepValidation(BaseModel):
    order: int
    technique_valid: bool
    official_technique_name: str | None
    quote_verified: bool


class AnalysisValidation(BaseModel):
    """Deterministic checks applied to a ReportAnalysis (stored as validation_json)."""

    steps: list[StepValidation]
    technology_quotes_verified: list[bool]
    quotes_total: int
    quotes_verified: int
    invalid_techniques: list[str]


class KqlValidation(BaseModel):
    """Schema check of a KQL query. It is not executed, so this is not a syntax guarantee."""

    status: Literal["schema_valid", "warnings", "invalid"]
    tables: list[str]
    unknown_tables: list[str]
    unknown_columns: list[str]
    messages: list[str]


HuntStatus = Literal["prepared", "informational"]


class HuntTrigger(BaseModel):
    document_id: int
    title: str
    url: str
    source_id: str
    published_at: str | None


class HuntTechnique(BaseModel):
    id: str
    name: str
    tactic: str


class HuntEvidence(BaseModel):
    quote: str
    verified: bool


class PreparePhase(BaseModel):
    trigger: HuntTrigger
    priority: Priority
    relevance_rationale: str
    matched_pirs: list[str]
    hypothesis: str
    scope: str
    techniques: list[HuntTechnique]
    pyramid_levels: list[PyramidLevel]
    evidence: list[HuntEvidence]


class ExecutePhase(BaseModel):
    status: Literal["not_run", "completed", "failed"] = "not_run"
    runs: list[dict] = []
    notes: list[str] = []


class ActPhase(BaseModel):
    outcome: Literal["pending", "supported", "not_observed", "inconclusive"] = "pending"
    findings: list[str] = []
    detections_proposed: list[str] = []
    gaps: list[str] = []
    future_hunts: list[str] = []
    recommendations: list[str] = []


class HuntPackage(BaseModel):
    """A PEAK hypothesis-driven hunt (stored as hunts.package_json; queries live in the queries table)."""

    hunt_type: Literal["hypothesis-driven"] = "hypothesis-driven"
    framework: Literal["PEAK"] = "PEAK"
    document_id: int
    profile_id: str
    title: str
    status: HuntStatus
    prepare: PreparePhase
    execute: ExecutePhase = ExecutePhase()
    act: ActPhase = ActPhase()
    knowledge: list[str] = []
