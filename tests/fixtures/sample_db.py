"""Reusable, publication-safe synthetic pipeline data. Never opens data/ti.db."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from tipipeline.attack import Attack, Technique
from tipipeline.config import load_themes
from tipipeline.db import connect, dumps, init_db
from tipipeline.llm import FakeBackend
from tipipeline.models import (
    ActPhase, AnalysisValidation, AttackStep, HuntEvidence, HuntPackage, HuntTechnique,
    HuntTrigger, KqlValidation, PIR, PreparePhase, Profile, ReportAnalysis,
    Settings, SourceConfig, StepValidation, Technology, Theme,
)
from tipipeline.pipeline import Context, STAGES

SAMPLE_NOW = datetime(2026, 10, 5, 19, 10, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]


def sample_themes() -> list[Theme]:
    """The repository's shared priority themes (config/priorities.yaml)."""
    return load_themes(ROOT)


def sample_profiles() -> list[Profile]:
    common = dict(region="United Kingdom", description="Synthetic customer environment for demonstrations and tests.")
    return [
        Profile(id="law-firm", name="UK law firm", sector="Legal services", crown_jewels=["Client matter files", "M&A deal rooms", "Client funds"],
                technologies=[Technology(vendor="Citrix", product="NetScaler Gateway", exposure="internet_facing"), Technology(vendor="Microsoft", product="Microsoft 365", exposure="cloud_service"), Technology(vendor="iManage", product="Work", exposure="internal")],
                pirs=[PIR(id="LAW-1", question="Are actors exploiting our remote-access edge?", theme="edge", keywords=["Citrix", "VPN"]), PIR(id="LAW-2", question="Which ransomware behaviours threaten confidential client matters?", theme="ransomware", keywords=["ransomware", "legal"])], **common),
        Profile(id="retail-bank", name="UK retail bank", sector="Financial services", crown_jewels=["Customer accounts", "Payment systems", "Core banking availability"],
                technologies=[Technology(vendor="Fortinet", product="FortiOS", exposure="internet_facing"), Technology(vendor="Microsoft", product="Microsoft 365", exposure="cloud_service")],
                pirs=[PIR(id="BANK-1", question="What credential-theft behaviours threaten customer and staff accounts?", theme="identity"), PIR(id="BANK-2", question="Which exploited edge vulnerabilities require urgent action?", theme="edge")], **common),
        Profile(id="manufacturer-ot", name="UK manufacturer with OT", sector="Manufacturing", crown_jewels=["Production availability", "Engineering workstations", "Safety and process integrity"],
                technologies=[Technology(vendor="Siemens", product="SIMATIC", exposure="ot"), Technology(vendor="Rockwell", product="FactoryTalk", exposure="ot"), Technology(vendor="Fortinet", product="FortiOS", exposure="internet_facing")],
                pirs=[PIR(id="OT-1", question="Which ransomware campaigns threaten our production boundary?", theme="ransomware"), PIR(id="OT-2", question="Which attacks could disrupt production across the IT/OT boundary?", theme="ot")], **common),
    ]


def sample_sources() -> list[SourceConfig]:
    return [
        SourceConfig(id="vendor-research", name="Example research", kind="rss", url="https://research.example/feed", tier="research"),
        SourceConfig(id="government", name="Government advisories", kind="rss", url="https://advisories.example/feed", tier="government"),
        SourceConfig(id="cisa-kev", name="CISA KEV", kind="cisa_kev", url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", tier="government"),
        SourceConfig(id="threatfox", name="ThreatFox", kind="threatfox", url="https://threatfox-api.abuse.ch/api/v1/", tier="ioc_feed"),
        SourceConfig(id="news", name="Security news", kind="rss", url="https://news.example/feed", tier="news"),
    ]


def sample_attack() -> Attack:
    specs = [
        ("T1190", "Exploit Public-Facing Application", ("Initial Access",)),
        ("T1505.003", "Web Shell", ("Persistence",)),
        ("T1059.001", "PowerShell", ("Execution",)),
        ("T1003.001", "LSASS Memory", ("Credential Access",)),
        ("T1567.002", "Exfiltration to Cloud Storage", ("Exfiltration",)),
        ("T1133", "External Remote Services", ("Initial Access", "Persistence")),
        ("T1486", "Data Encrypted for Impact", ("Impact",)),
    ]
    return Attack({id_: Technique(id_, name, tactics, f"https://attack.mitre.org/techniques/{id_.replace('.', '/')}/", False) for id_, name, tactics in specs})


def _insert(conn, table: str, **values):
    conn.execute(f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", list(values.values()))


def build_sample_context(root: Path, *, now: datetime = SAMPLE_NOW) -> Context:
    conn = connect(root / "sample.db")
    init_db(conn)
    ctx = Context(root=root, settings=Settings(), sources=sample_sources(), profiles=sample_profiles(), db=conn, llm=FakeBackend(), run_id=3, themes=sample_themes())
    ctx.__dict__["attack"] = sample_attack()
    populate_sample_db(conn, now=now)
    return ctx


def populate_sample_db(conn, *, now: datetime = SAMPLE_NOW) -> None:
    """Populate every schema table. Call on an empty initialized database."""
    iso = lambda hours=0, minutes=0: (now + timedelta(hours=hours, minutes=minutes)).isoformat(timespec="seconds")
    for id_, hours, status in [(1, -36, "ok"), (2, -12, "partial"), (3, -0.15, "running")]:
        stages = {stage: {"status": "ok", "seconds": 1.2} for stage in STAGES}
        if id_ == 2:
            stages["collect"] = {"status": "ok", "errors": 1, "seconds": 4.2}
            stages["analyse"] = {"status": "error", "error": "One report exceeded the analysis timeout", "seconds": 600}
        if id_ == 3:
            stages = {k: v for k, v in stages.items() if k not in {"report", "dashboard"}}
        _insert(conn, "runs", id=id_, started_at=iso(hours), finished_at=None if status == "running" else iso(hours, 8), status=status, stages_json=dumps(stages))
    for run_id in (1, 2, 3):
        for i, source_id in enumerate(["vendor-research", "government", "cisa-kev", "threatfox", "news"]):
            error = run_id == 3 and source_id == "news"
            _insert(conn, "source_fetches", run_id=run_id, source_id=source_id, fetched_at=iso(-36 if run_id == 1 else -12 if run_id == 2 else -0.1, i), status="error" if error else "ok", items_seen=0 if error else 8+i, items_new=0 if error else 2, items_updated=1 if source_id == "vendor-research" else 0, error="HTTP 403: source denied the request" if error else None)

    quotes = [
        "The operators exploited Citrix NetScaler Gateway to gain initial access.",
        "A web shell was written to the appliance and used to execute commands.",
        "PowerShell downloaded a second-stage payload from https://updates-example.net/stage.ps1.",
        "The payload accessed LSASS memory to obtain credentials.",
        "Stolen matter files were transferred to an external cloud storage account.",
        "This sentence is not present in the source report.",
    ]
    titles = {
        1: "Remote-access exploitation and credential theft against UK legal services",
        2: "Ransomware actors target manufacturing remote access",
        3: "CVE-2026-12345 — Citrix NetScaler Gateway exploitation",
        4: "ThreatFox IOC batch: ExampleLoader",
        5: "Legal sector attacked through a remote-access gateway",
        6: '<script>alert("title")</script> & a failed research analysis',
        7: "Older credential theft report outside the digest window",
        8: "CVE-2026-23456 — Fortinet FortiOS exploited vulnerability",
        9: "Retail breach disclosure: customer data exposure",
    }
    for id_, title in titles.items():
        kind = "vulnerability" if id_ in (3, 8) else "ioc_batch" if id_ == 4 else "advisory" if id_ == 2 else "article"
        source = "cisa-kev" if id_ in (3, 8) else "threatfox" if id_ == 4 else "government" if id_ == 2 else "news" if id_ in (5, 9) else "vendor-research"
        tier = next(s.tier for s in sample_sources() if s.id == source)
        meta = {}
        if id_ in (3, 8):
            meta = {"cveID": "CVE-2026-12345" if id_ == 3 else "CVE-2026-23456", "vendorProject": "Citrix" if id_ == 3 else "Fortinet", "product": "NetScaler Gateway" if id_ == 3 else "FortiOS", "vulnerabilityName": title, "shortDescription": "Remote-access software vulnerability with evidence of exploitation.", "dateAdded": "2026-10-05", "dueDate": "2026-10-19", "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply vendor mitigations and investigate affected systems."}
        if id_ == 4:
            meta = {"malware": "ExampleLoader", "iocs": [{"ioc_type": "ip:port", "ioc": "198.51.100.42:443", "confidence_level": 80}]}
        collected = iso(-48) if id_ == 7 else iso(-11, id_)
        text = "\n".join(quotes[:5]) + "\nT1190\nIndicators: 198.51.100.42 updates-example.net" if id_ == 1 else "Remote services were used to access the environment. Files were encrypted on engineering workstations." if id_ == 2 else "Synthetic source text for " + title
        _insert(conn, "documents", id=id_, source_id=source, kind=kind, tier=tier, url=f"https://reports.example/doc-{id_}", canonical_url=f"https://reports.example/doc-{id_}", title=title, published_at=iso(-14, id_), collected_at=collected, updated_at=iso(-1) if id_ == 1 else collected, content_hash=f"hash-{id_}-v2" if id_ == 1 else f"hash-{id_}", version=2 if id_ == 1 else 1, text=text, meta_json=dumps(meta), duplicate_of=1 if id_ == 5 else None, cluster_id=1 if id_ in (1, 3, 4, 5) else 2 if id_ in (2, 8) else id_, processed_version=2 if id_ == 1 else 1, extracted_version=2 if id_ == 1 else 1)
        for version in range(1, 3 if id_ == 1 else 2):
            _insert(conn, "document_versions", document_id=id_, version=version, content_hash=f"hash-{id_}-v{version}", title=title, text=text, collected_at=collected)
    for a, b, reason, detail, score in [(1, 5, "near_duplicate", "overlapping report text", .93), (1, 3, "shared_cve", "CVE-2026-12345", None), (1, 4, "shared_indicator", "198.51.100.42", None), (2, 8, "shared_cve", "CVE-2026-23456", None)]:
        _insert(conn, "document_links", doc_a=a, doc_b=b, reason=reason, detail=detail, score=score)

    indicators = [
        ("ipv4", "198.51.100.42", None), ("ipv6", "2001:db8::42", None),
        ("domain", "updates-example.net", None), ("url", "https://updates-example.net/stage.ps1", None),
        ("md5", "a"*32, None), ("sha1", "b"*40, None), ("sha256", "c"*64, None),
        ("email", "billing@updates-example.net", None), ("cve", "CVE-2026-12345", None),
        ("ipv4", "8.8.8.8", "Public DNS resolvers"), ("domain", "login.microsoftonline.com", "Microsoft services"),
        ("cve", "CVE-2026-23456", None),
    ]
    for id_, (type_, value, warninglist) in enumerate(indicators, 1):
        _insert(conn, "indicators", id=id_, type=type_, value=value, first_seen=iso(-36), last_seen=iso(-.1))
        doc_ids = [3] if id_ == 9 else [2, 8] if id_ == 12 else [1, 4] if id_ in (1, 3, 6) else [1]
        for doc_id in doc_ids:
            _insert(conn, "document_indicators", document_id=doc_id, indicator_id=id_, context="feed" if doc_id == 4 else "metadata" if doc_id in (3, 8) else "body" if warninglist else "ioc_section", snippet=f"Observed value: {value}", warninglist=warninglist)

    attack = sample_attack()
    specs = [("T1190", "Initial Access", "stated"), ("T1505.003", "Persistence", "stated"), ("T1059.001", "Execution", "stated"), ("T1003.001", "Credential Access", "inferred"), ("T1567.002", "Exfiltration", "inferred"), ("T1999", "Discovery", "inferred")]
    steps = [AttackStep(order=i, description=q, tactic=tactic, technique_id=id_, technique_name=attack.get(id_).name if attack.get(id_) else "Unknown technique", basis=basis, evidence_quote=q, observables=["powershell.exe"] if id_ == "T1059.001" else []) for i, ((id_, tactic, basis), q) in enumerate(zip(specs, quotes), 1)]
    reports = {
        1: ReportAnalysis(summary="A remote-access intrusion progressed from gateway exploitation to credential theft and exfiltration of legal matter files.", report_type="campaign", huntable=True, huntable_reason="Concrete remote-access and process behaviours support endpoint hunts.", threat_actors=["Storm-2077 (synthetic)"], malware=["ExampleLoader"], tools=["PowerShell"], affected_technologies=[{"vendor": "Citrix", "product": "NetScaler Gateway", "versions": "Not stated", "evidence_quote": quotes[0]}], cves=["CVE-2026-12345"], targeted_sectors=["Legal services", "Financial services"], targeted_regions=["United Kingdom"], attack_steps=steps),
        2: ReportAnalysis(summary="Ransomware operators used external remote services before encrypting engineering workstations.", report_type="advisory", huntable=True, huntable_reason="Remote-service and impact behaviours are described, but IT/OT telemetry coverage varies.", threat_actors=[], malware=["ExampleRansom"], tools=[], affected_technologies=[], cves=["CVE-2026-23456"], targeted_sectors=["Manufacturing"], targeted_regions=["United Kingdom"], attack_steps=[AttackStep(order=1, description="Remote access", tactic="Initial Access", technique_id="T1133", technique_name="External Remote Services", basis="stated", evidence_quote="Remote services were used to access the environment.", observables=[]), AttackStep(order=2, description="Encryption", tactic="Impact", technique_id="T1486", technique_name="Data Encrypted for Impact", basis="stated", evidence_quote="Files were encrypted on engineering workstations.", observables=[])]),
        7: ReportAnalysis(summary="An older credential-theft report.", report_type="threat_research", huntable=False, huntable_reason="No concrete observables.", threat_actors=[], malware=[], tools=[], affected_technologies=[], cves=[], targeted_sectors=["Legal services"], targeted_regions=[], attack_steps=[]),
        9: ReportAnalysis(summary="A retailer disclosed exposure of customer information, without technical intrusion details.", report_type="news", huntable=False, huntable_reason="Disclosure contains no reproducible behaviours or IOCs.", threat_actors=[], malware=[], tools=[], affected_technologies=[], cves=[], targeted_sectors=["Retail"], targeted_regions=["United Kingdom"], attack_steps=[]),
    }
    for doc_id, report in reports.items():
        checks = [StepValidation(order=s.order, technique_valid=attack.is_valid(s.technique_id), official_technique_name=attack.get(s.technique_id).name if attack.get(s.technique_id) else None, quote_verified=s.technique_id != "T1999") for s in report.attack_steps]
        validation = AnalysisValidation(steps=checks, technology_quotes_verified=[True]*len(report.affected_technologies), quotes_total=len(checks)+len(report.affected_technologies), quotes_verified=sum(s.quote_verified for s in checks)+len(report.affected_technologies), invalid_techniques=[s.technique_id for s in report.attack_steps if not attack.is_valid(s.technique_id)])
        _insert(conn, "analyses", document_id=doc_id, document_version=2 if doc_id == 1 else 1, status="ok", model="fake", created_at=iso(-40) if doc_id == 7 else iso(-.08), summary=report.summary, report_type=report.report_type, huntable=int(report.huntable), analysis_json=report.model_dump_json(), validation_json=validation.model_dump_json())
        for s, check in zip(report.attack_steps, checks):
            _insert(conn, "document_techniques", document_id=doc_id, technique_id=s.technique_id, source="llm", step_order=s.order, basis=s.basis, quote=s.evidence_quote, quote_verified=int(check.quote_verified), valid=int(check.technique_valid))
    _insert(conn, "document_techniques", document_id=1, technique_id="T1190", source="explicit", step_order=0, quote="T1190", quote_verified=1, valid=1)
    _insert(conn, "analyses", document_id=6, document_version=1, status="error", model="fake", created_at=iso(-.08), error="Analysis timed out; no structured output was stored.")

    relevance_specs = {
        1: [("high", 92), ("medium", 68), ("medium", 58)],
        2: [("low", 25), ("medium", 60), ("high", 87)],
        3: [("high", 95), ("none", 0), ("none", 0)],
        8: [("none", 0), ("high", 91), ("high", 89)],
        7: [("medium", 52), ("low", 20), ("none", 0)],
        9: [("low", 20), ("medium", 51), ("low", 20)],
    }
    profiles = sample_profiles()
    for doc_id, scores in relevance_specs.items():
        for profile, (priority, score) in zip(profiles, scores):
            _insert(conn, "relevance", document_id=doc_id, profile_id=profile.id, document_version=2 if doc_id == 1 else 1, priority=priority, score=score, rationale="Confirmed deployed technology matches the KEV entry; deployed versions are unknown." if doc_id in (3, 8) and score else "No deployed technology match." if doc_id in (3, 8) else "The reported behaviours and targeted sector intersect with this environment's crown jewels.", matched_pirs_json=dumps([profile.pirs[0].id] if score else []), matched_technologies_json=dumps(["Citrix NetScaler Gateway" if doc_id == 3 else "Fortinet FortiOS"] if doc_id in (3, 8) and score else []), unknowns_json=dumps(["Exact deployed versions and exposure are not confirmed."] if score else []), method="rules" if doc_id in (3, 8) else "llm", created_at=iso(-40) if doc_id == 7 else iso(-.06))

    hunt_specs = [(1, 1, "law-firm", "prepared"), (2, 1, "retail-bank", "prepared"), (3, 1, "manufacturer-ot", "prepared"), (4, 2, "manufacturer-ot", "prepared"), (5, 9, "retail-bank", "informational")]
    for id_, doc_id, profile_id, status in hunt_specs:
        profile = next(p for p in profiles if p.id == profile_id)
        prepared = status == "prepared"
        ot = profile_id == "manufacturer-ot"
        title = "Gateway-to-endpoint intrusion chain" if doc_id == 1 else "Remote-access ransomware at the IT/OT boundary" if doc_id == 2 else "Retail breach context review"
        hypothesis = "An intruder used remote-access infrastructure to execute PowerShell and access credential material on managed endpoints." if doc_id == 1 else "Remote access preceded ransomware activity on engineering workstations." if doc_id == 2 else "Disclosure may inform future customer-data risk decisions; no technical hunt hypothesis is supported."
        package = HuntPackage(document_id=doc_id, profile_id=profile_id, title=title, status=status,
            prepare=PreparePhase(trigger=HuntTrigger(document_id=doc_id, title=titles[doc_id], url=f"https://reports.example/doc-{doc_id}", source_id="vendor-research" if doc_id == 1 else "government" if doc_id == 2 else "news", published_at=iso(-14)), priority="high" if profile_id == "law-firm" or doc_id == 2 else "medium", relevance_rationale="Protect confidential information and determine whether the intrusion chain is present.", matched_pirs=[profile.pirs[0].id], hypothesis=hypothesis, scope="30 days of telemetry; managed endpoints and remote-access edge.", techniques=[HuntTechnique(id="T1059.001", name="PowerShell", tactic="Execution")] if prepared else [], pyramid_levels=["ip_addresses", "domain_names", "ttps"] if prepared else [], evidence=[HuntEvidence(quote=quotes[2], verified=True), HuntEvidence(quote=quotes[5], verified=False)] if doc_id == 1 else []),
            act=ActPhase(gaps=["IT endpoint, identity and perimeter logs do not show OT activity. Confirm plant-floor coverage before reading a clean result as no OT activity."] if ot else [], recommendations=["Confirm asset scope and validate query results before escalation."], future_hunts=["Investigate remote-access authentication anomalies."], detections_proposed=["Consider a scheduled analytic for web-server processes spawning scripting engines after validation."] if prepared and not ot else []), knowledge=["A prepared query is not an executed hunt or a detection finding."])
        _insert(conn, "hunts", id=id_, document_id=doc_id, profile_id=profile_id, document_version=2 if doc_id == 1 else 1, status=status, title=title, hypothesis=hypothesis, package_json=package.model_dump_json(), created_at=iso(-.04), updated_at=iso(-.03))
        if not prepared:
            continue
        for kind, generated_by in [("ioc_sweep", "template"), ("behavioural", "llm")]:
            table = "DeviceNetworkEvents" if kind == "ioc_sweep" else "DeviceProcessEvents"
            kql = 'let lookback = 30d;\nlet indicator_ips = dynamic(["198.51.100.42"]);\nDeviceNetworkEvents\n| where TimeGenerated >= ago(lookback)\n| where RemoteIP in (indicator_ips)\n| project TimeGenerated, DeviceName, RemoteIP, InitiatingProcessFileName' if kind == "ioc_sweep" else 'let lookback = 30d;\nDeviceProcessEvents\n| where TimeGenerated >= ago(lookback)\n| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe")\n| where FileName in~ ("powershell.exe", "cmd.exe")\n| project TimeGenerated, DeviceName, FileName, ProcessCommandLine'
            validation = KqlValidation(status="schema_valid", tables=[table], unknown_tables=[], unknown_columns=[], messages=[])
            _insert(conn, "queries", hunt_id=id_, kind=kind, title="IOC network sweep" if kind == "ioc_sweep" else "Web-server child process investigation", purpose="Locate indicator connections; results require investigation." if kind == "ioc_sweep" else "Test the hypothesis of web-server-to-shell execution.", kql=kql, tables_json=dumps([table]), technique_ids_json=dumps([] if kind == "ioc_sweep" else ["T1059.001"]), benign_json=dumps(["Approved administration or software deployment may resemble this activity."]), pivots_json=dumps(["Review parent process, user identity and network destination."]), generated_by=generated_by, validation_status="schema_valid", validation_json=validation.model_dump_json(), created_at=iso(-.02))
    for status, doc_id, task in [("ok", 1, "analysis"), ("error", 6, "analysis"), ("ok", 1, "relevance"), ("ok", 1, "hunt")]:
        _insert(conn, "llm_calls", run_id=3, task=task, document_id=doc_id, model="fake", effort="medium", started_at=iso(-.08), duration_ms=1400, status=status, error="Timed out" if status == "error" else None)
    conn.commit()
