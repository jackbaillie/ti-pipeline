"""Deterministic markdown renderers. No report text is interpreted as markdown."""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from tipipeline.report.data import Doc, Hunt, Snapshot
from tipipeline.report.digest import ProfileDigest
from tipipeline.report.text import (
    CONTEXT_LABELS, INDICATOR_LABELS, INDICATOR_ORDER, PYRAMID_LABELS,
    defang_text, first_sentence, format_time, md_code, md_fence, md_inline as esc,
    md_link, md_url,
)


def _list(values: list[str], empty: str = "None recorded.") -> str:
    return "\n".join(f"- {esc(v)}" for v in values) if values else empty


def _joined(values: list[str]) -> str:
    return ", ".join(esc(v) for v in values) or "None recorded"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    return ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |", *["| " + " | ".join(row) + " |" for row in rows], ""]


def _time(value: str | None, s: Snapshot) -> str:
    return esc(format_time(value, s.tz, with_zone=True))


def kev_fields(doc: Doc) -> list[tuple[str, str]]:
    keys = [("CVE", "cveID"), ("Vendor", "vendorProject"), ("Product", "product"),
            ("Vulnerability", "vulnerabilityName"), ("Added to KEV", "dateAdded"),
            ("Remediation due", "dueDate"), ("Ransomware campaign use", "knownRansomwareCampaignUse"),
            ("Required action", "requiredAction")]
    return [(label, str(doc.meta[key])) for label, key in keys if doc.meta.get(key)]


def document_markdown(s: Snapshot, doc: Doc) -> str:
    a = s.analyses.get(doc.id)
    lines = [f"# {esc(doc.title)}", "", *_table(["Field", "Value"], [
        ["Document", f"{doc.id} · version {doc.version}"], ["Source", f"{esc(doc.source_name)} ({esc(doc.tier)})"],
        ["Source link", md_url(doc.url)], ["Published", _time(doc.published_at, s)],
        ["Collected", _time(doc.collected_at, s)], ["Updated", _time(doc.updated_at, s)], ["Kind", esc(doc.kind)],
    ])]
    if doc.duplicate_of:
        lines += [f"Duplicate of document {doc.duplicate_of}; not independent corroboration.", ""]
    if a:
        lines += ["## Analysis", "", f"Status: **{esc(a.status)}** · analysed document version {a.document_version}.", ""]
        if a.document_version != doc.version:
            lines += [f"**Stale analysis:** this assessment predates document version {doc.version}.", ""]
        if a.error or a.parse_error:
            lines += [esc(a.error or a.parse_error), ""]
        if a.summary:
            lines += [esc(a.summary), ""]
        if a.report:
            r = a.report
            lines += [f"Report type: **{esc(r.report_type)}**", "", f"Huntable: **{'yes' if r.huntable else 'no'}** — {esc(r.huntable_reason)}", "",
                      f"Actors: {_joined(r.threat_actors)}", "", f"Malware: {_joined(r.malware)}", "", f"Tools: {_joined(r.tools)}", "",
                      f"Targeted sectors: {_joined(r.targeted_sectors)}", "", f"Targeted regions: {_joined(r.targeted_regions)}", "",
                      "### Affected technologies", ""]
            if r.affected_technologies:
                checks = a.validation.technology_quotes_verified if a.validation else []
                lines += _table(["Vendor / product", "Versions", "Evidence quote", "Quote check"], [
                    [esc(f"{t.vendor} {t.product}"), esc(t.versions) or "Not stated", esc(t.evidence_quote),
                     "verified" if i < len(checks) and checks[i] else "unverified"]
                    for i, t in enumerate(r.affected_technologies)])
            else:
                lines += ["No affected technologies stated.", ""]
            lines += ["### ATT&CK attack steps", ""]
            steps = s.steps(doc.id)
            if steps:
                lines += _table(["Order", "Tactic", "Technique (official name)", "Basis", "Evidence quote", "Quote check"], [
                    [str(st.order), esc(st.tactic), md_code(st.technique_id) + " " + esc(st.name) + (" **INVALID ID**" if not st.valid else ""),
                     esc(st.basis), esc(st.quote), "verified" if st.verified else "unverified"] for st in steps])
                for st in steps:
                    lines += [f"**Step {st.order}:** {esc(st.description)}"]
                    if st.observables:
                        lines += [f"Observables: {_joined([defang_text(v) for v in st.observables])}"]
                    lines += [""]
            else:
                lines += ["No ATT&CK steps extracted.", ""]
            if a.validation:
                lines += [f"Quote checks: {a.validation.quotes_verified}/{a.validation.quotes_total} exact source quotes verified. Verification checks text support, not independent truth.", ""]
    else:
        lines += ["## Analysis", "", "No report analysis available. Any relevance below is rules-based or awaits analysis.", ""]
    if doc.is_kev:
        lines += ["## Known exploited vulnerability", ""]
        if doc.meta.get("shortDescription"):
            lines += [esc(doc.meta["shortDescription"]), ""]
        lines += _table(["Field", "Value"], [[esc(k), esc(v)] for k, v in kev_fields(doc)])
    explicit = s.explicit_techniques(doc.id)
    if explicit:
        lines += ["## Explicit ATT&CK ID mentions", "", "An explicit ID mention is not an independently verified attack step.", ""]
        lines += _table(["ID", "Official name", "Validity"], [[md_code(u.technique_id), esc(u.name) or "Unavailable", "valid" if u.valid else "**INVALID ID**"] for u in explicit])
    lines += ["## Indicators", "", "Display values are defanged. Warninglisted indicators may be benign/shared infrastructure and should not be treated as confirmed malicious.", ""]
    grouped: dict[str, list] = defaultdict(list)
    for i in s.indicators_by_doc.get(doc.id, []):
        grouped[i.type].append(i)
    if not grouped:
        lines += ["No indicators extracted.", ""]
    for type_ in INDICATOR_ORDER:
        if type_ not in grouped:
            continue
        lines += [f"### {INDICATOR_LABELS[type_]}", ""]
        lines += _table(["Value (defanged)", "Context", "Warninglist", "Source snippet"], [
            [md_code(i.display), esc(CONTEXT_LABELS.get(i.context, i.context)), esc(i.warninglist) or "No match",
             esc(defang_text(i.snippet, [j.value for j in s.indicators_by_doc.get(doc.id, [])]))] for i in grouped[type_]])
    lines += ["## Relevance by profile", ""]
    rows = s.relevance_by_doc.get(doc.id, [])
    if not rows:
        lines += ["Not assessed for any profile yet.", ""]
    for r in rows:
        lines += [f"### {esc(s.profile_name(r.profile_id))}", "", f"**{r.priority.title()}** · score {r.score}/100 · method: {esc(r.method)}", "", esc(r.rationale), "",
                  f"Matched PIRs: {_joined(r.matched_pirs)}", "", f"Matched technologies: {_joined(r.matched_technologies)}", "",
                  "Unknowns:", _list(r.unknowns, "None recorded; this does not imply full certainty."), ""]
        if r.document_version != doc.version:
            lines += [f"**Stale relevance:** assessed document version {r.document_version}, current version {doc.version}.", ""]
    lines += ["## Hunt packages", ""]
    hunts = s.hunts_for_doc(doc.id)
    if hunts:
        for h in hunts:
            lines += [f"- {md_link(h.title, f'../../hunts/{h.profile_id}/{h.stem}.md')} — {esc(s.profile_name(h.profile_id))}; {esc(h.status)}"]
        lines += [""]
    else:
        lines += ["No hunt packages prepared.", ""]
    lines += ["## Related reporting", ""]
    related = s.related(doc.id)
    if related:
        for other, reasons in related:
            label = md_link(other.title, f"{other.id}.md") if other.id in s.assessed_doc_ids() else esc(other.title) + f" (document {other.id}, not assessed)"
            lines += [f"- {label} — {esc('; '.join(reasons))}"]
    else:
        lines += ["No related documents in this cluster."]
    return "\n".join(lines).rstrip() + "\n"


def hunt_markdown(s: Snapshot, h: Hunt) -> str:
    lines = [f"# {esc(h.title)}", "", f"Profile: **{esc(s.profile_name(h.profile_id))}** · hunt #{h.id} · status: **{esc(h.status)}**", "",
             "Framework: PEAK · hypothesis-driven. Queries are prepared, not executed. Schema checks are not KQL syntax or semantic guarantees.", ""]
    if h.package is None:
        lines += ["Hunt package could not be read: " + esc(h.package_error), ""]
        return "\n".join(lines)
    p = h.package.prepare
    profile = s.profiles.get(h.profile_id)
    questions = {pir.id: pir.question for pir in profile.pirs} if profile else {}
    doc = s.docs.get(h.document_id)
    if doc and doc.version != h.document_version:
        lines += [f"**Stale hunt:** prepared for document version {h.document_version}; current version {doc.version}.", ""]
    lines += ["## Prepare", "", "### Trigger", "",
              md_link(p.trigger.title, f"../../reports/documents/{p.trigger.document_id}.md"), "", md_url(p.trigger.url), "",
              f"Source: {esc(p.trigger.source_id)} · published: {_time(p.trigger.published_at, s)}", "",
              f"Priority: **{p.priority.title()}**", "", esc(p.relevance_rationale), "", "### Matched PIRs", ""]
    lines += [f"- {md_code(id_)} — {esc(questions.get(id_, 'Question unavailable in current profile configuration.'))}" for id_ in p.matched_pirs] or ["No PIRs matched."]
    lines += ["", "### Hypothesis", "", esc(p.hypothesis), "", "### Scope", "", esc(p.scope), "", "### Techniques", ""]
    lines += _table(["ID", "Official name", "Tactic"], [[md_code(t.id), esc(t.name), esc(t.tactic)] for t in p.techniques]) if p.techniques else ["No techniques mapped.", ""]
    lines += ["### Pyramid of Pain", "", _list([PYRAMID_LABELS.get(level, level) for level in p.pyramid_levels], "No levels recorded."), "", "### Telemetry", ""]
    lines += _table(["Required tables", "Available", "Missing"], [[_joined(p.required_tables), _joined(p.available_tables), _joined(p.missing_tables)]])
    lines += ["### Evidence", ""]
    lines += _table(["Quote", "Verification"], [[esc(e.quote), "verified" if e.verified else "unverified"] for e in p.evidence]) if p.evidence else ["No evidence quotes recorded.", ""]
    lines += ["## Execute", "", f"Status: **{esc(h.package.execute.status.replace('_', ' '))}**", ""]
    if h.package.execute.notes:
        lines += [_list(h.package.execute.notes), ""]
    if not h.queries:
        lines += ["No queries prepared. Review telemetry gaps before attempting execution.", ""]
    for q in h.queries:
        lines += [f"### {esc(q.title)}", "", esc(q.purpose), "",
                  f"Kind: {esc(q.kind)} · generated by: {esc(q.generated_by)} · validation: **{esc(q.validation_status)}**", "",
                  f"Tables: {_joined(q.tables)} · techniques: {_joined(q.technique_ids)}", ""]
        lines += [_list(q.validation.messages, "No schema-check messages.") if q.validation else "Validation details unavailable.", "", md_fence(q.kql, "kusto"), "",
                  "Benign explanations:", _list(q.benign, "None recorded; investigate false-positive causes before acting."), "",
                  "Pivots:", _list(q.pivots, "None recorded."), ""]
    act = h.package.act
    lines += ["## Act", "", f"Outcome: **{esc(act.outcome)}** (no findings are implied before execution).", ""]
    for heading, values in [("Findings", act.findings), ("Gaps", act.gaps), ("Future hunts", act.future_hunts), ("Recommendations", act.recommendations), ("Detection proposals", act.detections_proposed)]:
        lines += [f"### {heading}", "", _list(values, "None recorded."), ""]
    lines += ["## Knowledge", "", _list(h.package.knowledge, "No additional knowledge recorded."), ""]
    return "\n".join(lines).rstrip() + "\n"


def digest_markdown(s: Snapshot, d: ProfileDigest, *, reports_prefix: str, hunts_prefix: str, stix_prefix: str, upload_files: list[Path]) -> str:
    profile = s.profiles[d.profile_id]
    lines = [f"# {esc(profile.name)} — intelligence digest", "", f"Window: {_time(d.window.start.isoformat(), s)} → {_time(d.window.end.isoformat(), s)}", "",
             f"Selection: {esc(d.window.basis)}. Includes updated documents and newly assessed deferred reporting. Label: {d.window.label} ({esc(s.timezone)}).", "",
             f"{d.window_doc_count} non-duplicate documents collected/updated; {d.assessed_count} assessed for this profile; {d.low_or_none} low/not-relevant items omitted from strategic briefing.", "",
             "## Strategic", "", "What matters to this organisation and why.", ""]
    if d.actors:
        lines += [f"Actors in relevant reporting: {_joined(d.actors)}", ""]
    if d.sectors:
        lines += [f"Targeted sectors in relevant reporting: {_joined(d.sectors)}", ""]
    if not d.items and not d.kev:
        lines += ["No high- or medium-priority intelligence assessed in this window. This is not evidence of an absence of threats; check source health and deferred/unanalysed documents.", ""]
    if d.items:
        for item in d.items:
            r, doc = item.relevance, item.doc
            a = s.analyses.get(doc.id)
            lines += [f"### {r.priority.title()} · {md_link(doc.title, reports_prefix + f'{doc.id}.md')}", "",
                      esc(first_sentence(a.summary if a else "")) or "No analytical summary available.", "", f"**Why it matters ({r.score}/100):** {esc(r.rationale)}", ""]
            if r.unknowns:
                lines += [f"Unknowns: {_joined(r.unknowns)}", ""]
    lines += ["### KEV matches", ""]
    if not d.kev:
        lines += ["No high- or medium-priority KEV technology matches in this window.", ""]
    else:
        lines += _table(["Vulnerability", "Priority", "Matched technology / why", "Action due"], [
            [md_link(i.doc.meta.get("cveID", i.doc.title), reports_prefix + f'{i.doc.id}.md'), i.relevance.priority.title(), esc(i.relevance.rationale), esc(i.doc.meta.get("dueDate", "Not stated"))] for i in d.kev])
    lines += ["## Operational", "", "Hunt packages prepared during this window. Nothing has been executed against a workspace.", ""]
    if not d.hunts:
        lines += ["No hunt packages prepared or updated in this window.", ""]
    else:
        lines += _table(["Hunt", "Status", "Hypothesis", "Telemetry gaps"], [
            [md_link(h.title, f'{hunts_prefix}{h.profile_id}/{h.stem}.md'), esc(h.status), esc(h.hypothesis), _joined(h.missing_tables)] for h in d.hunts])
    lines += ["## Tactical", "", "Unique indicators across the run-window reporting (all sources, not a claim of profile-specific maliciousness). Warninglist matches are included in counts but should be reviewed before use.", ""]
    if not d.indicator_counts:
        lines += ["No indicators extracted from documents collected or updated in this window.", ""]
    else:
        lines += _table(["Type", "Unique values", "Warninglisted"], [[INDICATOR_LABELS[t], str(n), str(w)] for t, n, w in d.indicator_counts])
    lines += ["### STIX upload batches", "", f"Path: {md_code('output/stix/sentinel-upload/')}", ""]
    if upload_files:
        lines += [f"- {md_link(path.name, stix_prefix + path.name)}" for path in upload_files] + [""]
    else:
        lines += ["No Sentinel upload batches available. Run the export stage before importing indicators.", ""]
    lines += ["### IOC sweep queries", "", "Prepared only; review validation messages, time ranges and warninglisted/shared infrastructure before running.", ""]
    if not d.sweeps:
        lines += ["No IOC sweep queries available for this profile in this window.", ""]
    for h, q in d.sweeps:
        lines += [f"#### {esc(q.title)}", "", md_link(h.title, f'{hunts_prefix}{h.profile_id}/{h.stem}.md'), "",
                  f"Validation: **{esc(q.validation_status)}**", "", md_fence(q.kql, "kusto"), ""]
    return "\n".join(lines).rstrip() + "\n"
