# ti-pipeline

A threat-intelligence pipeline that monitors research and advisory feeds, assesses relevance to example customer environments, and prepares **PEAK hypothesis-driven hunt packages** for Microsoft Sentinel and Defender XDR.

The useful question is not just “which indicators were published?” It is **“why does this report matter to this environment, and what could we search for?”**

This is a runnable demonstration project, not an autonomous SOC or a production detection service. It prepares investigations; an analyst still reviews the intelligence and queries. No Azure resources are required to run it.

**[Explore a real-source example](examples/README.md)** — report analysis, three customer-specific hunt packages, KQL, STIX and a dashboard screenshot. The example includes an unavailable-telemetry query rather than presenting every generated search as runnable.

## Workflow

```text
Research blogs / advisories / KEV / optional ThreatFox
  → collect full text and preserve source metadata
  → canonicalise URLs, version changed documents, identify near-duplicates
  → extract observables, flag warninglist matches, link related reports
  → analyse behaviour with source quotes and current ATT&CK IDs
  → assess relevance against each customer's intelligence requirements
  → prepare hypotheses, KQL and visibility gaps
  → export STIX, hunt packages, briefings and a static dashboard
```

- **Collection:** configured RSS/Atom feeds, CISA KEV JSON and optional authenticated ThreatFox collection. One source failing does not discard other sources' results.
- **Document history:** canonical URLs and content hashes prevent identical re-imports. Changed content creates a new document version. Near-duplicate and shared-observable links help connect reporting; they do not establish common actor attribution or independent corroboration.
- **Observables:** deterministic extraction and refanging of addresses, domains, URLs, hashes, email addresses and CVEs. IOC-section, body-text and structured-feed occurrences retain their context. MISP warninglist matches are flagged, not deleted.
- **Analysis:** a model produces structured report analysis with attack steps, affected technologies, stated/inferred distinctions and supporting quotations. Code checks whether quotations occur in the source and whether technique IDs exist in the loaded ATT&CK catalogue. These checks do not prove that the source is true or that a technique mapping is semantically correct.
- **Relevance:** the same report is assessed against multiple environment profiles. KEV matching uses deterministic rules; narrative reports use structured model assessments with reasons and unknowns. Product presence is not evidence that an affected version is deployed.
- **Hunt preparation:** a relevant, huntable report can produce deterministic retrospective IOC sweeps and model-drafted behavioural KQL. Queries are checked against a configured table/column catalogue and each profile's available telemetry.
- **Delivery:** Markdown report briefs and profile digests, PEAK hunt packages, STIX output and an offline-capable static HTML dashboard.

### Indicator qualification and expiry

Malicious-activity STIX indicators require an unflagged explicit IOC-section or structured-feed occurrence. Body-only observations are retained for analysis, not automatically promoted to malicious indicators. Export confidence is an **uncalibrated source/context heuristic**, not a probability; repeated publishers do not earn a corroboration bonus.

Expiry policies run from the source-observation timestamp: IPs 30 days, domains/URLs 90 days, email addresses 180 days and hashes 365 days. These are configurable-in-code demo policies, not universal intelligence lifetimes. Generated bundles use the `stix2` library's **TLP:WHITE** marking; this is not automatic TLP 2.0 classification or permission to redistribute restricted source material.

Warninglists are refreshed after seven days. Shared-indicator and shared-CVE clustering ignores values appearing in more than eight documents to limit common-infrastructure clusters.

### Why not just use Sentinel TI matching?

Sentinel already matches imported indicators against connected logs. This project does not replace that. STIX export is an integration boundary for native TI matching; the additional work is interpreting reporting, prioritising it per environment and preparing behavioural hunts.

The KQL IOC sweep is a separate, explicit retrospective search. Neither the sweep nor STIX export proves compromise, and neither is executed or uploaded automatically by this project.

## Hunting and intelligence methodology

| Concept | Job in this project |
|---|---|
| **PIRs** | State the questions the customer needs answered and guide relevance. |
| **PEAK Prepare** | Capture triggering intelligence, relevance, hypothesis, scope, evidence and required telemetry. |
| **PEAK Execute** | Supply queries, their limitations, possible benign explanations and investigation pivots. Execution remains **not run** until an analyst performs it. |
| **PEAK Act** | Retain visibility gaps and space for findings, detection proposals and recommendations. A prepared package is not a completed hunt. |
| **Knowledge throughout** | Keep source evidence and related-report context attached to the investigation. |
| **ATT&CK** | Describe reported behaviours using current technique identifiers; not an automatic coverage guarantee. |
| **Pyramid of Pain** | Distinguish searches for hashes/IPs/domains from artefacts, tools and TTPs. Both can be useful; changing indicators does not necessarily change the behaviour. |
| **STIX 2.1** | Export qualified indicators and related intelligence in a standard format. |

Only hypothesis-driven hunting is implemented. Baseline and model-assisted telemetry hunts are different workflows, not labels for “we used an LLM.”

References: [PEAK](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html), [Pyramid of Pain](https://www.sans.org/tools/the-pyramid-of-pain), [FIRST's PIR guidance](https://www.first.org/global/sigs/cti/curriculum/pir), [ATT&CK](https://attack.mitre.org/), [Sentinel STIX upload API](https://learn.microsoft.com/en-us/azure/sentinel/stix-objects-api).

## Quick start

Requires Python 3.12+, [uv](https://docs.astral.sh/uv/), and, for model analysis, the [Codex CLI](https://developers.openai.com/codex/cli/) authenticated with an eligible ChatGPT subscription. Subscription usage limits apply; ChatGPT billing does not include API credits.

```bash
git clone https://github.com/jackbaillie/ti-pipeline.git
cd ti-pipeline
uv sync --frozen
codex login
uv run ti-pipeline init
uv run ti-pipeline run --limit 3
uv run ti-pipeline status
```

The configured model is **`gpt-6.1-sol`**, at **medium** reasoning for report analysis/relevance and **high** for hunt drafting. Change runtime settings in `config/settings.yaml`. There is no silent model fallback.

The initial lookback is 14 days for feeds and 30 days for KEV additions. A valid but infrequently updated feed may contribute no recent documents. Model work is capped per stage/run; remaining reports stay available for subsequent runs.

### Optional ThreatFox key

Register for an Auth-Key at [auth.abuse.ch](https://auth.abuse.ch/), then export `THREATFOX_AUTH_KEY` or put it in the ignored `.env` file:

```dotenv
THREATFOX_AUTH_KEY=your-key
```

Without a key, ThreatFox is visibly skipped; other sources continue. Follow source terms, licensing and sharing restrictions before redistributing intelligence or using community feeds commercially.

### Commands

```bash
# Collection and rule-based outputs without model calls
uv run ti-pipeline run --no-llm

# Selected stages in pipeline order
uv run ti-pipeline run --stages collect,process,extract,cluster --no-llm

# Submit a report URL, then process pending work
uv run ti-pipeline submit 'https://example.org/threat-report'

# Re-render outputs from stored intelligence
uv run ti-pipeline run --stages report,dashboard --no-llm

# All deterministic tests; no paid model calls
uv run pytest
```

Open `output/dashboard/index.html` directly, or serve the generated site locally:

```bash
python -m http.server 8000 --bind 127.0.0.1 --directory output/dashboard
```

The dashboard is regenerated output, not an always-running application. It does not provide user accounts, live query execution or a feedback editor.

## Customer profiles

Profiles in `config/profiles/` are **fictional demonstrations**, not real customer data:

- **UK law firm:** client confidentiality, sensitive documents, identity compromise and payment diversion.
- **UK retail bank:** financial-sector threats, payments, identity and internet-facing infrastructure.
- **UK manufacturer with OT:** ransomware, remote access and production continuity, with intentionally incomplete OT visibility.

Each profile contains technologies, exposure descriptions, crown jewels, available telemetry, retention and PIRs. Add another YAML file conforming to the same structure to add a profile.

Schemas in `config/schemas/tables.yaml` describe the intended Sentinel/Defender telemetry. They are configured assumptions, **not discovery of a live workspace**. The queries target a Sentinel workspace with the corresponding data connectors; standalone Defender advanced hunting can require schema/time-column adjustments.

## Outputs and storage

| Path | Contents |
|---|---|
| `data/ti.db` | SQLite intelligence, source fetches, versions, analysis, relevance, hunts and run history. |
| `data/cache/` | ATT&CK catalogue and warninglist downloads. |
| `data/logs/` | Local execution logs. |
| `output/reports/` | Report briefs and per-profile digests. |
| `output/hunts/` | PEAK packages and queries. |
| `output/stix/` | STIX bundles and Sentinel upload payloads. |
| `output/dashboard/` | Static analyst dashboard. |

Runtime data, outputs, credentials and local working documentation are not versioned. Selected examples may be published separately with source attribution; full source articles should not be republished indiscriminately.

## Twice-daily schedule

On Linux with systemd user services:

```bash
./deploy/install-timer.sh
systemctl --user list-timers ti-pipeline.timer
journalctl --user -u ti-pipeline.service
```

The timer runs at **08:00 and 20:00 Europe/London**, including daylight-saving changes. Persistent timers catch up a missed run when the user service manager starts. For unattended operation, enable user lingering if it is not already enabled: `loginctl enable-linger "$USER"`.

The supplied service expects `uv` and `codex` on the user's `~/.local/bin` path; adjust the unit for other installations. A process lock prevents an overlapping manual and scheduled run.

To stop scheduled processing:

```bash
systemctl --user disable --now ti-pipeline.timer
```

## Boundaries

- **Schema-checked is not executed or validated detection logic.** KQL checking is heuristic and cannot establish syntax, runtime success, detection recall or false-positive rates.
- **An observable is not automatically malicious.** Body-text mentions stay distinguishable from explicit IOC sections and structured feeds. Warninglist matches do not prove benignness either.
- **No live Azure actions:** no workspace creation, STIX uploads, searches, rule deployment or response actions. These are potential integrations, not completed features.
- **No fabricated hunt findings:** Execute remains not run and Act remains pending. Missing telemetry is recorded as a gap, not as a clean search result.
- **No X connector yet:** the initial automated collection is RSS/Atom and structured feeds.
- **No adaptive learning or autonomous investigation loop:** saved analysis/history provides traceability, not an automatically trained model.
- **No production accuracy claims:** this project has deterministic tests and real-source demonstrations, but not a measured detection benchmark against malicious and benign telemetry.
- **Untrusted inputs:** report analysis runs with Codex user configuration ignored, shell execution, web search, image tools, subagents and hooks disabled, plus a read-only ephemeral work directory. Public source text is sent to the configured model provider. These restrictions reduce tool-access risk; they do not make model conclusions trustworthy.

Possible extensions include analyst-approved read-only Sentinel execution, STIX upload, explicit analyst feedback and evaluation against known telemetry (for example, the workflow studied by [CTI-REALM](https://www.microsoft.com/en-us/security/blog/2026/03/20/cti-realm-a-new-benchmark-for-end-to-end-detection-rule-generation-with-ai-agents/)). These do not change the separation between observed evidence, generated proposals and analyst conclusions.

## Licence

Code: MIT. Source reports and third-party intelligence retain their original licensing and handling requirements. ATT&CK and MISP warninglists are credited to their respective maintainers.
