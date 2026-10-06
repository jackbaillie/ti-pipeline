# ti-pipeline

I built this to practise turning threat reporting into something a SOC can investigate. It reads public research and advisories, groups related reports, and asks what matters to each customer before drafting a hunt.

The examples use three fictional organisations: Chiles & Associates, JLB Credit and Vandelay Industries. Their profiles describe the business, important systems, technologies and intelligence priorities. There is no assumed inventory of their log tables.

![Threat intelligence overview](examples/dashboard.png)

## From a report to a hunt

```text
Public feeds and CISA KEV
  → collect, version and deduplicate reports
  → extract indicators and flag likely benign references
  → group related reporting into stories
  → analyse behaviours with source quotes and ATT&CK mappings
  → assess relevance to each customer and their priorities
  → draft customer-specific KQL hunts
  → dashboard, Markdown briefs and STIX
```

The overview leads with relevant stories, sorted by score. Several Citrix reports and KEV entries appear together rather than taking up separate rows for the same customer. Patch bulletins stay low priority; exploited vulnerabilities have their own KEV entries. Weekly roundups cannot merge unrelated stories.

Hunts are written separately for each customer, using the reason the report mattered to them. For example, a NetScaler item relevant to a law firm's remote access should produce appliance-log searches, rather than unrelated Windows queries from elsewhere in the same bulletin. The [worked example](examples/README.md) follows one report through all three customers.

The Hunts page groups work by priorities such as identity theft, edge-device exploitation and remote-access abuse. ATT&CK offers a trending list and an expandable tactic → technique → reports view.

## Manual investigations

The dashboard's Investigate page accepts a report URL, CVE, ATT&CK technique or a hypothesis such as “Entra session-token theft following phishing”. Choose a customer or leave it unscoped.

It searches the collected corpus, groups the matching reports and gathers indicators and techniques. A supplied URL is fetched and analysed. It then drafts KQL from that evidence. Results are saved so they can be revisited; the page shows progress while a job is running.

This searches the feeds already collected, not the whole web. An empty result stays empty.

## Keeping the output useful

- IOC sections and structured feeds supply the default indicator list. Scraped body mentions are optional. MISP warninglists, an editable allowlist and publisher-domain checks flag likely benign references. Shared hosting is handled separately so an attacker-controlled tenant is not trusted just because its provider is popular.
- Analysis quotes are checked against the source text, and technique IDs against the current ATT&CK catalogue.
- KQL is checked against a Sentinel/Defender table catalogue. Failed checks get one repair attempt; queries still failing are omitted. This does not replace testing the query in a workspace. No query is executed by the project.
- Public reports are untrusted input. Model calls have tools disabled and run in a read-only sandbox. The URL importer rejects private destinations, including redirects to them.

The implementation is Python with SQLite. Each stage is a module under `src/tipipeline/`. [Design notes](docs/design-notes.md) explain the scoring, clustering and model boundary.

## Run it

Requires Python 3.12+, [uv](https://docs.astral.sh/uv/) and the [Codex CLI](https://developers.openai.com/codex/cli/) signed in for model calls. I use my existing ChatGPT subscription; the backend is isolated in `llm.py`.

```bash
uv sync --frozen
codex login
uv run ti-pipeline init
uv run ti-pipeline run --limit 3
uv run ti-pipeline serve
```

Open **http://127.0.0.1:8765/dashboard/**. The server runs manual investigations one at a time. Generated pages can also be opened from `output/` without a server, but the form needs `serve`.

```bash
uv run ti-pipeline investigate T1539 --customer law-firm
uv run ti-pipeline investigate 'Entra token theft' --include-scraped
uv run ti-pipeline run --no-llm
uv run ti-pipeline status
uv run pytest
```

Settings live in `config/settings.yaml`; profiles, priorities and the allowlist are beside it. `./deploy/install-timer.sh` installs the 08:00/20:00 Europe/London schedule. Optional ThreatFox collection needs `THREATFOX_AUTH_KEY`.

## Next

Run the queries against known attack and benign telemetry in Sentinel, and record analyst feedback on the relevance ranking. At present the project demonstrates preparation, not measured detection performance.

Code is MIT. Source reporting, ATT&CK and MISP warninglists retain their publishers' terms.
