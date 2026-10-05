# Real-source example: phishing and remote-management tooling

These are generated outputs from a local run on **2026-10-05**, not handwritten successful hunt findings. Customer environments are fictional; the research source is public. Model: `gpt-6.1-sol` with medium reasoning for analysis/relevance and high for hunt drafting.

Source: Microsoft Threat Intelligence, [Phishing Abuses RMM Tools for Persistent Access](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/).

## Follow the investigation

1. [Report analysis](reports/documents/73.md): source evidence, attack steps, ATT&CK mappings, observables and three customer relevance assessments.
2. Compare the PEAK hunt packages:
   - [Law firm](hunts/law-firm/3-rmm-access-followed-by-secondary-remote-tooling.md)
   - [Retail bank](hunts/retail-bank/2-rmm-access-followed-by-secondary-remote-tooling.md)
   - [Manufacturer with OT](hunts/manufacturer-ot/1-rmm-access-followed-by-secondary-remote-tooling.md)
3. Each package has a sibling `.yaml` file containing the structured package and queries.
4. [STIX bundle](stix/documents/73.json): source-qualified indicators and related entities. This file has not been uploaded to Sentinel.

The same report has different investigative consequences. The law-firm package retains a service-installation query but flags it **invalid for that environment** because `SecurityEvent` is not available; its Act section records the visibility gap. The manufacturer profile lacks email and OT monitoring. The bank has broader telemetry, but that does not establish that it was targeted or compromised.

Every Execute section remains **not run** and every Act outcome remains **pending**. Model-written KQL is a reviewable draft. Schema checks do not prove runtime validity, useful detection logic, or the absence of false positives.

## Demonstrated locally

- `uv run ti-pipeline run --limit 1` completed all ten stages successfully after earlier collection/analysis runs.
- Corpus snapshot: 181 collected documents, 4 model-analysed reports, 5 prepared hunt packages and 28 stored queries across three profiles. The rest of the corpus is not implied to have received model analysis.
- Across the four analyses, all 114 supporting quotations were found in their source text and all returned technique IDs were valid in the loaded ATT&CK catalogue. This is source-occurrence/identifier validation, not an accuracy benchmark.
- 16 sources fetched successfully; optional ThreatFox was skipped because no Auth-Key was configured.
- `uv run pytest -q`: 169 tests passed.
- Static dashboard checked in Chromium on desktop and at 390px, including navigation, IOC filtering, KQL copying and missing-telemetry display.

![Dashboard showing terminal run health and corpus counts](dashboard.png)

The snapshot is a selected example, not the whole runtime database. No private customer data or workspace credentials are included. Refer to the source publication for the original reporting; its content retains its original rights.
