# Design notes

The detail behind the README, for anyone reading the code.

## Documents and versions

Each item is stored under a canonical URL with a hash of its extracted text. If the text changes, the document gets a new version. Extraction, analysis, relevance and hunts each record the version they processed, so only changed reports are reworked.

Near-duplicates are found by comparing five-word shingles across the last 30 days of articles and advisories. A Jaccard score of 0.60 or more counts as a duplicate. Between 0.40 and 0.60 the headlines must also be at least 0.75 similar, which catches lightly edited syndication without merging separate coverage of the same campaign. Shingles that appear in many documents (newsletter boilerplate) are ignored. A duplicate is not treated as independent corroboration.

## Clustering

Reports are linked when they share an indicator or a CVE. Values that appear in more than eight documents are ignored, because shared hosting or a widely reported CVE would otherwise join unrelated reports. A link means shared evidence, not the same actor.

## Indicators

Extraction refangs common defanging (`hxxp://`, `[.]`, `[at]`) and records where each value was found: an IOC section, the body text, a structured feed or metadata. MISP warninglists are refreshed weekly and matches are flagged, not deleted.

The two outputs use different bars:

- IOC sweep queries use every unflagged IP, domain, URL and hash from the report, including body mentions, capped at 200 values per type. A retrospective search is cheap to review.
- STIX indicators are only created from unflagged IOC-section or feed observations, because they feed matching and blocking. They expire after a fixed time from the last sighting: IPs 30 days, domains and URLs 90, email addresses 180, hashes 365. Confidence comes from the source tier (government 85, research 80, IOC feed 65, news 50). It is a starting heuristic, not a measured value. STIX IDs are stable, so re-exporting updates objects instead of duplicating them.

Sentinel's threat intelligence analytics already match imported indicators against new logs. The IOC sweep here is a separate look back over the last 30 days (or less if the customer keeps less), and the STIX bundle is the hand-off point for native matching. Behavioural queries use the customer's full retention.

## Relevance

KEV entries are matched deterministically: the KEV vendor and product against each profile's technology list, using a small alias table for renamed products. A match on an internet-facing product, or one with known ransomware use, is high priority; otherwise medium.

Narrative reports are assessed by the model for all customers in one call, against each profile's technologies, crown jewels and PIRs, with reasons and unknowns. Rule-based signals (product matches, sector, region, PIR keywords, KEV CVEs for a matched product) are passed in as hints. If the model leaves a customer out, the same rules produce that customer's assessment. If the call fails, nothing is stored and the report is retried next run.

Scores run from 0 to 100 and sort the review queue. They are not probabilities.

## Hunt packages

Packages follow PEAK's hypothesis-driven flow:

- Prepare: trigger report, priority and rationale, matched PIRs, hypothesis, scope, ATT&CK techniques, Pyramid of Pain levels, required telemetry and source quotes.
- Execute: the queries, each with benign explanations and pivots. Status stays "not run" until an analyst runs them.
- Act: findings, gaps, recommendations and detection ideas. Missing telemetry is recorded here as a gap.
- Knowledge: anything to carry into later hunts.

There are two kinds of query. IOC sweeps (IP, domain, URL, hash) are built from templates for whichever tables the customer collects. Behavioural queries are drafted by the model from the report's attack steps, once per report, and then validated separately for each customer.

Validation compares the tables and columns a query appears to use with `config/schemas/tables.yaml` and the customer's available tables. A query that needs a table the customer doesn't collect is marked invalid and listed as a gap. This is a lookup, not a KQL parser, so syntax and logic still need checking in a real workspace.

## Model calls

Calls go through `codex exec` with `gpt-6.1-sol`: medium reasoning for analysis and relevance, high for hunt drafting. Each call gets a JSON schema, and the response is validated with Pydantic. A failed call is retried once, then recorded as an error and shown in the run status.

Report text is untrusted. The prompt marks it as data, and the Codex CLI runs with user config ignored, shell and exec tools disabled, web search, image viewing, sub-agents and hooks off, and a read-only sandbox in an empty temporary directory. That limits what a malicious report could make the model do. It doesn't make the model's reading of a report correct, which is why the quote and ATT&CK checks exist.

Each model stage handles a capped number of documents per run, highest priority first. The rest wait for the next run.

## Scheduling and failure handling

A systemd user timer runs the pipeline at 08:00 and 20:00 Europe/London and catches up a missed run after downtime. A lock file stops two runs overlapping. One failing source or document doesn't stop the run, but the run is marked partial and the CLI exits non-zero.

## Known gaps

- No query has been run against a live workspace, so detection quality is unmeasured.
- Relevance scores and indicator lifetimes are uncalibrated.
- Collection is RSS/Atom, KEV and ThreatFox only.
- There is no analyst feedback loop yet.
