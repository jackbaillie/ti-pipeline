# Design notes

The detail behind the README, for anyone reading the code.

## Documents and versions

Each item is stored under a canonical URL with a hash of its extracted text. If the text changes, the document gets a new version. Extraction, analysis, relevance and hunts each record the version they processed, so only changed reports are reworked.

Near-duplicates are found by comparing five-word shingles across the last 30 days of articles and advisories. A Jaccard score of 0.60 or more counts as a duplicate. Between 0.40 and 0.60 the headlines must also be at least 0.75 similar, which catches lightly edited syndication without merging separate coverage of the same campaign. Shingles that appear in many documents (newsletter boilerplate) are ignored. A duplicate is not treated as independent corroboration.

## Stories

Reports are linked when they share an unflagged indicator or a CVE, and linked reports form a story. KEV entries for the same vendor and product added within 30 days of each other join the same story, so three NetScaler KEV entries sit with the reports about them. Values that appear in more than eight documents are ignored, because shared hosting or a widely reported CVE would otherwise join unrelated reports. Weekly round-ups, newsletters and patch bulletins keep their links but never join a story: one digest mentions many unrelated items and would merge them all. A link means shared evidence, not the same actor.

## Indicators

Extraction refangs common defanging (`hxxp://`, `[.]`, `[at]`) and records where each value was found: an IOC section, the body text, a structured feed or metadata. Placeholders (`example.com`, `contoso.com`) and masked values (`5.xxx.xx.xxx`) are dropped. A file name such as `Documents.zip` counts as a domain only when defanged or part of a URL, and code such as `Mail.Read` only under an IOC heading.

Likely benign values are flagged, not deleted. The flag is the matching MISP warninglist (refreshed weekly), else `publisher` for a value on the reporting source's own domain, else `allowlist` for a domain in `config/allowlist.yaml`. Matching stops at the tenant: a warninglist entry for `pages.dev` or `blogspot.com` does not flag `my-site.pages.dev`, because each subdomain there belongs to whoever registered it.

IOC sweeps and STIX use unflagged observations from IOC sections or structured feeds by default. The dashboard and manual investigations can also show scraped body mentions. `hunt.include_scraped_iocs` enables those mentions in scheduled sweeps; it does not relax STIX qualification. Sweeps support IPs, domains, URLs and hashes, capped at 200 values per family.

STIX indicators expire from the latest qualifying source observation: IPs 30 days, domains and URLs 90, email addresses 180, hashes 365. Source-tier confidence values are heuristics, not measured probabilities. Stable IDs let exports update existing objects. The bundled TLP:WHITE marking does not override the publisher's redistribution terms.

Sentinel's native threat-intelligence analytics match imported indicators against logs. These sweeps are explicit retrospective searches. Both behavioural queries and sweeps use `hunt.lookback_days`, which defaults to 30.

## Relevance

KEV entries are matched deterministically: the KEV vendor and product against each profile's technology list, using a small alias table for renamed products. A match on an internet-facing product, or one with known ransomware use, is high priority; otherwise medium.

Narrative reports are assessed by the model for all customers in one call, against each profile's technologies, crown jewels and PIRs, with reasons and unknowns. Rule-based signals (product matches, sector, region, PIR keywords, KEV CVEs for a matched product) are passed in as hints. If the model leaves a customer out, the same rules produce that customer's assessment. If the call fails, nothing is stored and the report is retried next run.

Scores run from 0 to 100 and sort the review queue. They are not probabilities.

Customer PIRs reference the shared themes in `config/priorities.yaml`. Themes organise the display; the PIR question remains the reason to investigate. Profiles contain business context and technologies, not telemetry inventories.

Patch bulletins are capped at low priority even when they contain exploited CVEs, because those CVEs already have KEV entries. The rule applies to analyses typed `vulnerability` with at least ten distinct CVEs or a recognised patch-bulletin title. For a roundup, the relevance rationale names the particular item that matters to the customer.

## Hunt packages

Packages follow PEAK's hypothesis-driven flow:

- Prepare: source report, customer relevance, matched PIRs, hypothesis, scope, techniques and supporting quotes.
- Execute: behavioural queries and IOC sweeps, with benign explanations and investigation pivots.
- Act: recorded findings or follow-up actions; nothing is invented before execution.
- Knowledge: related reporting and earlier hunts.

There is one drafting call per relevant report/customer pair. The prompt receives the customer's business and technology context, the relevance rationale, verified analysis and the full Sentinel table catalogue. Appliance-focused hunts should use Syslog or CommonSecurityLog rather than assume endpoint agents run on the appliance.

Queries are checked for apparent table and column references. Failing queries get one repair call; any still failing are dropped. A pair with no surviving query is recorded as an error and remains eligible for retry. There is no customer-table availability check and no claim that a schema check proves executable KQL or useful detection logic.

## Model calls

Calls go through `codex exec` with `gpt-6.1-sol`: medium reasoning for analysis and relevance, high for hunt drafting. Each call gets a JSON schema, and the response is validated with Pydantic. A failed call is retried once, then recorded as an error and shown in the run status.

Report text is untrusted. The prompt marks it as data, and the Codex CLI runs with user config ignored, shell and exec tools disabled, web search, image viewing, sub-agents and hooks off, and a read-only sandbox in an empty temporary directory. That limits what a malicious report could make the model do. It doesn't make the model's reading of a report correct, which is why the quote and ATT&CK checks exist.

The configured cap applies independently to analysis documents, relevance documents and hunt report/customer pairs. Repairs and backend retries can add calls. Unfinished work waits for later runs.

## Scheduling and failure handling

A systemd user timer runs the pipeline at 08:00 and 20:00 Europe/London and catches up a missed run after downtime. A lock file stops two runs overlapping. One failing source or document doesn't stop the run, but the run is marked partial and the CLI exits non-zero.

## Manual investigations and serving

`ti-pipeline serve` serves `output/` and adds a live Investigate form. It binds to loopback by default; an operator can explicitly select the host's tailnet address. Extra browser hostnames must be listed with repeated `--hostname` options. Requests with an unrecognised host or cross-origin form submissions are rejected. There is no account system: devices permitted to reach the listener can submit model work. Keep it private.

The four input paths are:

- URL: fetch a public report, extract indicators and analyse it.
- CVE: find collected reports mentioning that CVE and any collected KEV entry.
- ATT&CK ID: find reports mapped to the technique, including sub-techniques for a parent ID.
- Hypothesis: extract search terms with the model, then rank matching corpus reports by term matches and recency.

Results group reports into stories and retain source titles and links. Indicator inclusion uses the same qualified/scraped distinction as scheduled hunts. Up to ten matched article/advisory reports get current analyses on demand; the result identifies which reports informed the draft. KEV-only or evidence-free matches do not produce a generic invented hunt. Drafting reuses the customer-hunt implementation.

Investigations persist as queued, running, done or error. One background worker processes them; live result pages refresh while pending. On restart, queued work resumes and interrupted running work becomes an error rather than silently repeating model calls. Evidence remains visible if hunt drafting fails, with the drafting error shown.

URL retrieval checks DNS results and every redirect, rejects non-public addresses, and connects to a checked address while retaining the original hostname for HTTP/TLS. This prevents a submitted report URL from turning the host into a private-network fetcher.

SQLite connections are per thread. URL collection, extraction and analysis wait for the scheduled pipeline lock to avoid overwriting observations from a different document version; the page shows that wait. Other lookups remain concurrent. Live pages read persisted investigation results instead of depending on a dashboard rebuild.

## Known gaps

- No query has been run against a live workspace, so detection quality is unmeasured.
- Relevance scores and indicator lifetimes are uncalibrated.
- Collection is RSS/Atom, KEV and ThreatFox only.
- There is no analyst feedback loop yet.
