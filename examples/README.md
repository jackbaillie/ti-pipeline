# Worked example: phishing that installs remote management tools

Source: Microsoft Threat Intelligence, [Phishing Abuses RMM Tools for Persistent Access](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/), 29 September 2026. The pipeline processed it on 5 October 2026. The three customers are fictional.

## Files

1. [Report analysis](reports/documents/73.md): attack steps with source quotes, ATT&CK mappings, extracted indicators and a relevance assessment for each customer.
2. Hunt packages, one per customer. Each Markdown file has a YAML sibling with the same package as structured data.
   - [Calloway Fenwick, law firm](hunts/law-firm/3-rmm-access-followed-by-secondary-remote-tooling.md)
   - [Thamesmere Bank](hunts/retail-bank/2-rmm-access-followed-by-secondary-remote-tooling.md)
   - [Brackwell Precision Engineering, manufacturer with OT](hunts/manufacturer-ot/1-rmm-access-followed-by-secondary-remote-tooling.md)
3. [STIX bundle](stix/documents/73.json): the indicators from this report that qualified for export.

## What to compare

All three packages test the same hypothesis: MSP360 launches PowerShell, which silently installs ScreenConnect, followed by new services and tools run through ScreenConnect. They share three behavioural queries and the IOC sweeps. What differs is what each customer can actually search and why it matters to them.

- Law firm: it doesn't collect `SecurityEvent`, so the service-installation query is marked invalid and the Act section records the visibility gap. No PIR matched; the hunt is still medium priority because the lures could reach fee earners and the access would expose client files.
- Manufacturer: matches its PIR on third-party remote access tools. The behavioural window is 30 days because that is its retention, and the package notes that IT logs say nothing about the OT network.
- Bank: matches its identity-attack PIR. A year of retention gives a 365-day behavioural window, and the domain sweep also covers `DnsEvents`.

None of these queries has been run against a workspace.

## First-run numbers

The first full run on 5 October collected 181 documents, analysed 4 reports with the model and prepared 5 hunt packages with 28 queries. All 114 supporting quotes were found in their sources, and every returned technique ID was valid in the current ATT&CK catalogue.

![Dashboard overview showing customers, ready hunts and high-priority intelligence](dashboard.png)

The source article belongs to Microsoft. Read the original for the full reporting.
