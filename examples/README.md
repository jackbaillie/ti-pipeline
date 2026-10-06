# Worked example: phishing and remote-management tools

Source: Microsoft Threat Intelligence, [Phishing Abuses RMM Tools for Persistent Access](https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/), 29 September 2026. These outputs were regenerated on 6 October 2026. All three customers are fictional.

## Start with the report

The [report analysis](reports/documents/73.md) contains the attack steps, source quotations, ATT&CK mappings, indicators and each customer's relevance assessment. The reported sequence involves MSP360 deploying ScreenConnect through PowerShell, followed by persistence and transferred utilities.

The customers do not automatically receive the same hunt:

| Customer | Assessment and result |
|---|---|
| Chiles & Associates | Low relevance. Windows endpoints and confidential documents make the report worth retaining, but it does not directly answer the firm's legal-sector, edge-exploitation, payment-fraud or cloud-identity priorities. No hunt is generated. |
| Vandelay Industries | Medium relevance. RMM abuse directly answers its third-party remote-access priority. The hunt examines deployment, persistence, transferred utilities and both agents' connections. |
| JLB Credit | Medium relevance. Credential-access tooling behind remote-management software is relevant to its identity priorities. The hunt correlates downloads, candidate utility execution and network activity. |

## Generated hunts

- [Vandelay: persistent MSP360 and ScreenConnect access](hunts/manufacturer-ot/16-persistent-msp360-and-screenconnect-access-at-vandelay.md)
- [JLB Credit: credential-access tooling delivered through RMM](hunts/retail-bank/36-jlb-credit-credential-access-tooling-delivered-through-rmm.md)

Each Markdown file has a YAML sibling containing the structured package. Behavioural queries are drafted separately for the customer; retrospective IOC sweeps come from templates. Lookbacks default to 30 days. These are draft searches, not completed investigations.

The [STIX bundle](stix/documents/73.json) contains the source-qualified indicators and related entities selected for export.

## What this demonstrates

A relevance decision can produce different hunts or no hunt. Customers are described by their business and technologies rather than an assumed log-table inventory. The indicator policy keeps IOC-section evidence separate from optional scraped mentions and benign flags.

The separate NetScaler demonstration on the running dashboard uses appliance logs in `CommonSecurityLog` and `Syslog`, with pivots to downstream endpoint connections and Entra sign-ins.

![Dashboard with grouped intelligence stories, customer priorities and ATT&CK trends](dashboard.png)

The source article belongs to Microsoft. Refer to it for the original reporting.
