# RMM access followed by secondary remote tooling

Profile: **Thamesmere Bank plc** · hunt #2 · status: **prepared**

Framework: PEAK · hypothesis-driven. Queries are prepared, not executed. Schema checks are not KQL syntax or semantic guarantees.

## Prepare

### Trigger

[Phishing Abuses RMM Tools for Persistent Access](../../reports/documents/73.md)

<https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access/>

Source: microsoft\_ti · published: 2026-09-29 22:39 BST

Priority: **Medium**

Persistent Windows remote access and follow-on credential-access utilities warrant a SOC hunt because stolen credentials could threaten privileged identities and sensitive banking data. The report partially informs RB-PIR-4 through credential-access activity, including browser-password utilities, but does not demonstrate AD/Entra compromise, MFA bypass or privileged-account theft. It establishes no financial-sector or UK targeting, payment-system attack, edge-device exploitation, or supplier compromise; legitimate RMM abuse alone does not substantiate a supply-chain attack.

### Matched PIRs

- `RB-PIR-4` — Which identity attacks against Active Directory, Entra ID and privileged access (credential theft, MFA bypass, help-desk social engineering, token theft) are in use?

### Hypothesis

Windows endpoints show MSP360 launching PowerShell to retrieve and silently install ScreenConnect, followed by persistent services and execution of utilities through ScreenConnect.

### Scope

Windows endpoints within the configured lookback. Process queries use streamed endpoint telemetry; the service query requires SecurityEvent 4697 with populated service fields. Compare matches with approved remote-support deployments. Execution: not\_run; syntax and runtime behavior remain unverified. Environment: Thamesmere Bank plc; behavioural window 365 days; IOC sweep window 30 days.

### Techniques

| ID | Official name | Tactic |
| --- | --- | --- |
| `T1566.002` | Spearphishing Link | Initial Access |
| `T1036` | Masquerading | Stealth |
| `T1204.002` | Malicious File | Execution |
| `T1548.004` | Elevated Execution with Prompt | Privilege Escalation |
| `T1059.003` | Windows Command Shell | Execution |
| `T1518` | Software Discovery | Discovery |
| `T1543.003` | Windows Service | Persistence |
| `T1547.001` | Registry Run Keys / Startup Folder | Persistence |
| `T1686.003` | Windows Host Firewall | Defense Impairment |
| `T1219` | Remote Access Tools | Command And Control |
| `T1059.001` | PowerShell | Execution |
| `T1105` | Ingress Tool Transfer | Command And Control |
| `T1071.001` | Web Protocols | Command And Control |
| `T1573` | Encrypted Channel | Command And Control |
| `T1102` | Web Service | Command And Control |
| `T1218.007` | Msiexec | Stealth |
| `T1112` | Modify Registry | Persistence |
| `T1036.005` | Match Legitimate Resource Name or Location | Stealth |
| `T1072` | Software Deployment Tools | Execution |
| `T1005` | Data from Local System | Collection |

### Pyramid of Pain

- Network/host artefacts (annoying)
- Tools (challenging)
- TTPs (tough)
- Domain names (simple)
- Hash values (trivial for the adversary to change)

### Telemetry

| Required tables | Available | Missing |
| --- | --- | --- |
| CommonSecurityLog, DeviceFileEvents, DeviceImageLoadEvents, DeviceNetworkEvents, DeviceProcessEvents, DnsEvents, EmailAttachmentInfo, EmailUrlInfo, SecurityEvent, UrlClickEvents | CommonSecurityLog, DeviceFileEvents, DeviceImageLoadEvents, DeviceNetworkEvents, DeviceProcessEvents, DnsEvents, EmailAttachmentInfo, EmailUrlInfo, SecurityEvent, UrlClickEvents | None recorded |

### Evidence

| Quote | Verification |
| --- | --- |
| Phishing emails directed users to actor-controlled landing pages that impersonated document-sharing portals, invitation workflows, Adobe Reader download pages, Zoom installation pages, and business collaboration platforms. | verified |
| The downloaded executables used filenames crafted to resemble legitimate business content, meeting invitations, PDF documents, and software installers. | verified |
| After victims downloaded and executed the masqueraded MSP360 installer, the binary launched from the user’s Downloads directory under a filename designed to resemble a legitimate business document. | verified |
| In observed successful installations, the process continued with elevated privileges, allowing deployment of MSP360 components and services. | verified |
| Installation workflows used cmd.exe for logging, prerequisite checks, file management, and installation-related tasks. | verified |
| The installer also performed prerequisite discovery by enumerating installed .NET runtimes using: dotnet –list-runtimes. | verified |
| MSP360 and ScreenConnect were installed as Windows services to establish persistent access. | verified |
| MSP360 created registry Run entries to automatically launch tray application components at user logon. | verified |
| The installation routine also modified the Windows Firewall configuration by creating an inbound allow rule for the MSP360 agent. | verified |
| The combination of MSP360 and ScreenConnect provided the threat actor with redundant remote administration channels and enabled the transfer, execution, and management of additional tooling during subsequent stages of the intrusion. | verified |
| Following successful installation of MSP360 RMM, the newly installed RMM.Agent.exe service launched PowerShell. | verified |
| MSP360 downloaded ScreenConnect, while the threat actor’s use of ScreenConnect was subsequently used to transfer and execute additional tooling on compromised endpoints. | verified |
| PowerShell and ScreenConnect communicated with actor-controlled infrastructure over HTTP/HTTPS. | verified |
| Payload retrieval and remote access communications occurred over encrypted network channels. | verified |
| Multiple cloud-hosted web services were used throughout the delivery and command-and-control infrastructure. | verified |
| The downloaded ClientSetup.msi package was installed silently using msiexec.exe /qn. | verified |
| MSP360 and ScreenConnect modified registry locations associated with services, persistence, credential provider components, protocol handlers, and uninstall entries. | verified |
| Several filenames were intentionally chosen to resemble legitimate Windows, Microsoft Defender, Phone Link, and security-related components, likely to reduce user suspicion and blend into normal operating system activity. | verified |
| The execution of these files occurred through ScreenConnect’s built-in RunFile functionality, which allows files to be transferred to and executed on managed endpoints. | verified |
| Additional tooling delivered through ScreenConnect was observed in post-compromise activity and used to collect information from victim devices. | verified |

## Execute

Status: **not run**

### MSP360 PowerShell retrieval followed by silent MSI installation

Test the observed RMM.Agent.exe → PowerShell retrieval and silent ClientSetup.msi installation sequence. Direct PowerShell parentage of msiexec and the 30-minute correlation window are hunt inferences; indirect installation chains will be missed.

Kind: behavioural · generated by: llm · validation: **schema\_valid**

Tables: DeviceProcessEvents · techniques: T1059.001, T1105, T1218.007

- Schema check only: not parsed or executed against Sentinel; syntax, types and data coverage are unverified.

```kusto
let lookback = 365d;
let downloads = DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where ActionType == "ProcessCreated"
| where FileName =~ "powershell.exe"
| where InitiatingProcessFileName =~ "RMM.Agent.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| where isnotempty(ProcessUniqueId)
| project TenantId, DeviceId, PowerShellUniqueId = ProcessUniqueId, DownloadTime = TimeGenerated, PowerShellCommand = ProcessCommandLine, RmmCommand = InitiatingProcessCommandLine;
DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where ActionType == "ProcessCreated"
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine contains "ClientSetup.msi" and ProcessCommandLine contains "/qn"
| where isnotempty(InitiatingProcessUniqueId)
| project TenantId, DeviceId, DeviceName, InstallTime = TimeGenerated, InstallerParentUniqueId = InitiatingProcessUniqueId, InstallerUniqueId = ProcessUniqueId, InstallerCommand = ProcessCommandLine, AccountDomain, AccountName
| join kind=inner downloads on TenantId, DeviceId, $left.InstallerParentUniqueId == $right.PowerShellUniqueId
| where InstallTime >= DownloadTime and InstallTime <= DownloadTime + 30m
| project DownloadTime, InstallTime, DeviceId, DeviceName, AccountDomain, AccountName, PowerShellUniqueId, InstallerUniqueId, RmmCommand, PowerShellCommand, InstallerCommand
```

Benign explanations:
- An authorized MSP deploys ScreenConnect through MSP360.
- IT migrates remote-support platforms or installs a backup support channel.

Pivots:
- Retrieve the complete process tree using DeviceId and the returned process unique IDs, including intervening shells.
- Inspect file and network events attributed to the PowerShell process for the downloaded package and its origin.
- Check deployment tickets, package signatures, and ScreenConnect tenant ownership.

### ScreenConnect execution from its user-profile transfer directory

Test the observed execution of transferred executables from Documents\\ScreenConnect\\Temp through ScreenConnect.WindowsClient.exe. Matching a grandparent process is an inference to accommodate an intervening launcher; execution alone does not establish collection or credential theft.

Kind: behavioural · generated by: llm · validation: **schema\_valid**

Tables: DeviceProcessEvents · techniques: T1072, T1219

- Schema check only: not parsed or executed against Sentinel; syntax, types and data coverage are unverified.

```kusto
let lookback = 365d;
DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where ActionType == "ProcessCreated"
| where FolderPath contains "\\Documents\\ScreenConnect\\Temp\\"
| where FileName endswith ".exe"
| where InitiatingProcessFileName =~ "ScreenConnect.WindowsClient.exe" or InitiatingProcessParentFileName =~ "ScreenConnect.WindowsClient.exe"
| project TimeGenerated, DeviceId, DeviceName, AccountDomain, AccountName, FileName, FolderPath, ProcessCommandLine, ProcessUniqueId, InitiatingProcessUniqueId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

Benign explanations:
- A support technician transfers and runs an approved diagnostic utility.
- ScreenConnect RunFile performs an authorized software deployment.

Pivots:
- Correlate DeviceFileEvents on DeviceId and executable path to inspect file creation and its initiating process.
- Review the returned process tree and subsequent file activity for information collection.
- Review ScreenConnect session and RunFile audit records for the operator and authorization.

### MSP360 and ScreenConnect service installations on one host

Test the observed installation of both remote-access products as Windows services. Ordering ScreenConnect after MSP360 within 24 hours is an inferred triage window; host correlation does not establish a common operator or malicious intent. Requires service-installation auditing.

Kind: behavioural · generated by: llm · validation: **schema\_valid**

Tables: SecurityEvent · techniques: T1219, T1543.003

- Schema check only: not parsed or executed against Sentinel; syntax, types and data coverage are unverified.

```kusto
let lookback = 365d;
let installs = SecurityEvent
| where TimeGenerated >= ago(lookback)
| where EventID == 4697
| where isnotempty(Computer)
| project TenantId, Computer, InstallTime = TimeGenerated, ServiceName, ServiceFileName, ServiceAccount, SubjectUserName, SubjectLogonId;
let rmmInstalls = installs
| where ServiceFileName contains "RMM.Agent.exe" or ServiceFileName contains "RMM.Agent.Launcher.exe"
| project TenantId, Computer, RmmInstallTime = InstallTime, RmmServiceName = ServiceName, RmmServiceFile = ServiceFileName, RmmServiceAccount = ServiceAccount, RmmInstallerUser = SubjectUserName, RmmInstallerLogonId = SubjectLogonId;
installs
| where ServiceFileName contains "ScreenConnect.ClientService.exe"
| project TenantId, Computer, ScreenConnectInstallTime = InstallTime, ScreenConnectServiceName = ServiceName, ScreenConnectServiceFile = ServiceFileName, ScreenConnectServiceAccount = ServiceAccount, ScreenConnectInstallerUser = SubjectUserName, ScreenConnectInstallerLogonId = SubjectLogonId
| join kind=inner rmmInstalls on TenantId, Computer
| where ScreenConnectInstallTime >= RmmInstallTime and ScreenConnectInstallTime <= RmmInstallTime + 1d
| project Computer, RmmInstallTime, ScreenConnectInstallTime, RmmServiceName, RmmServiceFile, RmmServiceAccount, RmmInstallerUser, RmmInstallerLogonId, ScreenConnectServiceName, ScreenConnectServiceFile, ScreenConnectServiceAccount, ScreenConnectInstallerUser, ScreenConnectInstallerLogonId
```

Benign explanations:
- An approved support rollout installs both management and remote-control services.
- A migration temporarily retains two remote-access products.

Pivots:
- Review SecurityEvent process creation and logon records on Computer using installation times and the corresponding subject logon IDs.
- Check service binary signatures, installation provenance, and approved software inventory.
- Where endpoint telemetry exists, inspect MSP360 PowerShell children and ScreenConnect-launched utilities around these installation times.

### Retrospective domain IOC sweep

Check non-warninglisted domain indicators retrospectively over 30 days. Sentinel TI-map analytics already match ingested indicators; this is an explicit historical check, not a new detection. Includes 7 deduplicated IOCs.

Kind: ioc\_sweep · generated by: template · validation: **schema\_valid**

Tables: DeviceNetworkEvents, DnsEvents, EmailUrlInfo, UrlClickEvents, CommonSecurityLog · techniques: None recorded

- Schema check only: not parsed or executed against Sentinel; syntax, types and data coverage are unverified.

```kusto
let lookback = 30d;
let iocs = dynamic(["adsaw.cfd", "adswre.cfd", "bunstar.harej.si", "ojsuyw.niyari.org", "sdfghj.rd-team.ru", "swedcorry.stefneyv.com", "trews.cfd"]);
let ioc_terms = dynamic(["adsaw", "adswre", "bunstar", "ojsuyw", "sdfghj", "swedcorry", "trews"]);
union isfuzzy=true
(
DeviceNetworkEvents
| where TimeGenerated >= ago(lookback)
| where RemoteUrl has_any (ioc_terms)
| mv-apply MatchedIndicator = iocs to typeof(string) on (
    where (tostring(parse_url(iff(tolower(tostring(RemoteUrl)) contains "://", tolower(tostring(RemoteUrl)), strcat("https://", tolower(tostring(RemoteUrl))))).Host) == MatchedIndicator or tostring(parse_url(iff(tolower(tostring(RemoteUrl)) contains "://", tolower(tostring(RemoteUrl)), strcat("https://", tolower(tostring(RemoteUrl))))).Host) endswith strcat(".", MatchedIndicator))
)
| project TimeGenerated, SourceTable = "DeviceNetworkEvents", MatchedIndicator, Device = tostring(DeviceName), User = tostring(InitiatingProcessAccountUpn), IP = tostring(RemoteIP)
),
(
DnsEvents
| where TimeGenerated >= ago(lookback)
| where Name has_any (ioc_terms)
| mv-apply MatchedIndicator = iocs to typeof(string) on (
    where (tostring(parse_url(iff(tolower(tostring(Name)) contains "://", tolower(tostring(Name)), strcat("https://", tolower(tostring(Name))))).Host) == MatchedIndicator or tostring(parse_url(iff(tolower(tostring(Name)) contains "://", tolower(tostring(Name)), strcat("https://", tolower(tostring(Name))))).Host) endswith strcat(".", MatchedIndicator))
)
| project TimeGenerated, SourceTable = "DnsEvents", MatchedIndicator, Device = tostring(Computer), User = "", IP = tostring(ClientIP)
),
(
EmailUrlInfo
| where TimeGenerated >= ago(lookback)
| where UrlDomain has_any (ioc_terms)
| mv-apply MatchedIndicator = iocs to typeof(string) on (
    where (tostring(parse_url(iff(tolower(tostring(UrlDomain)) contains "://", tolower(tostring(UrlDomain)), strcat("https://", tolower(tostring(UrlDomain))))).Host) == MatchedIndicator or tostring(parse_url(iff(tolower(tostring(UrlDomain)) contains "://", tolower(tostring(UrlDomain)), strcat("https://", tolower(tostring(UrlDomain))))).Host) endswith strcat(".", MatchedIndicator))
)
| project TimeGenerated, SourceTable = "EmailUrlInfo", MatchedIndicator, Device = "", User = "", IP = ""
),
(
UrlClickEvents
| where TimeGenerated >= ago(lookback)
| where Url has_any (ioc_terms)
| mv-apply MatchedIndicator = iocs to typeof(string) on (
    where (tostring(parse_url(iff(tolower(tostring(Url)) contains "://", tolower(tostring(Url)), strcat("https://", tolower(tostring(Url))))).Host) == MatchedIndicator or tostring(parse_url(iff(tolower(tostring(Url)) contains "://", tolower(tostring(Url)), strcat("https://", tolower(tostring(Url))))).Host) endswith strcat(".", MatchedIndicator))
)
| project TimeGenerated, SourceTable = "UrlClickEvents", MatchedIndicator, Device = "", User = tostring(AccountUpn), IP = tostring(IPAddress)
),
(
CommonSecurityLog
| where TimeGenerated >= ago(lookback)
| where DestinationHostName has_any (ioc_terms) or RequestURL has_any (ioc_terms)
| mv-apply MatchedIndicator = iocs to typeof(string) on (
    where (tostring(parse_url(iff(tolower(tostring(DestinationHostName)) contains "://", tolower(tostring(DestinationHostName)), strcat("https://", tolower(tostring(DestinationHostName))))).Host) == MatchedIndicator or tostring(parse_url(iff(tolower(tostring(DestinationHostName)) contains "://", tolower(tostring(DestinationHostName)), strcat("https://", tolower(tostring(DestinationHostName))))).Host) endswith strcat(".", MatchedIndicator)) or (tostring(parse_url(iff(tolower(tostring(RequestURL)) contains "://", tolower(tostring(RequestURL)), strcat("https://", tolower(tostring(RequestURL))))).Host) == MatchedIndicator or tostring(parse_url(iff(tolower(tostring(RequestURL)) contains "://", tolower(tostring(RequestURL)), strcat("https://", tolower(tostring(RequestURL))))).Host) endswith strcat(".", MatchedIndicator))
)
| project TimeGenerated, SourceTable = "CommonSecurityLog", MatchedIndicator, Device = tostring(Computer), User = tostring(SourceUserName), IP = tostring(DestinationIP)
)
| order by TimeGenerated desc
```

Benign explanations:
- Shared or reassigned infrastructure, research activity, or authorised testing may explain a match; corroborate with the source and surrounding events.

Pivots:
- Pivot on the matched device/user/IP and nearby events.
- Confirm timing and IOC provenance before drawing a conclusion.

### Retrospective hash IOC sweep

Check non-warninglisted hash indicators retrospectively over 30 days. Sentinel TI-map analytics already match ingested indicators; this is an explicit historical check, not a new detection. Includes 31 deduplicated IOCs.

Kind: ioc\_sweep · generated by: template · validation: **schema\_valid**

Tables: DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents, EmailAttachmentInfo · techniques: None recorded

- Schema check only: not parsed or executed against Sentinel; syntax, types and data coverage are unverified.

```kusto
let lookback = 30d;
let iocs = dynamic(["02f2ce03a2650f17bfe6e8744eebbf58522016cbdb92af8f2217b5dd4a1ad550", "06ad69b9bebad3cc75b594cc5bb1ca0035ea22bb8a683002ca051d948566426b", "108ef7e628d7a20bd6241a5b57149e27a6061f467123eb64061975559f8f73dc", "19035c8e2520fb70b3e2ec5338c14311b88a26cc1fb8304a01494260b6b55af1", "1a534d04bf30894d20764e91f7e94e0a73f060f0abacc9feeedba427995c83a8", "374c4934b14a1151ea68847c8627c3f1c0b878f4e673bda3f15e4388dfde0187", "3ff5e49fd2f2bd0758467763c44d69e781b7460af84a6e3966e2621bc5bf7096", "40f8e774e1e7a484b78c7ae4336bc47aa9cab20dc8e1e67d89838e807975f9b1", "4188c6588f3dcda881c3f2d12df580051179a999f040b799af506edeb3211a26", "499d07894f730fb685ee3cbfc1a933e0da93750c1ed25a49b2eb9c32adef156a", "529543b4fe6a4c21d28be56dbf92fcac91d8df808d8518b4275c973fa547ad63", "5bf8cf29ac6803e7269b045dea48003af7cfe48bedfc081b57ff9e86cb08971b", "67c979dc13961b09f24f85a801e4c918420adca6117c92efbeeeaa68a6344f55", "6a89de024ca62536de6f5fc10e49896bb1ac330ca39dce30203afdcc45ae237e", "6cc665057c4a4fe42a309afd3a7fa96cf1af126e9c6e08e56df5105e05378bcc", "77fb0e75f4396cb57bbbd28f6dc5310369a87abec9e2acc457aa99a0063ed27a", "857c2f283de799faa74b56e862c0a9f96e67aa1b4fa4a9e46395098365b99de3", "a03c84ae9e569c04fdd271277f508bba5a299d53c3c0efe0819338d178fe1c5b", "a93c946c237b981189d2668d938a9d4d1d9681757e48dae8d9d65ed25b5da657", "bc8b1b0c80512ba0e8ffccfee5b507df16a3355db1143c3ba81ef42dac1baa6c", "c2c004a56de2a99f5b06ceb58d8a4b371fb60fd66ff5936786fe8d8037ead208", "ccea4e1acc51ac43ba9da76ada00e7e308cc33d9c5c264dff82d1be83e957b88", "ceb3f7fe9a618ff29a21b126383c23900fad58d6ae2b5552d7e306e4b6acf4b0", "d232d82e410de12702a67c58acf927304ee42f3e6d81a9d71eca99f9052126db", "d3cb7ded277b49be06e6a1860f7c7e913e252802e9d32453a185e24797bf53ef", "d49cc01641c3045bf3119f9d71e7ffd29bfce32ca4b27cc96340716ed4d41cdc", "dd434f3ffcafeda538d43226665115ba136ad0fdb43dad8536e1368ca9a17b64", "e31e5da7c58a7e8f89f9629f095edd7d741a1fb0b85fcb39f3818dbd9497b1e3", "f094b8263471c7b76dbed03d420736449920368fa0eca2ed6b1aea2645138d97", "f34330d4c6e0aa978dc3af40360c14b31ad51127", "fc96a04c615847f0fb1391f04d9d1aac7f78ddfb7d459168df0a4172b98354e2"]);
union isfuzzy=true
(
DeviceFileEvents
| where TimeGenerated >= ago(lookback)
| where SHA256 in~ (iocs) or SHA1 in~ (iocs) or MD5 in~ (iocs)
| extend MatchedIndicator = case(SHA256 in~ (iocs), tostring(SHA256), SHA1 in~ (iocs), tostring(SHA1), tostring(MD5))
| project TimeGenerated, SourceTable = "DeviceFileEvents", MatchedIndicator, Device = tostring(DeviceName), User = tostring(InitiatingProcessAccountUpn), IP = ""
),
(
DeviceProcessEvents
| where TimeGenerated >= ago(lookback)
| where SHA256 in~ (iocs) or SHA1 in~ (iocs) or MD5 in~ (iocs) or InitiatingProcessSHA256 in~ (iocs) or InitiatingProcessSHA1 in~ (iocs) or InitiatingProcessMD5 in~ (iocs)
| extend MatchedIndicator = case(SHA256 in~ (iocs), tostring(SHA256), SHA1 in~ (iocs), tostring(SHA1), MD5 in~ (iocs), tostring(MD5), InitiatingProcessSHA256 in~ (iocs), tostring(InitiatingProcessSHA256), InitiatingProcessSHA1 in~ (iocs), tostring(InitiatingProcessSHA1), tostring(InitiatingProcessMD5))
| project TimeGenerated, SourceTable = "DeviceProcessEvents", MatchedIndicator, Device = tostring(DeviceName), User = tostring(AccountUpn), IP = ""
),
(
DeviceImageLoadEvents
| where TimeGenerated >= ago(lookback)
| where SHA256 in~ (iocs) or SHA1 in~ (iocs) or MD5 in~ (iocs)
| extend MatchedIndicator = case(SHA256 in~ (iocs), tostring(SHA256), SHA1 in~ (iocs), tostring(SHA1), tostring(MD5))
| project TimeGenerated, SourceTable = "DeviceImageLoadEvents", MatchedIndicator, Device = tostring(DeviceName), User = tostring(InitiatingProcessAccountUpn), IP = ""
),
(
EmailAttachmentInfo
| where TimeGenerated >= ago(lookback)
| where SHA256 in~ (iocs)
| extend MatchedIndicator = tostring(SHA256)
| project TimeGenerated, SourceTable = "EmailAttachmentInfo", MatchedIndicator, Device = "", User = tostring(RecipientEmailAddress), IP = ""
)
| order by TimeGenerated desc
```

Benign explanations:
- Shared or reassigned infrastructure, research activity, or authorised testing may explain a match; corroborate with the source and surrounding events.

Pivots:
- Pivot on the matched device/user/IP and nearby events.
- Confirm timing and IOC provenance before drawing a conclusion.

## Act

Outcome: **pending** (no findings are implied before execution).

### Findings

None recorded.

### Gaps

None recorded.

### Future hunts

None recorded.

### Recommendations

None recorded.

### Detection proposals

None recorded.

## Knowledge

No additional knowledge recorded.
