"""Retrospective IOC sweeps, restricted to each customer's collected tables."""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass

from tipipeline.models import DraftQuery, Profile
from tipipeline.hunt.kql import lookback_days

IOC_CAP = 200
FAMILIES = {
    "ip": {"ipv4", "ipv6"}, "domain": {"domain"}, "url": {"url"},
    "hash": {"md5", "sha1", "sha256"},
}
PYRAMID_LEVELS = {"ip": "ip_addresses", "domain": "domain_names", "url": "network_host_artifacts", "hash": "hash_values"}


@dataclass(frozen=True)
class _Guidance:
    noun: str
    benign: tuple[str, ...]
    pivots: tuple[str, ...]


# Analyst triage notes for a sweep hit, by indicator family.
_GUIDANCE = {
    "ip": _Guidance(
        "IP addresses",
        (
            "Shared hosting, CDN, cloud or VPN egress address carrying unrelated traffic.",
            "Address reassigned since the report; compare match times with the reported activity dates.",
        ),
        (
            "Sign-in match: review the user's other sign-ins, MFA result and any new device or session from that address.",
            "Device match: find the initiating process and the device's other connections around the match time.",
        ),
    ),
    "domain": _Guidance(
        "domains",
        (
            "Parked, sinkholed or re-registered domain, or a subdomain on shared hosting or dynamic DNS.",
            "Mail filters or link scanners resolved the domain without a user visiting it.",
        ),
        (
            "Identify the process that resolved or connected to the domain and review its parent and command line.",
            "Check DNS and proxy logs from the same device for first contact and regular beaconing.",
        ),
    ),
    "url": _Guidance(
        "URLs",
        (
            "Legitimate file-sharing or cloud storage link reused by the actor; the content may since have changed.",
            "Safe Links or proxy scanning fetched the URL without a user opening it.",
        ),
        (
            "Check UrlClickEvents or proxy logs for who opened the link and whether it was allowed or blocked.",
            "Look for files written shortly after the click and the process that opened them.",
        ),
    ),
    "hash": _Guidance(
        "file hashes",
        (
            "Legitimate or dual-use tool listed because of how the actor used it, such as a signed RMM installer; check the signer against approved software.",
            "Security team or sandbox host handling a copy of the sample.",
        ),
        (
            "Walk the process tree on the matched device: parent, children and command lines around the match.",
            "Find where the file came from (download URL, email attachment or dropping process) and how many devices have it.",
        ),
    ),
}


@dataclass(frozen=True)
class Sweep:
    family: str
    query: DraftQuery
    generated_by: str = "template"
    kind: str = "ioc_sweep"


@dataclass(frozen=True)
class _Target:
    table: str
    fields: tuple[str, ...]
    device: str = ""
    user: str = ""
    ip: str = ""


_TARGETS = {
    "ip": (
        _Target("DeviceNetworkEvents", ("RemoteIP", "LocalIP"), "DeviceName", "InitiatingProcessAccountUpn", "RemoteIP"),
        _Target("SigninLogs", ("IPAddress",), user="UserPrincipalName", ip="IPAddress"),
        _Target("AADNonInteractiveUserSignInLogs", ("IPAddress",), user="UserPrincipalName", ip="IPAddress"),
        _Target("IdentityLogonEvents", ("IPAddress", "DestinationIPAddress"), "DeviceName", "AccountUpn", "IPAddress"),
        _Target("CloudAppEvents", ("IPAddress",), user="AccountDisplayName", ip="IPAddress"),
        _Target("OfficeActivity", ("ClientIP",), user="UserId", ip="ClientIP"),
        _Target("CommonSecurityLog", ("SourceIP", "DestinationIP"), "Computer", "SourceUserName", "SourceIP"),
        _Target("DeviceLogonEvents", ("RemoteIP",), "DeviceName", "AccountName", "RemoteIP"),
        _Target("EmailEvents", ("SenderIPv4", "SenderIPv6"), user="RecipientEmailAddress", ip="SenderIPv4"),
    ),
    "domain": (
        _Target("DeviceNetworkEvents", ("RemoteUrl",), "DeviceName", "InitiatingProcessAccountUpn", "RemoteIP"),
        _Target("DnsEvents", ("Name",), "Computer", ip="ClientIP"),
        _Target("EmailUrlInfo", ("UrlDomain",)),
        _Target("UrlClickEvents", ("Url",), user="AccountUpn", ip="IPAddress"),
        _Target("CommonSecurityLog", ("DestinationHostName", "RequestURL"), "Computer", "SourceUserName", "DestinationIP"),
    ),
    "url": (
        _Target("DeviceNetworkEvents", ("RemoteUrl",), "DeviceName", "InitiatingProcessAccountUpn", "RemoteIP"),
        _Target("EmailUrlInfo", ("Url",)),
        _Target("UrlClickEvents", ("Url",), user="AccountUpn", ip="IPAddress"),
        _Target("CommonSecurityLog", ("RequestURL",), "Computer", "SourceUserName", "DestinationIP"),
    ),
    "hash": (
        _Target("DeviceFileEvents", ("SHA256", "SHA1", "MD5"), "DeviceName", "InitiatingProcessAccountUpn"),
        _Target("DeviceProcessEvents", ("SHA256", "SHA1", "MD5", "InitiatingProcessSHA256", "InitiatingProcessSHA1", "InitiatingProcessMD5"), "DeviceName", "AccountUpn"),
        _Target("DeviceImageLoadEvents", ("SHA256", "SHA1", "MD5"), "DeviceName", "InitiatingProcessAccountUpn"),
        _Target("EmailAttachmentInfo", ("SHA256",), user="RecipientEmailAddress"),
    ),
}


def indicator_values(indicators: Iterable[dict], family: str, cap: int = IOC_CAP) -> list[str]:
    values = {
        str(i["value"]).lower() if family in {"domain", "hash"} else str(i["value"])
        for i in indicators if i["type"] in FAMILIES[family] and not i.get("warninglist")
    }
    return sorted(values)[:cap]


def _literal(value: str) -> str:
    # JSON string escaping is also valid for a KQL double-quoted string.
    return json.dumps(value, ensure_ascii=False)


def _branch(target: _Target, family: str) -> str:
    insensitive = family == "hash"
    op = "in~" if insensitive else "in"
    clauses = [target.table, "| where TimeGenerated >= ago(lookback)"]
    fields = target.fields
    if family == "domain":
        # has_any matches alphanumeric terms, not dotted hostnames. Prefilter
        # on one label term per IOC before checking the exact host/subdomain.
        clauses.append("| where " + " or ".join(f"{f} has_any (ioc_terms)" for f in fields))
        clauses.append("| mv-apply MatchedIndicator = iocs to typeof(string) on (")
        hosts = []
        for f in fields:
            raw = f"tolower(tostring({f}))"
            # parse_url also handles RemoteUrl values that are bare hostnames.
            host = f'tostring(parse_url(iff({raw} contains "://", {raw}, strcat("https://", {raw}))).Host)'
            hosts.append(f"({host} == MatchedIndicator or {host} endswith strcat(\".\", MatchedIndicator))")
        clauses.append("    where " + " or ".join(hosts))
        clauses.append(")")
    else:
        clauses.append("| where " + " or ".join(f"{f} {op} (iocs)" for f in fields))
        if len(fields) == 1:
            matched = f"tostring({fields[0]})"
        else:
            args = ", ".join(f"{f} {op} (iocs), tostring({f})" for f in fields[:-1])
            matched = f"case({args}, tostring({fields[-1]}))"
        clauses.append(f"| extend MatchedIndicator = {matched}")
    device = f"tostring({target.device})" if target.device else '""'
    user = f"tostring({target.user})" if target.user else '""'
    ip = f"tostring({target.ip})" if target.ip else '""'
    clauses.append(
        f"| project TimeGenerated, SourceTable = {_literal(target.table)}, MatchedIndicator, "
        f"Device = {device}, User = {user}, IP = {ip}"
    )
    return "\n".join(clauses)


def build_sweeps(profile: Profile, indicators: Iterable[dict], cap: int = IOC_CAP) -> list[Sweep]:
    indicators = list(indicators)
    days = lookback_days(profile.retention_days)
    sweeps = []
    for family in FAMILIES:
        values = indicator_values(indicators, family, cap)
        targets = [t for t in _TARGETS[family] if t.table in profile.telemetry]
        if not values or not targets:
            continue
        prefix = (
            f"let lookback = {days}d;\n"
            f"let iocs = dynamic({json.dumps(values, ensure_ascii=False)});\n"
        )
        if family == "domain":
            terms = sorted({max(re.findall(r"[A-Za-z0-9]+", v), key=len) for v in values})
            prefix += f"let ioc_terms = dynamic({json.dumps(terms)});\n"
        branches = [_branch(t, family) for t in targets]
        body = branches[0] if len(branches) == 1 else "union isfuzzy=true\n" + ",\n".join("(\n" + b + "\n)" for b in branches)
        kql = prefix + body + "\n| order by TimeGenerated desc"
        total = len(indicator_values(indicators, family, max(len(indicators), cap)))
        guide = _GUIDANCE[family]
        count = f"{len(values)} non-warninglisted {guide.noun}"
        if total > len(values):
            count += f" (capped at {cap} of {total})"
        sweeps.append(Sweep(family, DraftQuery(
            title=f"Retrospective {family.upper() if family == 'ip' else family} IOC sweep",
            purpose=(
                f"Searches {days} days of logs for {count}. "
                "Sentinel TI-map rules match new events against ingested indicators; this sweep covers older logs."
            ),
            technique_ids=[], tables=[t.table for t in targets], kql=kql,
            benign_explanations=list(guide.benign), pivots=list(guide.pivots),
        )))
    return sweeps
