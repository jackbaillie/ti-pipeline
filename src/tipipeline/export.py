"""STIX 2.1 evidence bundles and Sentinel upload envelopes.

TLP:WHITE is used (the legacy STIX vocabulary for unrestricted sharing).
Indicator lifetimes are triage defaults, not guarantees of continued malice:
IPs 30 days (rapid reassignment), domains/URLs 90, email 180, immutable file
hashes 365. Stored observations are never removed when the TTL expires.
Only explicit IOC-section and structured-feed observations are exported as
malicious-activity indicators; body mentions remain unclassified observations.
Stable STIX IDs let repeated exports update rather than duplicate objects.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid5

import stix2

from tipipeline.extract.iocs import clean_url, normalise, timestamp

NAMESPACE = UUID("72306ab1-97b8-4c6c-a089-274cf8fd479d")
TTL_DAYS = {"ipv4": 30, "ipv6": 30, "domain": 90, "url": 90, "email": 180, "md5": 365, "sha1": 365, "sha256": 365}
SOURCE_CONFIDENCE = {"government": 85, "research": 80, "ioc_feed": 65, "news": 50, "manual": 60}
PROPERTIES = {"ipv4": "ipv4-addr:value", "ipv6": "ipv6-addr:value", "domain": "domain-name:value",
              "url": "url:value", "email": "email-addr:value", "md5": "file:hashes.MD5",
              "sha1": "file:hashes.'SHA-1'", "sha256": "file:hashes.'SHA-256'"}


def stable_id(type_: str, value: str) -> str:
    return f"{type_}--{uuid5(NAMESPACE, type_ + ':' + value)}"


def pattern(type_: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"[{PROPERTIES[type_]} = '{escaped}']"


def _date(value: str | None, fallback: str | None = None) -> datetime:
    return datetime.fromisoformat(timestamp(value, fallback)).astimezone(UTC)


def _feed_confidences(document) -> dict[tuple[str, str], int]:
    result = {}
    if document["kind"] != "ioc_batch": return result
    for item in json.loads(document["meta_json"]).get("iocs", []):
        if not isinstance(item, dict): continue
        key = normalise(item.get("ioc_type", ""), item.get("ioc", ""))
        try: confidence = max(0, min(100, int(item["confidence_level"])))
        except (KeyError, TypeError, ValueError): continue
        if key:
            result[key] = max(result.get(key, 0), confidence)
            if key[0] == "url":
                parsed = clean_url(key[1])
                if parsed: result[parsed[1], parsed[2]] = confidence
    return result


def confidence(rows, documents, feed_scores) -> int:
    """Transparent, ordinal heuristic, not a calibrated probability.

An explicit IOC section scores above an incidental body mention. ThreatFox's
confidence is blended with the source tier. The strongest observation score
is retained; repeated reporting adds no confidence because source independence
has not been established.
"""
    scores = []
    for row in rows:
        document = documents[row["document_id"]]
        score = SOURCE_CONFIDENCE[document["tier"]]
        score += {"ioc_section": 10, "feed": 5, "metadata": 5, "body": -15}[row["context"]]
        feed = feed_scores.get(document["id"], {}).get((row["type"], row["value"]))
        if feed is not None: score = round((score + feed) / 2)
        scores.append(score)
    return max(0, min(100, max(scores)))


def run(ctx) -> dict:
    now = datetime.now(UTC)
    identity = stix2.Identity(id=stable_id("identity", "ti-pipeline"), name="ti-pipeline", identity_class="system",
                              created="2026-10-05T00:00:00Z", modified="2026-10-05T00:00:00Z")
    marking = stix2.TLP_WHITE
    documents = {row["id"]: row for row in ctx.db.execute("SELECT * FROM documents WHERE duplicate_of IS NULL ORDER BY id")}
    feed_scores = {key: _feed_confidences(document) for key, document in documents.items() if document["kind"] == "ioc_batch"}
    associations = defaultdict(list)
    document_iocs = defaultdict(list)
    for row in ctx.db.execute("""SELECT i.*,di.document_id,di.context FROM indicators i
        JOIN document_indicators di ON di.indicator_id=i.id JOIN documents d ON d.id=di.document_id
        WHERE d.duplicate_of IS NULL AND di.warninglist IS NULL AND i.type != 'cve'
          AND di.context IN ('ioc_section','feed')
        ORDER BY i.id,di.document_id"""):
        associations[row["id"]].append(row)
        document_iocs[row["document_id"]].append(row["id"])
    indicators = {}
    for indicator_id, rows in associations.items():
        row = rows[0]
        sources = [documents[item["document_id"]] for item in rows]
        # Body observations touch the global IOC history but cannot revive
        # malicious validity. Only qualifying source associations define it.
        sightings = [_date(document["published_at"], document["collected_at"]) for document in sources]
        created, last = min(sightings), max(sightings)
        until = last + timedelta(days=TTL_DAYS[row["type"]])
        references = [{"source_name": document["source_id"], "url": document["url"], "description": document["title"]} for document in sources]
        description = "Reported in: " + "; ".join(f"{document['title']} ({document['source_id']})" for document in sources)
        indicators[indicator_id] = stix2.Indicator(
            id=stable_id("indicator", row["type"] + ":" + row["value"]), name=row["value"], description=description,
            pattern=pattern(row["type"], row["value"]), pattern_type="stix", pattern_version="2.1",
            indicator_types=["malicious-activity"], created_by_ref=identity.id,
            created=created, modified=max(now, created), valid_from=created, valid_until=until,
            confidence=confidence(rows, documents, feed_scores), external_references=references,
            object_marking_refs=[marking.id])
    technique_objects = {}
    document_techniques = defaultdict(list)
    for row in ctx.db.execute("""SELECT DISTINCT dt.document_id,dt.technique_id
        FROM document_techniques dt JOIN documents d ON d.id=dt.document_id
        LEFT JOIN analyses a ON a.document_id=dt.document_id
        WHERE dt.valid=1 AND (dt.source='explicit'
            OR (dt.source='llm' AND a.status='ok' AND a.document_version=d.version))
        ORDER BY dt.document_id,dt.technique_id"""):
        if row["document_id"] not in documents: continue
        technique = ctx.attack.get(row["technique_id"])
        if not technique or technique.deprecated: continue
        if technique.id not in technique_objects:
            technique_objects[technique.id] = stix2.AttackPattern(
                id=stable_id("attack-pattern", technique.id), name=technique.name,
                created_by_ref=identity.id, created=identity.created, modified=identity.modified,
                external_references=[{"source_name": "mitre-attack", "external_id": technique.id, "url": technique.url}],
                object_marking_refs=[marking.id])
        document_techniques[row["document_id"]].append(technique.id)
    document_cves = defaultdict(list)
    vulnerabilities = {}
    for row in ctx.db.execute("""SELECT di.document_id,i.value FROM document_indicators di
        JOIN indicators i ON i.id=di.indicator_id WHERE i.type='cve' ORDER BY di.document_id,i.value"""):
        if row["document_id"] not in documents: continue
        if row["value"] not in vulnerabilities:
            vulnerabilities[row["value"]] = stix2.Vulnerability(
                id=stable_id("vulnerability", row["value"]), name=row["value"],
                created_by_ref=identity.id, created=identity.created, modified=identity.modified,
                external_references=[{"source_name": "cve", "external_id": row["value"],
                                      "url": f"https://www.cve.org/CVERecord?id={row['value']}"}], object_marking_refs=[marking.id])
        document_cves[row["document_id"]].append(row["value"])
    directory = ctx.output_dir / "stix"
    document_dir = directory / "documents"
    upload_dir = directory / "sentinel-upload"
    document_dir.mkdir(parents=True, exist_ok=True)
    upload_dir.mkdir(parents=True, exist_ok=True)
    wanted = set()
    unique = {identity.id: identity, marking.id: marking}
    for document_id, document in documents.items():
        objects = ([indicators[item] for item in document_iocs[document_id]]
                   + [technique_objects[item] for item in document_techniques[document_id]]
                   + [vulnerabilities[item] for item in document_cves[document_id]])
        published = _date(document["published_at"] or document["collected_at"])
        summary = ctx.db.execute("SELECT summary FROM analyses WHERE document_id=? AND document_version=? AND status='ok'",
                                 (document_id, document["version"])).fetchone()
        report = stix2.Report(
            id=stable_id("report", document["canonical_url"]), name=document["title"], published=published,
            created=_date(document["collected_at"]), modified=max(now, _date(document["collected_at"])),
            description=summary[0] if summary and summary[0] else f"Source reporting from {document['source_id']}; extracted observations, not an attribution claim.",
            report_types=["vulnerability" if document["kind"] == "vulnerability" else "threat-report"],
            created_by_ref=identity.id, object_refs=[obj.id for obj in objects] or [identity.id],
            external_references=[{"source_name": document["source_id"], "url": document["url"]}], object_marking_refs=[marking.id])
        bundle_objects = [identity, marking, report, *objects]
        unique.update((obj.id, obj) for obj in bundle_objects)
        target = document_dir / f"{document_id}.json"
        target.write_text(stix2.Bundle(objects=bundle_objects).serialize(pretty=True) + "\n")
        wanted.add(target.name)
    for target in document_dir.glob("*.json"):
        if target.name not in wanted: target.unlink()
    active = [item for item in indicators.values() if item.valid_until > now]
    (directory / "active-indicators.json").write_text(stix2.Bundle(objects=[identity, marking, *active]).serialize(pretty=True) + "\n")
    # Sentinel accepts indicator/identity SDOs. Reports and marking-definition
    # objects stay in the full bundles; TLP's canonical marking ID is retained.
    uploads = [identity, *active] if active else []
    batches = 0
    upload_names = set()
    for start in range(0, len(uploads), 100):
        batches += 1
        name = f"batch-{batches:03}.json"
        envelope = {"sourcesystem": "ti-pipeline", "stixobjects": [json.loads(item.serialize()) for item in uploads[start:start+100]]}
        (upload_dir / name).write_text(json.dumps(envelope, indent=2) + "\n")
        upload_names.add(name)
    for target in upload_dir.glob("batch-*.json"):
        if target.name not in upload_names: target.unlink()
    return {"documents": len(documents), "indicators": len(indicators), "active_indicators": len(active),
            "expired_indicators": len(indicators) - len(active), "attack_patterns": len(technique_objects),
            "vulnerabilities": len(vulnerabilities), "objects_by_type": dict(Counter(obj.type for obj in unique.values())),
            "sentinel_batches": batches, "sentinel_objects": len(uploads), "tlp": "WHITE (unrestricted)"}
