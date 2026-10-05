"""Deterministic extraction of IOCs and explicit ATT&CK references."""
from __future__ import annotations

import json
from collections import Counter
from urllib.parse import urlsplit

from tipipeline.attack import TECHNIQUE_ID_RE
from tipipeline.db import upsert_indicator
from tipipeline.extract.iocs import IOC, clean_url, extract_text, normalise, refang, source_domain, timestamp
from tipipeline.extract.warninglists import load


def metadata_iocs(document) -> list[IOC]:
    metadata = json.loads(document["meta_json"])
    if document["kind"] == "vulnerability":
        item = normalise("cve", metadata.get("cveID", ""))
        return [IOC(*item, "metadata", metadata.get("shortDescription", document["title"]))] if item else []
    items: dict[tuple[str, str], IOC] = {}
    for record in metadata.get("iocs", []):
        if not isinstance(record, dict): continue
        item = normalise(record.get("ioc_type", ""), record.get("ioc", ""))
        if not item: continue
        items[item] = IOC(*item, "feed", str(record.get("ioc", "")))
        if item[0] == "url":
            parsed = clean_url(item[1])
            if parsed:
                host = parsed[1], parsed[2]
                items[host] = IOC(*host, "feed", str(record.get("ioc", "")))
    return list(items.values())


def _source_match(type_: str, value: str, source: str) -> bool:
    if not source: return False
    if type_ == "domain": host = value
    elif type_ == "url": host = urlsplit(value).hostname or ""
    elif type_ == "email": host = value.rsplit("@", 1)[-1]
    else: return False
    return host == source or host.endswith("." + source)


def run(ctx) -> dict:
    warnings = load(ctx)
    documents = ctx.db.execute("""
        SELECT * FROM documents d
        WHERE extracted_version IS NULL OR extracted_version < version
           OR (duplicate_of IS NOT NULL AND
               (EXISTS (SELECT 1 FROM document_indicators di WHERE di.document_id=d.id)
                OR EXISTS (SELECT 1 FROM document_techniques dt WHERE dt.document_id=d.id AND dt.source='explicit')))
        ORDER BY id
    """).fetchall()
    counts: Counter = Counter()
    techniques = duplicate_count = 0
    for document in documents:
        document_id = document["id"]
        ctx.db.execute("DELETE FROM document_indicators WHERE document_id=?", (document_id,))
        ctx.db.execute("DELETE FROM document_techniques WHERE document_id=? AND source='explicit'", (document_id,))
        if document["duplicate_of"] is not None:
            duplicate_count += 1
        else:
            records = metadata_iocs(document) if document["kind"] in {"vulnerability", "ioc_batch"} else extract_text(document["text"])
            seen_at = timestamp(document["published_at"], document["collected_at"])
            for record in records:
                indicator_id = upsert_indicator(ctx.db, record.type, record.value, seen_at)
                ctx.db.execute("""INSERT INTO document_indicators (document_id,indicator_id,context,snippet)
                                  VALUES (?,?,?,?)""", (document_id, indicator_id, record.context, record.snippet))
                counts[record.type] += 1
            for technique_id in sorted(set(TECHNIQUE_ID_RE.findall(document["text"]))):
                valid = int(ctx.attack.is_valid(technique_id))
                ctx.db.execute("""INSERT INTO document_techniques
                    (document_id,technique_id,source,basis,quote,quote_verified,valid)
                    VALUES (?,?,'explicit','stated',?,1,?)""", (document_id, technique_id, technique_id, valid))
                techniques += 1
        ctx.db.execute("UPDATE documents SET extracted_version=version WHERE id=?", (document_id,))
        ctx.db.commit()
    # Refresh all flags, including unchanged content, after a weekly list
    # refresh. An observation is kept even when legitimate infrastructure matches.
    for row in ctx.db.execute("""SELECT di.document_id,di.indicator_id,di.warninglist,i.type,i.value,d.url
                                FROM document_indicators di JOIN indicators i ON i.id=di.indicator_id
                                JOIN documents d ON d.id=di.document_id""").fetchall():
        own_domain = source_domain(row["url"])
        flag = "source-domain" if _source_match(row["type"], row["value"], own_domain) else warnings.match(row["type"], row["value"])
        if row["warninglist"] != flag:
            ctx.db.execute("UPDATE document_indicators SET warninglist=? WHERE document_id=? AND indicator_id=?",
                           (flag, row["document_id"], row["indicator_id"]))
    ctx.db.commit()
    flagged = {row["warninglist"]: row["n"] for row in ctx.db.execute(
        "SELECT warninglist,COUNT(*) n FROM document_indicators WHERE warninglist IS NOT NULL GROUP BY warninglist")}
    total = {row["type"]: row["n"] for row in ctx.db.execute("""SELECT i.type,COUNT(DISTINCT i.id) n FROM indicators i
        JOIN document_indicators di ON di.indicator_id=i.id JOIN documents d ON d.id=di.document_id
        WHERE d.duplicate_of IS NULL GROUP BY i.type""")}
    incomplete = bool(warnings.unavailable or warnings.stale)
    status = "partial" if incomplete and (warnings.lists or documents) else "error" if incomplete else "ok"
    return {"status": status, "documents": len(documents) - duplicate_count, "duplicates_skipped": duplicate_count,
            "indicators_by_type": dict(counts), "total_indicators_by_type": total,
            "explicit_techniques": techniques, "flagged": sum(flagged.values()), "flagged_by_warninglist": flagged,
            "warninglists_loaded": len(warnings.lists), "warninglists_unavailable": warnings.unavailable,
            "warninglists_stale": warnings.stale}
