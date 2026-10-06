"""Wrap one customer's drafted hunt in its PEAK package."""
from __future__ import annotations

import json

from tipipeline.hunt.draft import DraftResult
from tipipeline.models import ActPhase, HuntPackage, HuntTrigger, PreparePhase, Profile


def build_package(*, document: dict, profile: Profile, relevance: dict, result: DraftResult, knowledge: list[str]) -> HuntPackage:
    return HuntPackage(
        document_id=document["id"], profile_id=profile.id, title=result.title, status="prepared",
        prepare=PreparePhase(
            trigger=HuntTrigger(
                document_id=document["id"], title=document["title"], url=document["url"],
                source_id=document["source_id"], published_at=document["published_at"],
            ),
            priority=relevance["priority"], relevance_rationale=relevance["rationale"],
            matched_pirs=json.loads(relevance["matched_pirs_json"]), hypothesis=result.hypothesis,
            scope=result.scope, techniques=result.techniques, pyramid_levels=result.pyramid_levels,
            evidence=result.evidence,
        ),
        act=ActPhase(gaps=result.gaps), knowledge=knowledge,
    )
