"""Directness, contradictory outcomes and platform scope assessment."""

from src.normalization.events import event_key

DIRECTNESS = {
    "directly_observed": 1.0,
    "source_reported": 0.7,
    "static_indicator": 0.15,
    "inferred": 0.3,
    "analyst_hypothesis": 0.1,
}


def assess(matches, by_id, technique, observations):
    ids = sorted({oid for match in matches for oid in match.evidence_ids})
    evidence = [by_id[oid] for oid in ids]
    # Copies of an underlying event cannot increase score or source independence.
    groups = {}
    for o in evidence:
        groups.setdefault(event_key(o), []).append(o)
    directness = min(DIRECTNESS[o.observation_status] for o in evidence)
    missing = sorted({item for m in matches for item in m.missing})
    contradictions = []
    if technique["revoked"] or technique["deprecated"]:
        contradictions.append("Catalog technique is revoked or deprecated")
    for o in evidence:
        if o.event_metadata.get("outcome") in {"failed", "blocked", "not_observed"}:
            contradictions.append(f"{o.observation_id}: action did not succeed")
        platform = o.event_metadata.get("platform")
        if platform and technique["platforms"] and platform not in technique["platforms"]:
            contradictions.append(
                f"{o.observation_id}: platform {platform} outside technique scope"
            )
    for o in observations:
        targets = set(o.event_metadata.get("contradicts_observation_ids", [])) & set(ids)
        if targets:
            if o.observation_status in {"directly_observed", "source_reported"}:
                contradictions.append(
                    f"{o.observation_id}: contradicts {', '.join(sorted(targets))}"
                )
            else:
                missing.append(f"Resolve unverified contrary claim from {o.observation_id}")
    sources = {
        o.event_metadata["independent_source_id"]
        for o in evidence
        if o.event_metadata.get("independent_source_id")
    }
    # Different source IDs are only potentially independent, and cannot inflate duplicates.
    independent_count = min(len(groups), len(sources))
    reliability = min(float(o.event_metadata.get("source_reliability", 0.7)) for o in evidence)
    if not all(o.event_metadata.get("platform") for o in evidence):
        missing.append("Platform is unknown; catalog platform compatibility is unverified")
    behavioral = any(m.method == "deterministic_rule" for m in matches)
    critical = sorted(
        {item for m in matches if m.method == "deterministic_rule" for item in m.missing}
    )
    critical.extend(
        item for item in missing if item.startswith("Resolve unverified contrary claim")
    )
    if directness < 0.7:
        critical.append("Observed or source-reported runtime behavior is required")
        missing.append("Observed or source-reported runtime behavior is required")
    return {
        "evidence": evidence,
        "directness": directness,
        "missing": sorted(set(missing)),
        "critical_missing": critical,
        "contradictions": sorted(set(contradictions)),
        "independent_count": independent_count,
        "reliability": reliability,
        "behavioral": behavioral,
    }
