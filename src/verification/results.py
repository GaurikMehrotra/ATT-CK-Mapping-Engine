"""Final independent traceability and status gates."""

from src.normalization.events import event_key
from src.rules.behavior import evaluate_rule
from src.rules.definitions import load_rules
from src.schemas.mappings import MappingStatus, ScoreConfig


def verify(run, batch, catalog, rules=None, config=None):
    rules = rules or load_rules()
    config = config or ScoreConfig()
    observations = {o.observation_id: o for o in batch.observations}
    if run.input_observation_ids != list(observations):
        raise ValueError("run input IDs differ from validated observations")
    if any(c.mapping_status != MappingStatus.REJECTED for c in run.rejected_candidates):
        raise ValueError("rejected list contains nonrejected candidate")
    if any(c.mapping_status == MappingStatus.REJECTED for c in run.candidate_mappings):
        raise ValueError("active candidate list contains rejected candidate")
    seen = set()
    for candidate in [*run.candidate_mappings, *run.rejected_candidates]:
        if candidate.mapping_id in seen:
            raise ValueError("duplicate mapping ID")
        seen.add(candidate.mapping_id)
        record = catalog["techniques"].get(candidate.technique_id)
        if not record or candidate.catalog_stix_id != record["stix_id"]:
            raise ValueError("candidate absent from catalog or incorrect source object")
        if (
            candidate.technique_name != record["name"]
            or candidate.subtechnique_parent_id != record["parent_id"]
            or candidate.associated_tactics != record["tactics"]
        ):
            raise ValueError("candidate metadata differs from loaded catalog")
        expected_score = round(max(0, min(1, sum(candidate.scoring_factors.values()))), 6)
        if abs(candidate.ranking_score - expected_score) > 1e-6:
            raise ValueError("ranking score does not match recorded factors")
        if not candidate.evidence_ids or set(candidate.evidence_ids) - observations.keys():
            raise ValueError("unresolvable candidate evidence")
        if set(candidate.evidence_ids) != {r.observation_id for r in candidate.evidence_references}:
            raise ValueError("incomplete evidence references")
        for ref in candidate.evidence_references:
            o = observations[ref.observation_id]
            if ref.underlying_event_key != event_key(o):
                raise ValueError("underlying event provenance changed")
            if (ref.source_id, ref.source_reference, ref.observation_status, ref.source_type) != (
                o.source_id,
                o.source_reference,
                o.observation_status,
                o.source_type,
            ):
                raise ValueError("source provenance changed")
        if candidate.mapping_status == MappingStatus.CONFIRMED:
            raise ValueError("automated pipeline cannot assert analyst confirmation")
        if candidate.mapping_status == MappingStatus.SUPPORTED:
            if record["revoked"] or record["deprecated"] or candidate.contradictions:
                raise ValueError("inactive or contradicted candidate cannot be supported")
            if "deterministic_rule" not in candidate.generation_methods:
                raise ValueError("retrieval or LLM alone cannot support a mapping")
            if candidate.ranking_score < config.supported_threshold:
                raise ValueError("supported candidate is below configured threshold")
            if any(
                observations[oid].observation_status not in {"directly_observed", "source_reported"}
                for oid in candidate.evidence_ids
            ):
                raise ValueError("nonruntime evidence cannot support execution")
            for oid in candidate.evidence_ids:
                o = observations[oid]
                if o.event_metadata.get("outcome") in {"failed", "blocked", "not_observed"}:
                    raise ValueError("unsuccessful source event cannot support successful behavior")
                platform = o.event_metadata.get("platform")
                if platform and record["platforms"] and platform not in record["platforms"]:
                    raise ValueError("platform outside catalog scope")
            if any(
                set(o.event_metadata.get("contradicts_observation_ids", []))
                & set(candidate.evidence_ids)
                for o in batch.observations
            ):
                raise ValueError("unresolved contrary evidence cannot support a mapping")
            valid_match = False
            for rule in rules.rules:
                if rule.rule_id + "@" + rule.version not in candidate.rule_ids:
                    continue
                for oid in candidate.evidence_ids:
                    for match in evaluate_rule(
                        rule, observations[oid], observations, config.correlation_window_seconds
                    ):
                        if (
                            match.technique_id == candidate.technique_id
                            and not match.missing
                            and set(match.evidence_ids) <= set(candidate.evidence_ids)
                        ):
                            valid_match = True
            if not valid_match:
                raise ValueError(
                    "supported candidate has no independently replayable defining rule"
                )
    supported = {
        oid
        for c in run.candidate_mappings
        if c.mapping_status == MappingStatus.SUPPORTED
        for oid in c.evidence_ids
    }
    if set(run.unmapped_observations) != set(observations) - supported:
        raise ValueError("unmapped observation list is inconsistent")
    return run
