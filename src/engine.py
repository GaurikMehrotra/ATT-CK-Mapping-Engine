"""Deterministic pipeline with optional retrieval and bounded rationale assistance."""

from collections import defaultdict
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from src.candidate_generation.retrieval import MetadataRetriever
from src.evidence.assessment import assess
from src.normalization.events import event_key
from src.ranking.scoring import score
from src.rules.behavior import evaluate_rule
from src.schemas.mappings import (
    CandidateMapping,
    EvidenceReference,
    MappingRun,
    MappingStatus,
    ScoreConfig,
)
from src.verification.results import verify


class Engine:
    def __init__(self, catalog, rules, config=None):
        self.catalog, self.rules = catalog, rules
        self.config = config or ScoreConfig()
        self.rule_warnings = rules.validate_catalog(catalog)
        self.retriever = MetadataRetriever(catalog)

    def map(self, batch, hybrid=True, llm=None):
        started = perf_counter()
        started_at = datetime.now(UTC).isoformat()
        by_id = {o.observation_id: o for o in batch.observations}
        grouped = defaultdict(list)
        for o in batch.observations:
            instance = o.event_metadata.get("correlation_id") or event_key(o)
            for rule in self.rules.rules:
                for match in evaluate_rule(rule, o, by_id, self.config.correlation_window_seconds):
                    grouped[(match.technique_id, instance)].append(match)
            if hybrid:
                for match in self.retriever.retrieve(o, self.config.metadata_limit):
                    grouped[(match.technique_id, instance)].append(match)
        candidates = []
        for (tid, _instance), matches in sorted(grouped.items()):
            record = self.catalog["techniques"][tid]
            # Retrieval adds audit history but cannot weaken or strengthen a rule-supported result.
            defining = [m for m in matches if m.method == "deterministic_rule"]
            assessed = assess(defining or matches, by_id, record, batch.observations)
            raw, factors, status, explanation = score(defining or matches, assessed, self.config)
            evidence = assessed["evidence"]
            candidate = CandidateMapping(
                mapping_id=str(uuid4()),
                technique_id=tid,
                technique_name=record["name"],
                catalog_stix_id=record["stix_id"],
                subtechnique_parent_id=record["parent_id"],
                associated_tactics=record["tactics"],
                mapping_status=status,
                ranking_score=raw,
                scoring_factors=factors,
                ranking_explanation=explanation,
                evidence_ids=[o.observation_id for o in evidence],
                evidence_references=[
                    EvidenceReference(
                        observation_id=o.observation_id,
                        source_id=o.source_id,
                        source_reference=o.source_reference,
                        source_type=o.source_type,
                        observation_status=o.observation_status,
                        underlying_event_key=event_key(o),
                    )
                    for o in evidence
                ],
                supporting_rationale=sorted({m.rationale for m in defining or matches}),
                missing_context=assessed["missing"],
                contradictions=assessed["contradictions"],
                rule_ids=sorted({m.rule_id for m in matches}),
                source_type=sorted({o.source_type for o in evidence}),
                limitations=sorted(
                    {l for m in matches for l in m.limitations}
                    | {l for o in evidence for l in o.limitations}
                    | {
                        "Candidate support does not establish malicious intent",
                        "Heuristic score is not probability",
                    }
                ),
                generation_methods=sorted({m.method for m in matches}),
            )
            candidates.append(candidate)
        # Suppress a broader parent only when supported child covers the same evidence.
        for parent in candidates:
            children = [
                c
                for c in candidates
                if c.subtechnique_parent_id == parent.technique_id
                and c.mapping_status == MappingStatus.SUPPORTED
                and set(parent.evidence_ids) <= set(c.evidence_ids)
            ]
            if children and parent.mapping_status != MappingStatus.REJECTED:
                parent.mapping_status = MappingStatus.REJECTED
                parent.contradictions.append(
                    "Redundant parent: defining child behavior supported for same evidence"
                )
        candidates.sort(key=lambda c: (-c.ranking_score, c.technique_id))
        supported_ids = {
            oid
            for c in candidates
            if c.mapping_status == MappingStatus.SUPPORTED
            for oid in c.evidence_ids
        }
        warnings = list(self.rule_warnings)
        if self.catalog["metadata"].get("synthetic"):
            warnings.append(
                "Synthetic catalog: not authoritative ATT&CK data or benchmark evidence"
            )
        if not supported_ids:
            warnings.append("Abstained: no evidence-supported candidate")
        llm_status = {"status": "disabled", "model": None, "prompt_version": "1.0"}
        if llm:
            llm_status = llm.assist(candidates, batch)
            if llm_status["status"] != "completed":
                warnings.append(
                    f"LLM assistance {llm_status['status']}; deterministic results retained"
                )
        run = MappingRun(
            mapping_run_id=str(uuid4()),
            catalog_version=self.catalog["metadata"]["catalog_version"],
            rule_set_version=self.rules.version,
            input_observation_ids=list(by_id),
            candidate_mappings=[
                c for c in candidates if c.mapping_status != MappingStatus.REJECTED
            ],
            rejected_candidates=[
                c for c in candidates if c.mapping_status == MappingStatus.REJECTED
            ],
            unmapped_observations=sorted(set(by_id) - supported_ids),
            warnings=warnings,
            processing_metadata={
                "started_at": started_at,
                "runtime_seconds": perf_counter() - started,
                "observation_count": len(by_id),
                "catalog_source_sha256": self.catalog["metadata"]["source_sha256"],
                "rule_set_sha256": self.rules.digest,
                "score_configuration": self.config.model_dump(),
                "configuration": "hybrid" if hybrid else "deterministic",
                "llm": llm_status,
                "calibrated": False,
            },
        )
        return verify(run, batch, self.catalog, self.rules, self.config)
