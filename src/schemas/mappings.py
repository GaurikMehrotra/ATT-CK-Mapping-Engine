"""Auditable outputs and configurable, nonprobabilistic scoring."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class MappingStatus(StrEnum):
    SUPPORTED = "supported_candidate"
    WEAK = "weak_candidate"
    INSUFFICIENT = "insufficient_evidence"
    REJECTED = "rejected"
    CONFIRMED = "analyst_confirmed"


class ScoreConfig(StrictModel):
    version: Literal["1.0"] = "1.0"
    supported_threshold: float = Field(default=0.70, gt=0, le=1)
    weak_threshold: float = Field(default=0.40, ge=0, lt=1)
    strength_weight: float = Field(default=0.40, ge=0, le=1)
    directness_weight: float = Field(default=0.25, ge=0, le=1)
    completeness_weight: float = Field(default=0.15, ge=0, le=1)
    reliability_weight: float = Field(default=0.10, ge=0, le=1)
    independence_weight: float = Field(default=0.10, ge=0, le=1)
    contradiction_penalty: float = Field(default=0.50, ge=0, le=1)
    correlation_window_seconds: int = Field(default=300, gt=0, le=86400)
    metadata_limit: int = Field(default=3, ge=0, le=20)

    @model_validator(mode="after")
    def valid_weights(self):
        weights = [
            self.strength_weight,
            self.directness_weight,
            self.completeness_weight,
            self.reliability_weight,
            self.independence_weight,
        ]
        if abs(sum(weights) - 1) > 1e-8 or self.weak_threshold >= self.supported_threshold:
            raise ValueError("weights must sum to one and weak threshold must be lower")
        return self


class EvidenceReference(StrictModel):
    observation_id: str
    source_id: str
    source_reference: str
    source_type: str
    observation_status: str
    underlying_event_key: str


class CandidateMapping(StrictModel):
    mapping_id: str
    technique_id: str
    technique_name: str
    catalog_stix_id: str
    subtechnique_parent_id: str | None
    associated_tactics: list[str]
    mapping_status: MappingStatus
    ranking_score: float = Field(ge=0, le=1)
    score_type: Literal["heuristic_ranking"] = "heuristic_ranking"
    score_version: Literal["1.0"] = "1.0"
    scoring_factors: dict[str, float]
    ranking_explanation: str
    evidence_ids: list[str]
    evidence_references: list[EvidenceReference]
    supporting_rationale: list[str]
    missing_context: list[str]
    contradictions: list[str]
    rule_ids: list[str]
    source_type: list[str]
    limitations: list[str]
    generation_methods: list[str]
    llm_rationale: str | None = None


class MappingRun(StrictModel):
    mapping_run_id: str
    schema_version: Literal["1.0"] = "1.0"
    catalog_version: str
    rule_set_version: str
    input_observation_ids: list[str]
    candidate_mappings: list[CandidateMapping]
    rejected_candidates: list[CandidateMapping]
    unmapped_observations: list[str]
    warnings: list[str]
    processing_metadata: dict
