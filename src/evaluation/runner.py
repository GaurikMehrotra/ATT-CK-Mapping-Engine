"""Keyword, contextual and hybrid comparison using explicit annotated manifests."""

from time import perf_counter

from pydantic import Field, model_validator

from src.evaluation.metrics import measure
from src.schemas.mappings import MappingStatus, StrictModel
from src.schemas.observations import ObservationBatch

# Deliberately broad and flawed; ONLY used for the comparison baseline.
KEYWORDS = {
    "powershell": "T1059.001",
    "cmd.exe": "T1059.003",
    "bash": "T1059.004",
    "run": "T1547.001",
    "task": "T1053.005",
    "disable": "T1562.001",
    "file": "T1204.002",
    "http": "T1071.001",
}


class Case(StrictModel):
    case_id: str = Field(min_length=1)
    input: ObservationBatch
    expected: list[str]
    acceptable_sets: list[list[str]] = Field(default_factory=list)
    evidence_labels: dict[str, list[str]] = Field(default_factory=dict)
    ambiguous: bool = False
    annotation_notes: str = Field(min_length=1)

    @model_validator(mode="after")
    def valid_labels(self):
        ids = {o.observation_id for o in self.input.observations}
        labels = set(self.expected) | {t for group in self.acceptable_sets for t in group}
        if set(self.evidence_labels) - labels:
            raise ValueError("evidence labels must correspond to annotated techniques")
        for refs in self.evidence_labels.values():
            if not refs or set(refs) - ids:
                raise ValueError("ground-truth evidence references must resolve")
        if labels - self.evidence_labels.keys():
            raise ValueError("every positive label requires annotated supporting evidence")
        return self


class Dataset(StrictModel):
    schema_version: str = "1.0"
    dataset_id: str = Field(min_length=1)
    synthetic: bool
    annotation_procedure: str = Field(min_length=1)
    cases: list[Case] = Field(min_length=1, max_length=10000)

    @model_validator(mode="after")
    def unique_cases(self):
        if self.schema_version != "1.0" or len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("unsupported dataset version or duplicate case IDs")
        return self


def keyword_predictions(batch, catalog):
    text = " ".join(
        " ".join(
            [
                o.description,
                o.process_name or "",
                o.command_line or "",
                o.file_path or "",
                o.registry_path or "",
                o.network_destination or "",
            ]
        )
        for o in batch.observations
    ).casefold()
    return sorted(
        {
            tid
            for word, tid in KEYWORDS.items()
            if word in text
            and tid in catalog["techniques"]
            and not catalog["techniques"][tid]["revoked"]
            and not catalog["techniques"][tid]["deprecated"]
        }
    )


def evaluate(engine, dataset, k=3, llm=None):
    if not 1 <= k <= 100:
        raise ValueError("k must be between 1 and 100")
    known = engine.catalog["techniques"]
    for case in dataset.cases:
        labels = set(case.expected) | {tid for group in case.acceptable_sets for tid in group}
        if labels - known.keys():
            raise ValueError("dataset label absent from loaded catalog")
    configurations = {}
    for mode in ["keyword", "deterministic", "hybrid"]:
        rows = []
        for case in dataset.cases:
            started = perf_counter()
            if mode == "keyword":
                predicted = keyword_predictions(case.input, engine.catalog)
                retrieved = predicted
                candidates = []
            else:
                run = engine.map(
                    case.input, hybrid=mode == "hybrid", llm=llm if mode == "hybrid" else None
                )
                candidates = [
                    c for c in run.candidate_mappings if c.mapping_status == MappingStatus.SUPPORTED
                ]
                predicted = list(dict.fromkeys(c.technique_id for c in candidates))
                retrieved = list(dict.fromkeys(c.technique_id for c in run.candidate_mappings))
            evidence_map = {}
            for c in candidates:
                evidence_map.setdefault(c.technique_id, set()).update(c.evidence_ids)
            # Unsupported is measured against explicit annotated evidence, not merely ID membership.
            unsupported = sum(
                not case.evidence_labels.get(tid)
                or not evidence_map.get(tid)
                or not set(case.evidence_labels[tid]) <= evidence_map[tid]
                for tid in predicted
            )
            rows.append(
                {
                    "case_id": case.case_id,
                    "predicted": predicted,
                    "retrieved": retrieved,
                    "expected": case.expected,
                    "acceptable_sets": case.acceptable_sets,
                    "ambiguous": case.ambiguous,
                    "unsupported_count": unsupported,
                    "complete_reference_count": len(evidence_map),
                    "observation_count": len(case.input.observations),
                    "runtime_seconds": perf_counter() - started,
                }
            )
        configurations[mode] = {"metrics": measure(rows, k), "cases": rows}
    return {
        "dataset_id": dataset.dataset_id,
        "synthetic": dataset.synthetic,
        "catalog_version": engine.catalog["metadata"]["catalog_version"],
        "rule_set_version": engine.rules.version,
        "rule_set_sha256": engine.rules.digest,
        "score_configuration": engine.config.model_dump(),
        "configurations": configurations,
        "llm_enabled": llm is not None,
        "limitations": ["Synthetic scenarios are not real-world benchmark evidence"]
        if dataset.synthetic
        else ["Quality depends on independently reviewed annotations and representative telemetry"],
    }
