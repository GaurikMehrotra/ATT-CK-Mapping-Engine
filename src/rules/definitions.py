"""Versioned rule metadata plus an allowlisted implementation registry."""

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from src.catalog.store import read_json
from src.schemas.mappings import StrictModel
from src.schemas.observations import Observation, ObservationType

HANDLER_TARGETS = {
    "powershell": "T1059.001",
    "cmd": "T1059.003",
    "unix_shell": "T1059.004",
    "interpreter": "T1059",
    "autorun": "T1547.001",
    "scheduled_task": "T1053.005",
    "defender": "T1562.001",
    "firewall": "T1562.004",
    "file_execution": "T1204.002",
    "http_c2": "T1071.001",
}


class Rule(StrictModel):
    rule_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    handler: Literal[
        "powershell",
        "cmd",
        "unix_shell",
        "interpreter",
        "autorun",
        "scheduled_task",
        "defender",
        "firewall",
        "file_execution",
        "http_c2",
    ]
    observation_types: list[ObservationType] = Field(min_length=1)
    required_fields: list[str]
    optional_context: list[str]
    technique_ids: list[str] = Field(min_length=1)
    rationale: str
    limitations: list[str]
    conditions: list[str] = Field(min_length=1)
    weakening_conditions: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def handler_contract(self):
        if self.technique_ids != [HANDLER_TARGETS[self.handler]]:
            raise ValueError("handler target must match its implemented ATT&CK behavior")
        if set(self.required_fields) - Observation.model_fields.keys():
            raise ValueError("rule requires an unknown observation field")
        return self


class RuleSet(StrictModel):
    version: str = Field(min_length=1)
    rules: list[Rule] = Field(min_length=1)

    def validate_catalog(self, catalog: dict) -> list[str]:
        seen = set()
        warnings = []
        for rule in self.rules:
            if rule.rule_id in seen:
                raise ValueError("duplicate rule ID")
            seen.add(rule.rule_id)
            for tid in rule.technique_ids:
                if tid not in catalog["techniques"]:
                    raise ValueError(f"rule {rule.rule_id} references absent technique {tid}")
                record = catalog["techniques"][tid]
                if record["revoked"] or record["deprecated"]:
                    warnings.append(f"{rule.rule_id}: {tid} is inactive; it will be rejected")
        return warnings

    @property
    def digest(self):
        return hashlib.sha256(
            json.dumps(self.model_dump(mode="json"), sort_keys=True).encode()
        ).hexdigest()


def load_rules(path: Path | None = None) -> RuleSet:
    return RuleSet.model_validate(
        read_json(path or Path(__file__).parents[2] / "rules/default.json")
    )
