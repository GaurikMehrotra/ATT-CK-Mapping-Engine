"""Synthetic STIX records using real identifiers; not benchmark evidence."""

import json

import pytest

from src.catalog.store import Catalog
from src.engine import Engine
from src.rules.definitions import load_rules


@pytest.fixture
def bundle():
    parent = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
        "name": "Synthetic command interpreter fixture",
        "description": "Synthetic test text",
        "x_mitre_domains": ["enterprise-attack"],
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
    }
    child = {
        **parent,
        "id": "attack-pattern--00000000-0000-4000-8000-000000000002",
        "name": "Synthetic PowerShell fixture",
        "x_mitre_is_subtechnique": True,
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": t}
            for t in ["execution", "defense-evasion"]
        ],
    }
    relation = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--00000000-0000-4000-8000-000000000003",
        "source_ref": child["id"],
        "target_ref": parent["id"],
        "relationship_type": "subtechnique-of",
    }
    return {"type": "bundle", "objects": [parent, child, relation]}


@pytest.fixture
def observation():
    return {
        "observation_id": "obs-1",
        "observation_type": "process_creation",
        "description": "Reported process creation",
        "source_type": "endpoint_telemetry",
        "source_id": "report-1",
        "source_reference": "events/1",
        "observation_status": "directly_observed",
    }


@pytest.fixture
def full_catalog(tmp_path):
    rules = load_rules()
    tids = {tid for rule in rules.rules for tid in rule.technique_ids}
    tids |= {tid.split(".")[0] for tid in tids}
    objects = []
    for i, tid in enumerate(sorted(tids)):
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--00000000-0000-4000-8000-{i:012d}",
                "name": f"Synthetic fixture {tid}",
                "description": f"Synthetic technique {tid}",
                "x_mitre_domains": ["enterprise-attack"],
                "x_mitre_is_subtechnique": "." in tid,
                "x_mitre_platforms": ["Windows"] if tid != "T1059.004" else ["Linux"],
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
                ],
            }
        )
    id_by_tid = {o["external_references"][0]["external_id"]: o["id"] for o in objects}
    for i, tid in enumerate(sorted(tids)):
        if "." in tid:
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--00000000-0000-4000-8000-{i:012d}",
                    "source_ref": id_by_tid[tid],
                    "target_ref": id_by_tid[tid.split(".")[0]],
                    "relationship_type": "subtechnique-of",
                }
            )
    p = tmp_path / "fixture.json"
    p.write_text(json.dumps({"type": "bundle", "objects": objects}))
    catalog = Catalog(tmp_path / "catalog.json")
    catalog.import_bundle(p, "synthetic-1", True)
    return catalog.load()


@pytest.fixture
def engine(full_catalog):
    return Engine(full_catalog, load_rules())
