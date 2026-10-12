"""Offline synthetic scenarios, not a real-world benchmark."""

import pytest
from pydantic import ValidationError

from src.engine import Engine
from src.ingestion.readers import ingest
from src.rules.definitions import load_rules
from src.schemas.mappings import ScoreConfig
from src.schemas.observations import ObservationBatch
from src.verification.results import verify


def event(**kwargs):
    base = {
        "observation_id": "o1",
        "observation_type": "process_creation",
        "description": "Synthetic observation",
        "source_type": "endpoint_telemetry",
        "source_id": "report1",
        "source_reference": "/events/1",
        "observation_status": "directly_observed",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -Command Get-Date",
        "event_metadata": {"platform": "Windows"},
    }
    base.update(kwargs)
    return base


def batch(*events):
    return ObservationBatch.model_validate({"observations": list(events)})


def supported(run):
    return {
        c.technique_id for c in run.candidate_mappings if c.mapping_status == "supported_candidate"
    }


def test_powershell_traceability_and_tactics(engine):
    run = engine.map(batch(event()), hybrid=False)
    assert supported(run) == {"T1059.001"}
    c = run.candidate_mappings[0]
    assert c.subtechnique_parent_id == "T1059"
    assert c.evidence_references[0].source_reference == "/events/1"
    assert c.score_type == "heuristic_ranking" and not run.processing_metadata["calibrated"]
    assert len(c.associated_tactics) == 2 and c.rule_ids == ["behavior.powershell@1.0"]


@pytest.mark.parametrize(
    "change",
    [
        {"command_line": None},
        {"observation_status": "static_indicator"},
        {"observation_status": "inferred"},
        {"observation_status": "analyst_hypothesis"},
    ],
)
def test_missing_or_nonruntime_abstains(engine, change):
    run = engine.map(batch(event(**change)), hybrid=False)
    assert not supported(run) and run.unmapped_observations == ["o1"]
    assert run.candidate_mappings[0].missing_context


@pytest.mark.parametrize(
    "meta", [{"platform": "Linux"}, {"outcome": "failed"}, {"outcome": "blocked"}]
)
def test_contradictions_rejected(engine, meta):
    run = engine.map(batch(event(event_metadata=meta)), hybrid=False)
    assert not supported(run) and run.rejected_candidates[0].contradictions


def test_explicit_contrary_evidence(engine):
    contrary = event(
        observation_id="o2",
        observation_type="other",
        process_name=None,
        event_metadata={"contradicts_observation_ids": ["o1"]},
    )
    run = engine.map(batch(event(), contrary), hybrid=False)
    assert run.rejected_candidates[0].mapping_status == "rejected"
    assert "o2" in run.rejected_candidates[0].contradictions[0]


@pytest.mark.parametrize("type_name", ["file_write", "network_connection", "dns_request"])
def test_isolated_events_abstain(engine, type_name):
    run = engine.map(batch(event(observation_type=type_name)), hybrid=False)
    assert not run.candidate_mappings and run.unmapped_observations == ["o1"]


def test_registry_exact_location(engine):
    e = event(
        observation_type="registry_modification",
        registry_path=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Demo",
        event_metadata={
            "action": "set_value",
            "registry_value_data": "example.exe",
            "platform": "Windows",
        },
    )
    assert supported(engine.map(batch(e), hybrid=False)) == {"T1547.001"}
    e["registry_path"] += r"\RunFake"
    assert not supported(engine.map(batch(e), hybrid=False))


def test_scheduled_task_outcome(engine):
    e = event(
        observation_type="scheduled_task",
        event_metadata={"action": "create", "task_action": "example.exe", "platform": "Windows"},
    )
    assert supported(engine.map(batch(e), hybrid=False)) == {"T1053.005"}
    command = event(
        process_name="schtasks.exe", command_line="schtasks.exe /create /tr example.exe /tn demo"
    )
    run = engine.map(batch(command), hybrid=False)
    assert not supported(run) and run.candidate_mappings[0].missing_context


def test_security_control_change(engine):
    e = event(
        observation_type="security_control_change",
        event_metadata={
            "control": "defender",
            "action": "disable",
            "outcome": "success",
            "platform": "Windows",
        },
    )
    assert supported(engine.map(batch(e), hybrid=False)) == {"T1562.001"}


def test_network_c2_requires_attribution(engine):
    e = event(
        observation_type="network_connection",
        network_destination="example.invalid",
        event_metadata={"application_protocol": "https", "c2_channel": True, "platform": "Windows"},
    )
    assert not supported(engine.map(batch(e), hybrid=False))
    e["event_metadata"]["c2_evidence_reference"] = "/detections/3"
    assert supported(engine.map(batch(e), hybrid=False)) == {"T1071.001"}


def test_explicit_file_sequence(engine):
    write = event(
        observation_id="write",
        observation_type="file_write",
        file_path=r"C:\demo.exe",
        timestamp="2026-01-01T00:00:00Z",
    )
    execute = event(
        process_name="demo.exe",
        command_line="demo.exe",
        file_path=r"C:\demo.exe",
        timestamp="2026-01-01T00:00:20Z",
        event_metadata={
            "file_write_observation_id": "write",
            "user_initiated": True,
            "platform": "Windows",
        },
    )
    assert supported(engine.map(batch(write, execute), hybrid=False)) == {"T1204.002"}
    execute["timestamp"] = "2025-12-31T23:00:00Z"
    assert not supported(engine.map(batch(write, execute), hybrid=False))


def test_no_assumed_event_relationship(engine):
    write = event(observation_id="write", observation_type="file_write", file_path=r"C:\demo.exe")
    execute = event(process_name="demo.exe", file_path=r"C:\demo.exe")
    assert not supported(engine.map(batch(write, execute), hybrid=False))


def test_duplicate_event_no_score_inflation(engine):
    first = event(event_metadata={"underlying_event_id": "same", "platform": "Windows"})
    duplicate = event(
        observation_id="o2",
        source_id="other",
        source_reference="/events/2",
        event_metadata=first["event_metadata"],
    )
    single = engine.map(batch(first), hybrid=False).candidate_mappings[0]
    both = engine.map(batch(first, duplicate), hybrid=False).candidate_mappings[0]
    assert single.ranking_score == both.ranking_score


def test_metadata_retrieval_cannot_support(engine):
    run = engine.map(
        batch(event(observation_type="other", description="Synthetic technique T1059")), hybrid=True
    )
    assert run.candidate_mappings and not supported(run)
    assert all(c.mapping_status == "insufficient_evidence" for c in run.candidate_mappings)


def test_parent_specificity(engine):
    e = event(
        process_name="unknown-interpreter",
        command_line="unknown-interpreter run sample",
        event_metadata={"behavior": "command_interpreter_execution", "platform": "Windows"},
    )
    assert supported(engine.map(batch(e), hybrid=False)) == {"T1059"}
    assert supported(engine.map(batch(event()), hybrid=False)) == {"T1059.001"}


def test_inactive_rule_target_rejected(full_catalog):
    full_catalog["techniques"]["T1059.001"]["revoked"] = True
    engine = Engine(full_catalog, load_rules())
    assert engine.map(batch(event()), hybrid=False).rejected_candidates


def test_rule_catalog_and_config_validation(full_catalog):
    del full_catalog["techniques"]["T1059.001"]
    with pytest.raises(ValueError):
        Engine(full_catalog, load_rules())
    with pytest.raises(ValidationError):
        ScoreConfig(strength_weight=0.9)


def test_independent_verification(engine):
    b = batch(event())
    run = engine.map(b, hybrid=False)
    run.candidate_mappings[0].evidence_ids = ["invented"]
    with pytest.raises(ValueError):
        verify(run, b, engine.catalog)


@pytest.mark.parametrize("format_name", ["sandbox", "endpoint", "incident", "static"])
def test_report_adapters(format_name):
    e = event()
    for key in ["source_type", "source_id", "source_reference"]:
        e.pop(key)
    if format_name == "static":
        e["observation_status"] = "static_indicator"
    result = ingest({"report_id": "r1", "events": [e]}, format_name)
    assert result.observations[0].source_reference == "/events/0"


def test_static_adapter_no_runtime_upgrade():
    e = event()
    for key in ["source_type", "source_id", "source_reference"]:
        e.pop(key)
    with pytest.raises(ValueError):
        ingest({"report_id": "r", "events": [e]}, "static")
