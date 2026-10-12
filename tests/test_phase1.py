import copy
import json

import pytest
from pydantic import ValidationError

from src.catalog.store import Catalog, CatalogError, read_json, validate_bundle
from src.main import main
from src.schemas.observations import Observation, ObservationBatch


def test_import_query_and_provenance(tmp_path, bundle):
    source = tmp_path / "fixture.json"
    source.write_text(json.dumps(bundle))
    cat = Catalog(tmp_path / "catalog.json")
    meta = cat.import_bundle(source, "synthetic-1", synthetic=True)
    assert meta["catalog_version"] == "synthetic-1"
    assert meta["synthetic"] and meta["imported_at"] and len(meta["source_sha256"]) == 64
    child = cat.query("T1059.001")[0]
    assert child["parent_id"] == "T1059"
    assert child["tactics"] == ["defense-evasion", "execution"]
    assert cat.load()["objects"][child["stix_id"]] == bundle["objects"][1]
    source.unlink()
    assert len(cat.query()) == 2  # Offline, original import file no longer needed.


@pytest.mark.parametrize("flag", ["revoked", "x_mitre_deprecated"])
def test_inactive_retained(tmp_path, bundle, flag):
    bundle["objects"][1][flag] = True
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(bundle))
    cat = Catalog(tmp_path / "catalog.json")
    cat.import_bundle(p, "fixture", True)
    assert not cat.query("T1059.001")
    assert cat.query("T1059.001", include_inactive=True)


@pytest.mark.parametrize("defect", ["reference", "parent", "id", "duplicate", "version", "name"])
def test_bad_catalog_rejected(bundle, defect):
    if defect == "reference":
        bundle["objects"][2]["target_ref"] = "attack-pattern--missing"
    elif defect == "parent":
        bundle["objects"].pop()
    elif defect == "id":
        bundle["objects"][1]["external_references"] = []
    elif defect == "duplicate":
        bundle["objects"].append(copy.deepcopy(bundle["objects"][0]))
    elif defect == "version":
        bundle["objects"][0]["spec_version"] = "2.0"
    else:
        del bundle["objects"][0]["name"]
    with pytest.raises(CatalogError):
        validate_bundle(bundle)


def test_failed_import_preserves_catalog(tmp_path, bundle):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(bundle))
    cat = Catalog(tmp_path / "catalog.json")
    cat.import_bundle(p, "fixture", True)
    before = cat.path.read_bytes()
    p.write_text('{"type":"bundle","objects":[]}')
    with pytest.raises(CatalogError):
        cat.import_bundle(p, "bad")
    assert cat.path.read_bytes() == before


def test_observation_roundtrip(observation):
    o = Observation.model_validate(observation)
    assert o.source_reference == "events/1"
    assert o.model_dump(mode="json")["observation_status"] == "directly_observed"


@pytest.mark.parametrize(
    "change",
    [
        {"source_reference": ""},
        {"observation_status": "confirmed"},
        {"source_type": "static_analysis"},
        {"process_id": -1},
        {"process_id": True},
        {"timestamp": "2026-01-01T00:00:00"},
        {"unexpected": "field"},
        {"schema_version": "2.0"},
    ],
)
def test_invalid_observations(observation, change):
    with pytest.raises(ValidationError):
        Observation.model_validate({**observation, **change})


def test_static_provenance_and_batch(observation):
    static = {
        **observation,
        "source_type": "static_analysis",
        "observation_status": "static_indicator",
    }
    assert Observation.model_validate(static).observation_status == "static_indicator"
    with pytest.raises(ValidationError):
        ObservationBatch.model_validate({"observations": [observation, observation]})


def test_cli(tmp_path, bundle, observation, capsys):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(bundle))
    path = str(tmp_path / "catalog.json")
    assert (
        main(
            [
                "--catalog",
                path,
                "catalog",
                "import",
                "--file",
                str(p),
                "--version",
                "fixture",
                "--synthetic",
            ]
        )
        == 0
    )
    assert main(["--catalog", path, "catalog", "info"]) == 0
    assert main(["--catalog", path, "catalog", "query", "--technique-id", "T1059.001"]) == 0
    p.write_text(json.dumps({"observations": [observation]}))
    assert main(["observations", "validate", "--file", str(p)]) == 0
    assert '"valid_observations": 1' in capsys.readouterr().out


def test_malformed_and_large_input(tmp_path):
    p = tmp_path / "bad.json"
    for text in ["{", "[]"]:
        p.write_text(text)
        with pytest.raises(CatalogError):
            read_json(p)
    p.write_text('{"x":"long"}')
    with pytest.raises(CatalogError):
        read_json(p, max_bytes=5)


def test_official_optional_empty_reference(bundle):
    bundle["objects"][0]["x_mitre_data_source_ref"] = ""
    assert validate_bundle(bundle)[1]["T1059"]


def test_historical_missing_parent_is_explicit(bundle):
    bundle["objects"].pop()
    bundle["objects"][1]["revoked"] = True
    record = validate_bundle(bundle)[1]["T1059.001"]
    assert record["parent_id"] is None and record["warnings"]
