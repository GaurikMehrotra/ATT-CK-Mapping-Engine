"""Validated STIX storage with atomic replacement and offline queries."""

import hashlib
import json
import math
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

MAX_BYTES = 100 * 1024 * 1024


class CatalogError(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("duplicate JSON object key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise CatalogError(f"nonfinite JSON constant: {value}")


def read_json(path: Path, max_bytes: int = MAX_BYTES) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise CatalogError("input exceeds size limit")
    try:
        result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, RecursionError) as exc:
        raise CatalogError("invalid JSON input") from exc
    if not isinstance(result, dict):
        raise CatalogError("expected a JSON object")
    stack = [(result, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > 64:
            raise CatalogError("JSON nesting exceeds 64 levels")
        if isinstance(value, float) and not math.isfinite(value):
            raise CatalogError("nonfinite JSON number")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return result


def _validate_object_shape(obj):
    if not isinstance(obj.get("type"), str):
        raise CatalogError("object type must be a string")
    try:
        UUID(obj["id"].split("--", 1)[1])
    except (ValueError, IndexError) as exc:
        raise CatalogError("invalid STIX UUID") from exc
    for key in ("revoked", "x_mitre_deprecated", "x_mitre_is_subtechnique"):
        if key in obj and not isinstance(obj[key], bool):
            raise CatalogError(f"{key} must be boolean")
    for key in ("name", "description", "x_mitre_detection", "x_mitre_version"):
        if key in obj and not isinstance(obj[key], str):
            raise CatalogError(f"{key} must be text")
    for key in ("x_mitre_domains", "x_mitre_platforms", "x_mitre_data_sources"):
        if key in obj and (
            not isinstance(obj[key], list) or not all(isinstance(v, str) for v in obj[key])
        ):
            raise CatalogError(f"{key} must be a string list")
    for key in ("external_references", "kill_chain_phases"):
        if key in obj and (
            not isinstance(obj[key], list) or not all(isinstance(v, dict) for v in obj[key])
        ):
            raise CatalogError(f"{key} must be an object list")
    for ref in obj.get("external_references", []):
        if not isinstance(ref.get("source_name"), str):
            raise CatalogError("external reference requires source_name")
        if "external_id" in ref and not isinstance(ref["external_id"], str):
            raise CatalogError("external_id must be text")
    for phase in obj.get("kill_chain_phases", []):
        if not all(isinstance(phase.get(k), str) for k in ("kill_chain_name", "phase_name")):
            raise CatalogError("invalid kill-chain phase")


def _references(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith("_ref"):
                if not isinstance(item, str):
                    raise CatalogError("STIX object reference must be text")
                if key.startswith("x_mitre_") and not item:
                    continue  # Official releases use empty optional custom references.
                yield item
            elif key.endswith("_refs"):
                if not isinstance(item, list) or not all(isinstance(ref, str) for ref in item):
                    raise CatalogError("STIX object references must be a string list")
                yield from item
            else:
                yield from _references(item)
    elif isinstance(value, list):
        for item in value:
            yield from _references(item)


def validate_bundle(bundle: dict) -> tuple[dict, dict]:
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise CatalogError("expected a STIX bundle with objects")
    objects = {}
    for obj in bundle["objects"]:
        if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
            raise CatalogError("every object must have a STIX ID")
        _validate_object_shape(obj)
        if not obj.get("type") or not obj["id"].startswith(obj["type"] + "--"):
            raise CatalogError("object type and STIX ID disagree")
        if obj.get("spec_version") != "2.1":
            raise CatalogError("only STIX 2.1 objects are supported")
        if obj["id"] in objects:
            raise CatalogError("duplicate STIX object ID")
        objects[obj["id"]] = obj
    for obj in objects.values():
        for ref in _references(obj):
            if not isinstance(ref, str) or ref not in objects:
                raise CatalogError(f"unresolved STIX reference in {obj['id']}")
        if obj["type"] == "relationship" and not all(
            obj.get(k) for k in ("source_ref", "target_ref", "relationship_type")
        ):
            raise CatalogError("incomplete relationship")
    techniques = {}
    for obj in objects.values():
        if obj["type"] != "attack-pattern":
            continue
        if "enterprise-attack" not in obj.get("x_mitre_domains", []):
            continue
        ids = [
            r.get("external_id", "")
            for r in obj.get("external_references", [])
            if r.get("source_name") == "mitre-attack"
        ]
        if len(ids) != 1 or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", ids[0]):
            raise CatalogError("invalid or missing ATT&CK technique ID")
        tid = ids[0]
        if tid in techniques or not obj.get("name") or not obj.get("description"):
            raise CatalogError("duplicate technique or missing name/description")
        child = "." in tid
        if child != bool(obj.get("x_mitre_is_subtechnique", False)):
            raise CatalogError("sub-technique identifier and flag disagree")
        parents = [
            objects[r["target_ref"]]
            for r in objects.values()
            if r["type"] == "relationship"
            and r["relationship_type"] == "subtechnique-of"
            and r["source_ref"] == obj["id"]
        ]
        historical = bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))
        if (child and len(parents) != 1 and not (historical and not parents)) or (
            not child and parents
        ):
            raise CatalogError("invalid sub-technique parent relationship")
        parent_id = None
        if parents:
            parent = parents[0]
            parent_ids = [
                r.get("external_id")
                for r in parent.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ]
            if parent["type"] != "attack-pattern" or parent_ids != [tid.split(".")[0]]:
                raise CatalogError("parent does not match sub-technique")
            if "enterprise-attack" not in parent.get("x_mitre_domains", []):
                raise CatalogError("parent belongs to another domain")
            parent_id = parent_ids[0]
        techniques[tid] = {
            "technique_id": tid,
            "stix_id": obj["id"],
            "name": obj["name"],
            "description": obj["description"],
            "parent_id": parent_id,
            "warnings": ["Historical sub-technique has no parent relationship"]
            if child and not parents
            else [],
            "tactics": sorted(
                {
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack"
                }
            ),
            "platforms": obj.get("x_mitre_platforms", []),
            "data_sources": obj.get("x_mitre_data_sources", []),
            "detection": obj.get("x_mitre_detection", ""),
            "references": obj.get("external_references", []),
            "object_version": obj.get("x_mitre_version"),
            "revoked": bool(obj.get("revoked", False)),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "mitigations": [
                r["source_ref"]
                for r in objects.values()
                if r["type"] == "relationship"
                and r["relationship_type"] == "mitigates"
                and r["target_ref"] == obj["id"]
            ],
        }
    if not techniques:
        raise CatalogError("no Enterprise ATT&CK techniques found")
    return objects, techniques


class Catalog:
    def __init__(self, path: Path):
        self.path = path

    def import_bundle(self, source: Path, version: str, synthetic: bool = False) -> dict:
        if not version.strip():
            raise CatalogError("explicit catalog version is required")
        bundle = read_json(source)
        objects, techniques = validate_bundle(bundle)
        collections = [
            o
            for o in objects.values()
            if o["type"] == "x-mitre-collection" and o.get("name") == "Enterprise ATT&CK"
        ]
        release_versions = {
            o.get("x_mitre_version") for o in collections if o.get("x_mitre_version")
        }
        if release_versions and release_versions != {version}:
            raise CatalogError(
                "declared catalog version disagrees with Enterprise collection metadata"
            )
        digest = hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest()
        metadata = {
            "schema_version": "1.0",
            "domain": "enterprise-attack",
            "catalog_version": version,
            "imported_at": datetime.now(UTC).isoformat(),
            "source_file": source.name,
            "source_bundle_id": bundle.get("id"),
            "version_verified_from_collection": bool(release_versions),
            "source_sha256": digest,
            "synthetic": synthetic,
            "technique_count": len(techniques),
        }
        payload = {"metadata": metadata, "objects": objects, "techniques": techniques}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        name = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=self.path.parent, delete=False) as f:
                name = f.name
                json.dump(payload, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, self.path)
        finally:
            if name and os.path.exists(name):
                os.unlink(name)
        return metadata

    def load(self) -> dict:
        return read_json(self.path)

    def info(self) -> dict:
        return self.load()["metadata"]

    def query(self, technique_id: str | None = None, include_inactive: bool = False) -> list:
        records = self.load()["techniques"].values()
        return [
            t
            for t in records
            if (technique_id is None or t["technique_id"] == technique_id)
            and (include_inactive or not (t["revoked"] or t["deprecated"]))
        ]
