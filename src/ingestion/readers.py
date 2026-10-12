"""Opt-in adapters for documented report envelopes, never report execution."""

from src.schemas.observations import ObservationBatch

FORMATS = ("normalized", "sandbox", "static", "endpoint", "incident")
SOURCES = {
    "sandbox": "sandbox",
    "static": "static_analysis",
    "endpoint": "endpoint_telemetry",
    "incident": "incident_report",
}


def ingest(payload: dict, format_name: str = "normalized") -> ObservationBatch:
    if format_name == "normalized":
        return ObservationBatch.model_validate(payload)
    if format_name not in SOURCES:
        raise ValueError("unsupported input format")
    # This is an explicit interoperable envelope, not a guessed vendor parser.
    if set(payload) - {"schema_version", "report_id", "events", "limitations"}:
        raise ValueError("unknown report envelope fields")
    if payload.get("schema_version", "1.0") != "1.0":
        raise ValueError("unsupported report schema version")
    if not isinstance(payload.get("report_id"), str) or not payload["report_id"].strip():
        raise ValueError("report_id is required")
    if not isinstance(payload.get("events"), list) or len(payload["events"]) > 100000:
        raise ValueError("events must be a bounded list")
    observations = []
    for index, event in enumerate(payload["events"]):
        if not isinstance(event, dict):
            raise TypeError("event must be an object")
        record = dict(event)
        for field in ("source_type", "source_id", "source_reference"):
            if field in record:
                raise ValueError("envelope provenance cannot be overridden")
        record.update(
            source_type=SOURCES[format_name],
            source_id=payload["report_id"],
            source_reference=f"/events/{index}",
        )
        # Static provenance remains static even if report strings assert execution.
        if format_name == "static":
            if record.get("observation_status", "static_indicator") != "static_indicator":
                raise ValueError("static adapter requires static_indicator status")
            record["observation_status"] = "static_indicator"
        record["limitations"] = list(record.get("limitations", [])) + payload.get("limitations", [])
        observations.append(record)
    return ObservationBatch.model_validate({"observations": observations})
