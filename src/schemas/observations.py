"""Versioned observations; provenance never implies runtime execution."""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EventContext(BaseModel):
    """Validate known context without discarding vendor-specific JSON metadata."""

    model_config = ConfigDict(extra="allow", strict=True, allow_inf_nan=False)
    platform: str | None = None
    source_reliability: float = Field(default=0.7, ge=0, le=1)
    underlying_event_id: str | None = Field(default=None, min_length=1)
    independent_source_id: str | None = Field(default=None, min_length=1)
    action: str | None = None
    outcome: str | None = None
    behavior: str | None = None
    task_action: str | None = None
    registry_value_data: str | None = None
    control: str | None = None
    file_write_observation_id: str | None = None
    correlation_id: str | None = None
    user_initiated: bool | None = None
    application_protocol: str | None = None
    c2_channel: bool | None = None
    c2_evidence_reference: str | None = None
    contradicts_observation_ids: list[str] = Field(default_factory=list)


Text = Annotated[str, Field(min_length=1, max_length=8192)]


class ObservationStatus(StrEnum):
    DIRECT = "directly_observed"
    REPORTED = "source_reported"
    STATIC = "static_indicator"
    INFERRED = "inferred"
    HYPOTHESIS = "analyst_hypothesis"


class ObservationType(StrEnum):
    PROCESS = "process_creation"
    FILE = "file_write"
    REGISTRY = "registry_modification"
    TASK = "scheduled_task"
    NETWORK = "network_connection"
    DNS = "dns_request"
    CONTROL = "security_control_change"
    STATIC = "static_indicator"
    OTHER = "other"


class SourceType(StrEnum):
    SANDBOX = "sandbox"
    STATIC = "static_analysis"
    ENDPOINT = "endpoint_telemetry"
    INCIDENT = "incident_report"
    ANALYST = "analyst"


class Observation(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    schema_version: Literal["1.0"] = "1.0"
    observation_id: Text
    observation_type: ObservationType
    description: Text
    source_type: SourceType
    source_id: Text
    source_reference: Text
    observation_status: ObservationStatus
    timestamp: datetime | None = None
    process_name: Text | None = None
    process_id: Annotated[int, Field(strict=True, ge=0)] | None = None
    parent_process_id: Annotated[int, Field(strict=True, ge=0)] | None = None
    command_line: Text | None = None
    file_path: Text | None = None
    registry_path: Text | None = None
    network_destination: Text | None = None
    event_metadata: dict[str, Any] = Field(default_factory=dict)
    limitations: list[Text] = Field(default_factory=list)

    @field_validator("event_metadata")
    @classmethod
    def validate_context(cls, value):
        EventContext.model_validate(value)
        return value

    @field_validator("timestamp")
    @classmethod
    def timezone_required(cls, value):
        if value is not None and value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value

    @model_validator(mode="after")
    def preserve_static_provenance(self):
        if (
            self.source_type == SourceType.STATIC or self.observation_type == ObservationType.STATIC
        ) and self.observation_status == ObservationStatus.DIRECT:
            raise ValueError("static indicators cannot be directly observed runtime events")
        return self


class ObservationBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    observations: list[Observation] = Field(max_length=100000)

    @model_validator(mode="after")
    def unique_ids(self):
        ids = [o.observation_id for o in self.observations]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate observation IDs")
        known = set(ids)
        for o in self.observations:
            refs = list(o.event_metadata.get("contradicts_observation_ids", []))
            if o.event_metadata.get("file_write_observation_id"):
                refs.append(o.event_metadata["file_write_observation_id"])
            if set(refs) - known or o.observation_id in refs:
                raise ValueError("context references must identify other observations in the batch")
        return self
