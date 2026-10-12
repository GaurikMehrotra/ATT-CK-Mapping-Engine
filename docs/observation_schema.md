# Observation schema 1.0

Each batch is an object with `schema_version: "1.0"` and `observations`. Exported JSON schemas live under `data/schemas`; runtime validators additionally enforce provenance, reference resolution and uniqueness.

| Field | Meaning |
|---|---|
| observation_id | Unique, nonempty batch-local evidence ID |
| observation_type | process_creation, file_write, registry_modification, scheduled_task, network_connection, dns_request, security_control_change, static_indicator, other |
| description | Source description; not executable instructions or proof by itself |
| source_type | sandbox, static_analysis, endpoint_telemetry, incident_report, analyst |
| source_id | Original report/source identity |
| source_reference | Original event pointer/report location; never fetched automatically |
| observation_status | Required: directly_observed, source_reported, static_indicator, inferred, analyst_hypothesis |
| timestamp | Optional timezone-aware date/time |
| process_name / process_id / parent_process_id | Optional executable name and nonnegative integer IDs |
| command_line | Optional original command text; inspected as tokens, never executed |
| file_path / registry_path / network_destination | Optional original artifact/context fields; never contacted |
| event_metadata | JSON context object; documented keys are typed, unknown vendor keys retained |
| limitations | Source limitations retained in mapping results |

Text fields are limited to 8,192 characters. Unknown observation fields, unsupported schema versions, duplicate IDs and nonexistent/self-referencing contextual event links fail validation. Static sources/types cannot claim directly observed runtime actions. Schema validation does not authenticate a report or prove its claims.

## Typed contextual keys

- `platform`: canonical catalog platform, e.g. Windows or Linux; unknown platform is reported as missing context.
- `action`, `outcome`: structured event operation and result. `failed`, `blocked`, or `not_observed` contradict successful behavior. Control changes require `success`.
- `source_reliability`: declared heuristic factor in [0,1], default 0.7; not calibrated.
- `underlying_event_id`: global upstream identity used to deduplicate copies.
- `correlation_id`: explicit identifier of the same behavior instance; unrelated events sharing a report are not grouped.
- `independent_source_id`: explicitly declared independent collection source. Source IDs alone never earn an independence bonus.
- `behavior`: `command_interpreter_execution` supports the generic interpreter rule when family is unknown.
- `registry_value_data`: startup command data; autorun action must be `set_value` or `create_value`.
- `task_action`: executable action; scheduled task action must be `create`.
- `control`: antivirus, edr, defender or firewall; disable/stop/uninstall are checked.
- `file_write_observation_id`: explicit batch-local file-write link. User execution also requires `user_initiated: true`, same file, and ordered timestamps within the window. Cross-source links require matching correlation IDs.
- `application_protocol`, `c2_channel`, `c2_evidence_reference`: explicit HTTP/HTTPS channel attribution with a report reference; ordinary HTTP/DNS remains insufficient. Channel attribution is source-supported, not independently authenticated by the engine.
- `contradicts_observation_ids`: explicit IDs contradicted by this event. Direct/reported contrary evidence rejects; unverified contrary claims lower support.

## Example

```json
{"schema_version":"1.0","observations":[{
  "observation_id":"ps-1","observation_type":"process_creation",
  "description":"Endpoint reports command execution",
  "source_type":"endpoint_telemetry","source_id":"report-1",
  "source_reference":"/events/0","observation_status":"directly_observed",
  "process_name":"powershell.exe","command_line":"powershell.exe -Command Get-Date",
  "event_metadata":{"platform":"Windows"}
}]}
```

This supports an interpreter candidate, not a maliciousness judgment. The example command is inert report data.

## Report envelopes

For `--format sandbox|endpoint|incident|static`, supply `{ "schema_version":"1.0", "report_id":"r1", "events":[...] }`, optionally with report-level limitations. Events use observation fields but omit source_type, source_id and source_reference; the adapter owns these fields and records `/events/INDEX`. Runtime envelopes require explicit observation_status. Static envelopes require or default to static_indicator and reject runtime upgrades. These are common documented adapters, not native parsers for Cuckoo, CAPE, commercial sandboxes or arbitrary SIEM formats.
