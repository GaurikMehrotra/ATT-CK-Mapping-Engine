"""Structured predicates; isolated network/file events do not prove intent."""

import re
from dataclasses import dataclass

from src.normalization.events import basename, command_tokens, windows_path


@dataclass
class RuleMatch:
    technique_id: str
    evidence_ids: list[str]
    rule_id: str
    strength: float
    missing: list[str]
    rationale: str
    limitations: list[str]
    method: str = "deterministic_rule"


def evaluate_rule(rule, observation, by_id, window):
    o = observation
    if o.observation_type not in rule.observation_types:
        return []
    meta = o.event_metadata
    process = basename(o.process_name)
    tokens = command_tokens(o.command_line)
    matched, strength, missing, evidence = False, 1.0, [], [o.observation_id]
    handler = rule.handler
    if handler in {"powershell", "cmd", "unix_shell"}:
        names = {
            "powershell": {"powershell.exe", "powershell", "pwsh", "pwsh.exe"},
            "cmd": {"cmd.exe", "cmd"},
            "unix_shell": {"sh", "bash", "dash", "zsh", "ksh"},
        }
        matched = process in names[handler]
        invocation = {
            "powershell": {"-command", "-c", "-file", "-f", "-encodedcommand", "-enc", "-e"},
            "cmd": {"/c", "/k"},
            "unix_shell": {"-c"},
        }
        if matched:
            valid_invocation = any(
                t in invocation[handler] and i + 1 < len(tokens) for i, t in enumerate(tokens)
            )
            # Unix script path invocation is also explicit, without requiring -c.
            valid_invocation |= (
                handler == "unix_shell" and len(tokens) > 1 and not tokens[1].startswith("-")
            )
            if not valid_invocation:
                missing.append("Command or script execution arguments")
                strength = 0.5
    elif handler == "interpreter":
        matched = meta.get("behavior") == "command_interpreter_execution" and process not in {
            "powershell.exe",
            "powershell",
            "pwsh",
            "pwsh.exe",
            "cmd.exe",
            "cmd",
            "sh",
            "bash",
            "dash",
            "zsh",
            "ksh",
        }
        if matched and not o.command_line:
            missing.append("Command line identifying the interpreter and execution")
            strength = 0.5
    elif handler == "autorun":
        path = windows_path(o.registry_path)
        matched = bool(
            re.fullmatch(
                r"(?:hkey_current_user|hkey_local_machine|hkcu|hklm)\\software\\(?:wow6432node\\)?microsoft\\windows\\currentversion\\(?:run|runonce)(?:\\[^\\]+)?",
                path,
            )
        )
        if matched and meta.get("action") not in {"set_value", "create_value"}:
            missing.append("Successful registry value creation/modification action")
            strength = 0.5
        if matched and not meta.get("registry_value_data"):
            missing.append("Registry value data identifying startup command")
    elif handler == "scheduled_task":
        matched = (o.observation_type == "scheduled_task" and meta.get("action") == "create") or (
            process in {"schtasks.exe", "schtasks"} and "/create" in tokens
        )
        if matched and not (
            meta.get("task_action") or ("/tr" in tokens and tokens.index("/tr") + 1 < len(tokens))
        ):
            missing.append("Task executable/action")
        if matched and o.observation_type == "process_creation":
            missing.append("Task creation result; command invocation alone does not prove success")
            strength = 0.65
    elif handler in {"defender", "firewall"}:
        matched = (
            o.observation_type == "security_control_change"
            and meta.get("control")
            in ({"firewall"} if handler == "firewall" else {"antivirus", "edr", "defender"})
            and meta.get("action") in {"disable", "stop", "uninstall"}
        )
        if matched and meta.get("outcome") != "success":
            missing.append("Successful security-control change result")
    elif handler == "file_execution":
        linked_id = meta.get("file_write_observation_id")
        linked = by_id.get(linked_id)
        matched = bool(linked and linked.observation_type == "file_write")
        if matched:
            evidence.append(linked_id)
            if (
                not o.file_path
                or not linked.file_path
                or (
                    o.file_path
                    if meta.get("platform") in {"Linux", "macOS"}
                    else windows_path(o.file_path)
                )
                != (
                    linked.file_path
                    if meta.get("platform") in {"Linux", "macOS"}
                    else windows_path(linked.file_path)
                )
            ):
                missing.append("Same explicitly linked written/executed file path")
            if not o.timestamp or not linked.timestamp:
                missing.append("Timestamps to validate event ordering")
            elif not 0 <= (o.timestamp - linked.timestamp).total_seconds() <= window:
                missing.append("File-write-before-execution within correlation window")
            if meta.get("user_initiated") is not True:
                missing.append(
                    "User action; a file write and execution alone do not prove user execution"
                )
            if linked.source_id != o.source_id and (
                not meta.get("correlation_id")
                or linked.event_metadata.get("correlation_id") != meta["correlation_id"]
            ):
                missing.append("Cross-source correlation identifier")
    elif handler == "http_c2":
        matched = (
            meta.get("application_protocol") in {"http", "https"} and meta.get("c2_channel") is True
        )
        if matched and not meta.get("c2_evidence_reference"):
            missing.append("Source evidence explaining command-and-control channel attribution")
        if matched and not o.network_destination:
            missing.append("Network destination")
    if not matched:
        return []
    if (
        o.observation_type == "process_creation"
        and process
        and tokens
        and basename(tokens[0]) != process
    ):
        missing.append("Process name and command-line executable disagree")
    for field in rule.required_fields:
        if not getattr(o, field, None):
            missing.append(f"Required field: {field}")
    return [
        RuleMatch(
            tid,
            evidence,
            rule.rule_id + "@" + rule.version,
            strength,
            sorted(set(missing)),
            rule.rationale,
            rule.limitations,
        )
        for tid in rule.technique_ids
    ]
