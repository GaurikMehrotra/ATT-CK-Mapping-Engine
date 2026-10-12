"""Comparison helpers leave original observations and command strings intact."""

import re


def basename(path: str | None) -> str:
    return (path or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()


def windows_path(path: str | None) -> str:
    return (path or "").replace("/", "\\").casefold().rstrip("\\")


def command_tokens(command: str | None) -> list[str]:
    # Token inspection only. Never shell evaluation, expansion or execution.
    return [
        t.strip("\"'").casefold()
        for t in re.findall(r'"[^"\n]*"|\'[^\'\n]*\'|[^\s]+', command or "")
    ]


def event_key(observation) -> str:
    explicit = observation.event_metadata.get("underlying_event_id")
    return (
        f"event:{explicit}"
        if explicit
        else f"source:{observation.source_id}:{observation.source_reference}"
    )
