"""JSON audit records and escaped Markdown, organized under every associated tactic."""

from collections import defaultdict
from pathlib import Path


def escape(text):
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("`", "&#96;")
        .replace("[", "&#91;")
        .replace("]", "&#93;")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("*", "\\*")
        .replace("_", "\\_")
        .replace("|", "\\|")
    )


def markdown(run):
    lines = [
        "# ATT&CK mapping report",
        "",
        f"Run: {run.mapping_run_id}",
        f"Catalog: {escape(run.catalog_version)}; rules: {escape(run.rule_set_version)}",
        "",
        "Scores are heuristic rankings, not probabilities. Supported candidates do not establish malicious intent.",
        "",
    ]
    groups = defaultdict(list)
    for c in run.candidate_mappings:
        for tactic in c.associated_tactics or ["unassigned"]:
            groups[tactic].append(c)
    for tactic, candidates in sorted(groups.items()):
        lines.extend([f"## {escape(tactic)}", ""])
        for c in candidates:
            lines.extend(
                [
                    f"### {c.technique_id}: {escape(c.technique_name)}",
                    "",
                    f"Status: {c.mapping_status.value}; ranking: {c.ranking_score:.3f}",
                    f"Mapping ID: {c.mapping_id}; catalog object: {c.catalog_stix_id}",
                    "",
                ]
            )
            for label, values in [
                ("Rationale", c.supporting_rationale),
                ("Missing context", c.missing_context),
                ("Contradictions", c.contradictions),
                ("Limitations", c.limitations),
            ]:
                lines.append(
                    f"{label}: " + ("; ".join(escape(v) for v in values) or "none recorded")
                )
            lines.extend(["", "Evidence:", ""])
            for ref in c.evidence_references:
                lines.append(
                    f"- {escape(ref.observation_id)} — {escape(ref.source_id)}:{escape(ref.source_reference)} ({ref.observation_status})"
                )
            if c.llm_rationale:
                lines.extend(["", f"Optional model selection: {escape(c.llm_rationale)}"])
            lines.extend(
                [
                    "",
                    "Scoring factors: " + escape(str(c.scoring_factors)),
                    "",
                    "Rules: " + escape(", ".join(c.rule_ids)),
                    "",
                ]
            )
    lines.extend(["## Rejected candidates", ""])
    for c in run.rejected_candidates:
        lines.append(f"- {c.technique_id} ({c.mapping_id}): " + escape("; ".join(c.contradictions)))
    lines.extend(
        [
            "",
            "## Unmapped observations",
            "",
            escape(", ".join(run.unmapped_observations)) or "none",
            "",
            "## Warnings",
            "",
        ]
    )
    lines.extend(f"- {escape(w)}" for w in run.warnings)
    return "\n".join(lines) + "\n"


def write_reports(run, directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"{run.mapping_run_id}.json"
    md_path = directory / f"{run.mapping_run_id}.md"
    # Unique run IDs plus exclusive creation preserve existing report files.
    with json_path.open("x") as f:
        f.write(run.model_dump_json(indent=2) + "\n")
    with md_path.open("x") as f:
        f.write(markdown(run))
    return json_path, md_path
