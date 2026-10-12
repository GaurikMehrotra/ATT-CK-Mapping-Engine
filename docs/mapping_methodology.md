# Mapping methodology

## Candidate generation

Ten allowlisted, versioned behavioral handlers cover PowerShell (T1059.001), Windows command shell (T1059.003), Unix shell (T1059.004), generic interpreter (T1059), registry Run/RunOnce (T1547.001), Windows scheduled task (T1053.005), tool impairment (T1562.001), firewall impairment (T1562.004), explicitly linked user file execution (T1204.002), and attributed HTTP/HTTPS C2 (T1071.001). IDs, names, tactics and platform metadata resolve against the loaded catalog. Invalid handler/target substitutions fail rule validation.

Rules inspect event types, exact executable basenames, argument tokens, anchored registry paths and typed metadata. Definitions record required fields, optional context, conditions, limitations and weakening conditions. The keyword matcher exists only in evaluation. Offline TF-IDF retrieval uses names, descriptions, detection text and legacy data sources, returning up to three candidates per observation with cosine similarity at least 0.08. Metadata retrieval is not behavioral proof and never elevates status.

## Context and evidence

The engine never assumes that same-report events are related. File-write/execution requires an explicit event link, same file path, ordered timestamps within the configured 300-second window, and user action; cross-source linking also requires matching correlation IDs. Windows comparisons are case-insensitive; Linux/macOS file paths remain case-sensitive. Process executable and command-line executable disagreements block support.

Evidence IDs resolve to source ID, original reference, source type, directness and underlying-event key. Duplicate upstream event IDs do not increase agreement. Distinct collection sources earn a bonus only when explicitly declared independent and correlated to the same behavior instance. Independence and source reliability are operator/source claims, not authenticated facts.

Direct/reported contradictions, failed/blocked outcomes, incompatible known platforms and inactive catalog objects reject support. Inferred contrary claims add unresolved context and prevent supported status. Static, inferred and hypothetical evidence cannot support runtime execution. An unknown platform is visible as a limitation; it does not force rejection when the defining event is otherwise supported.

## Statuses and abstention

- `supported_candidate`: defining runtime/reported behavior, no contradiction, and score above threshold; intent still uncertain.
- `weak_candidate`: a behavioral match with missing defining context or lower score.
- `insufficient_evidence`: retrieval-only, nonruntime or too little evidence.
- `rejected`: contradiction, inactive catalog record, or redundant parent.
- `analyst_confirmed`: schema-reserved for external analyst workflows; automated mapping never emits it.

An observation is unmapped unless it supports at least one supported candidate. Runs can retain weak/retrieved candidates while abstaining. Empty input also yields an explicit abstention warning. No child is selected merely to satisfy specificity: generic interpreter evidence can return the parent; supported child evidence suppresses a redundant parent over the same evidence. Distinct parent/child behaviors with different evidence remain separate. Multi-tactic records appear under each tactic in Markdown with the same mapping ID.

## Score 1.0

A configurable weighted sum is clamped to [0,1]. Defaults:

| Factor | Weight/input |
|---|---|
| Behavioral match | 0.40 × rule strength (typically 1, incomplete launch 0.5, task invocation 0.65, metadata-only 0.2) |
| Observation directness | 0.25 × direct 1, reported 0.7, inferred 0.3, static 0.15, hypothesis 0.1; conservative minimum over required evidence |
| Defining context completeness | 0.15 × 1 if no defining gap, otherwise 0 |
| Declared source reliability | 0.10 × minimum source reliability (default 0.7) |
| Independent agreement | 0.10 for at least two explicitly independent sources with distinct underlying events, otherwise 0 |
| Contradiction | subtract 0.50 if contradictory |

Supported threshold is 0.70; weak threshold is 0.40. Weights must sum to one. Missing defining context, absent behavioral rules or contradictions impose hard status gates regardless of score. Unknown optional platform context is listed separately from defining gaps. Metadata candidates do not strengthen or weaken rule-supported candidates. Each output records factors, score configuration/version, explanation, gaps, source references, limitations and rule versions. These are heuristic rankings, never probabilities. No calibration or maliciousness classifier has been trained.

Final verification checks catalog metadata, provenance, factor arithmetic, threshold, observation directness, and independently replays a defining rule before allowing supported status.
