# Reproducible evaluation

The included manifest has **24 agent-authored synthetic development cases**, explicitly labeled before evaluation with expected technique sets, source-evidence IDs, ambiguity flags and annotation notes. Cases cover each rule, negative/incomplete observations, static indicators, contradictory results, related sequences and multi-label behavior. There is no real-world labeled dataset, independent human review, annotator agreement study or held-out benchmark. This suite is a regression demonstration, not validation of the research hypothesis.

```bash
python -m src.main evaluate --dataset data/manifests/mapping_test.json --k 3
```

Measured per-case results and runtime are stored in `docs/evaluation_results.json`. Runtime excludes initial catalog loading/metadata-index construction and measures each evaluation configuration's per-case processing.

## Configurations

1. Keyword baseline: unrestricted case-insensitive substring matching over descriptions and selected fields. Exact keyword/ID pairs are in `src/evaluation/runner.py`; these broad matches deliberately receive no source-evidence validation.
2. Deterministic contextual mapper: structured rules, context, contradictions, ranking and final verification.
3. Hybrid: the same mapper plus local metadata retrieval, and optional local selection when explicitly enabled. The saved measurement used no LLM.

Supported final labels are measured separately from retrieved candidates (which include weak/insufficient suggestions). The included data were designed around implemented rules, so perfect final-label scores are expected regression outcomes and cannot be generalized. Hybrid retrieves more uncertain candidates; this lowers raw retrieval precision without changing the supported final results.

## Annotation protocol for additional data

Annotators should read original telemetry and the pinned catalog, label acceptable technique alternatives, record defining evidence and gaps, and explicitly mark ambiguous/negative cases. Positive labels must cite input observation IDs. Independent review and disagreement resolution are required for research-quality conclusions. Freeze annotations and cutoff before running comparisons. Keep calibration/development and held-out evaluation sources separate. The manifest schema supports `acceptable_sets`; choose the closest predeclared acceptable set by symmetric difference, with deterministic lexical tie-breaking. An explicit empty set represents justified abstention. Labels absent from the loaded catalog fail evaluation.

## Metrics and denominators

- Candidate precision/recall: correct retrieved label memberships divided by retrieved/reference memberships; candidate recall@k uses the first k retrieved labels.
- Final set precision/recall and micro-F1: aggregate TP/(TP+FP), TP/(TP+FN), 2TP/(2TP+FP+FN).
- Macro-label F1: unweighted mean label F1 over the union of reference/predicted labels. This is a multi-label metric; no single-label accuracy claim is made.
- Precision@k: per-case correct final labels in the first k / k, then mean across all cases; empty/unfilled slots count against precision.
- Recall@k: per-case recovered reference labels in the first k / reference-label count, then mean across all cases.
- Exact match: cases whose final label set equals an accepted reference set / cases.
- Unsupported rate: final predictions lacking an annotated supporting evidence set in their emitted references / final predictions. The keyword baseline has no evidence references, so its rate is 1 even for some correct IDs; this measures evidentiary support, not just label correctness.
- Abstention: cases with no supported final predictions / cases.
- Evidence completeness: final predicted labels with emitted resolvable references / final predicted labels.
- Runtime: sum of measured case durations / total observations.
- Ambiguous-case exact match: accepted final-set matches among cases marked ambiguous / ambiguous cases.

Duplicate technique predictions within a case collapse to one label; evidence is unioned for that label. Empty denominators return zero, explicitly recorded in output; inspect counts rather than interpreting zero as quality. All retrieved/reference/predicted counts, per-case predictions and score configuration are retained.

## Measured development outcomes

| Configuration | Final precision | Final recall | Micro-F1 | Exact set match | Evidence completeness |
|---|---:|---:|---:|---:|---:|
| Keyword | 0.400 | 0.833 | 0.541 | 0.417 | 0.000 |
| Deterministic | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| Hybrid, no LLM | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |

These numbers apply only to the included synthetic development cases. No real-world improvement, statistical significance or model calibration is claimed. Missing telemetry, source assertions, narrow rule coverage, overlapping development/test scenarios and single-agent annotation limit validity.
