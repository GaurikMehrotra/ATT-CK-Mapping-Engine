# Implementation milestones

| Phase | Deliverables | Validation |
|---|---|---|
| 0 Audit | Empty checkout, Python 3.12; no reusable modules or unrelated files | Git status and filesystem inspection |
| 1 Catalog/schema | `src/catalog`, `src/schemas/observations.py`, catalog CLI, synthetic fixtures | 24 tests; official 18.0 import, 835 records, offline query |
| 2 Rules | `rules/default.json`, `src/rules`, engine candidate pipeline | Behavioral predicates, missing context, abstention, parent specificity |
| 3 Context/ranking | `src/evidence`, `src/ranking`, normalization, config, verification | Explicit sequence links, contradictory outcomes, source independence and duplicate events; combined suite reached 53 tests |
| 4 Reports/CLI | `src/reporting`, map/explain/rules commands, output schemas | Saved JSON round trip, Markdown escaping/multi-tactic output, CLI end to end |
| 5 Evaluation | `src/evaluation`, annotated manifest, metrics and measured results | Three configurations, arithmetic/alternative-label tests, 24 synthetic development scenarios |
| 6 Optional model | `src/llm/ollama.py` | Valid mocked selection, malformed/invented claims, prompt injection, timeout, unavailable endpoint; combined suite reached 80 tests |
| 7 Hardening | Structural JSON/STIX checks, independent verification, exported schemas, CI, documentation | 114 passing tests, Ruff lint/format, dependency checks, wheel installation, official/offline CLI demonstrations and actual unavailable-model fallback |

Remaining product/research extensions: native vendor-specific parsers, wider behavioral rules, additional ATT&CK domains, independently annotated real telemetry and calibration. Live Ollama inference was not exercised because no local model/service is installed. The adapter and deterministic fallback are implemented and tested. No commits or pushes were performed.
