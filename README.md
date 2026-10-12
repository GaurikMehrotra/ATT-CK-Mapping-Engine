# Evidence-driven MITRE ATT&CK Mapping Engine

A local defensive analysis engine that validates security observations, retrieves candidates from a versioned Enterprise ATT&CK catalog, and assesses which candidates have defensible behavioral evidence. It prioritizes traceability and abstention. It does not execute malware, resolve extracted indicators, or upload reports.

All implementation phases are present: schemas and STIX catalog; deterministic rules; contextual evidence and heuristic ranking; JSON/Markdown reports and CLI; evaluation; optional constrained Ollama assistance; automated hardening checks. Rule coverage is intentionally limited to ten documented behaviors, not every ATT&CK technique.

## Install and test

Python 3.11+; Python 3.12 was validated. Run from the checkout:

```bash
python -m venv /workspace/attack-mapping-venv
source /workspace/attack-mapping-venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pip install --no-deps -e .
python -m pytest -q
ruff check .
ruff format --check .
```

No paid API, GPU, model or service is needed. The lock file records tested development dependency versions; `pyproject.toml` defines supported ranges.

## Explicit official catalog import

Use the official [MITRE attack-stix-data](https://github.com/mitre-attack/attack-stix-data) STIX 2.1 repository. The demonstrated catalog is **Enterprise 18.0**, not a claim to the latest release. Downloads occur only when explicitly requested:

```bash
mkdir -p data/attack_catalog
curl --fail --location https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-18.0.json -o data/attack_catalog/enterprise-attack-18.0.json
python -m src.main catalog import --file data/attack_catalog/enterprise-attack-18.0.json --version 18.0
python -m src.main catalog info
python -m src.main catalog query --technique-id T1059.001
python -m src.main catalog query --include-inactive
python -m src.main rules validate
```

Imports validate before atomic replacement. Release labels must match Enterprise collection metadata when supplied by the bundle. A digest of canonical parsed source content, import time, bundle ID and object versions are recorded. The digest identifies content; it is not an independent release signature. Use separate `--catalog PATH` files to retain multiple releases. Revoked and deprecated records remain available but are excluded from default recommendations.

## Mapping and explanation

```bash
python -m src.main observations validate --file data/observations/demo.json
python -m src.main map --input data/observations/demo.json --no-llm
python -m src.main map --input data/observations/demo.json --mode deterministic --no-llm
python -m src.main explain --mapping-id MAPPING_ID --report reports/RUN_ID.json
python -m src.main evaluate --dataset data/manifests/mapping_test.json
python -m src.main --config configs/default.json rules validate
python -m src.main --help
```

`map` prints the run plus its actual report paths. Substitute IDs printed by the run in `explain`; explanation can also search the default reports directory. `--output-dir DIR` changes the report directory. Global `--catalog`, `--rules` and `--config` options precede subcommands. Evaluation accepts `--k 3`, and `--output PATH` exclusively creates a JSON result file. Existing reports/results are not overwritten.

The demo produces supported PowerShell, Windows command-shell and registry-autorun candidates with observation references. The simple example in `data/observations/example.json` lacks command context and remains unmapped. Hybrid mode adds metadata retrieval; similarity alone never earns supported status. A candidate is an observed behavior hypothesis, not a verdict about malicious intent.

## Fully offline demonstration

The small catalog fixture is explicitly synthetic test text using real technique identifiers. It is not authoritative technique documentation or a research benchmark:

```bash
python -m src.main --catalog /tmp/synthetic-attack-catalog.json catalog import --file data/fixtures/synthetic-enterprise.json --version synthetic-1 --synthetic
python -m src.main --catalog /tmp/synthetic-attack-catalog.json rules validate
python -m src.main --catalog /tmp/synthetic-attack-catalog.json map --input data/observations/demo.json --no-llm
python -m src.main --catalog /tmp/synthetic-attack-catalog.json evaluate --dataset data/manifests/mapping_test.json
```

## Ingestion and schemas

Normalized input: `{ "schema_version": "1.0", "observations": [...] }`. Every observation needs an ID, type, description, source type/ID/reference, and explicit observation status. Optional process, file, registry, network, time and typed context fields refine support. See [observation schema](docs/observation_schema.md) and exported [JSON schemas](data/schemas/observation_batch.schema.json).

`--format sandbox|static|endpoint|incident` accepts a documented envelope with `report_id` and `events` using the same event field names. These interoperable adapters are **not vendor-specific sandbox parsers**. Each preserves provenance as `/events/INDEX`; the static adapter always retains static status. [Examples](data/observations) show normalized and envelope inputs.

## Optional local Ollama

If you already have Ollama and a model, start it with `ollama serve` and provision your chosen model explicitly (for example `ollama pull llama3.2:3b`). Model acquisition is optional and never performed by mapping commands.

```bash
python -m src.main map --input data/observations/demo.json --llm --model llama3.2:3b --llm-timeout 5
```

The endpoint defaults to loopback port 11434; remote endpoints and redirects are forbidden. Assistance returns schema-validated selections from retrieved mapping IDs with exact evidence IDs and allowed rationale codes. The application renders factual prose from its own templates, preventing model-authored invented observations. Assistance never changes ranking, evidence or status. This is intentionally narrower than unrestricted AI rationale generation.

Malformed output, oversized responses, timeouts and an unavailable model preserve deterministic results. The actual local unavailable-model path was verified; no live model inference was run in this environment. Automated tests exercise valid structured responses without a running model.

## Evidence and measured limits

See [methodology](docs/mapping_methodology.md), [architecture](docs/architecture.md), [evaluation](docs/evaluation.md), [measured results](docs/evaluation_results.json), [safety](docs/safety.md), and [milestones](docs/milestones.md). Tests and evaluation use synthetic observations only. Their successful results do not establish real-world accuracy or calibrated confidence. Static indicators do not establish runtime execution; missing telemetry does not establish absence of behavior.
