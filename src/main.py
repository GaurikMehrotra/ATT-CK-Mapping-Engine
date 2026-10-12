"""Offline evidence-driven ATT&CK mapping, catalog management and evaluation."""

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from src.catalog.store import Catalog, CatalogError, read_json
from src.engine import Engine
from src.evaluation.runner import Dataset, evaluate
from src.ingestion.readers import FORMATS, ingest
from src.llm.ollama import Ollama
from src.reporting.reports import write_reports
from src.rules.definitions import load_rules
from src.schemas.mappings import MappingRun, ScoreConfig


def add_llm_options(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--llm", action="store_true", help="Opt in to local Ollama assistance")
    group.add_argument(
        "--no-llm", action="store_true", help="Explicit deterministic-only operation (default)"
    )
    parser.add_argument("--model", default="llama3.2:3b")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    parser.add_argument("--llm-timeout", type=float, default=5)


def explain(mapping_id, report=None, directory=Path("reports")):
    paths = [report] if report else sorted(directory.glob("*.json"))
    for path in paths:
        run = MappingRun.model_validate(read_json(path))
        for candidate in [*run.candidate_mappings, *run.rejected_candidates]:
            if candidate.mapping_id == mapping_id:
                return {
                    "mapping_run_id": run.mapping_run_id,
                    "catalog_version": run.catalog_version,
                    **candidate.model_dump(mode="json"),
                }
    raise ValueError("Mapping ID not found; specify --report for a particular saved run")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=Path("data/attack_catalog/catalog.json"))
    parser.add_argument("--rules", type=Path, help="JSON rule set (allowlisted handlers only)")
    parser.add_argument("--config", type=Path, help="JSON scoring configuration")
    commands = parser.add_subparsers(dest="command", required=True)
    cat = commands.add_parser("catalog").add_subparsers(dest="operation", required=True)
    imp = cat.add_parser("import")
    imp.add_argument("--file", type=Path, required=True)
    imp.add_argument("--version", required=True)
    imp.add_argument("--synthetic", action="store_true")
    cat.add_parser("info")
    query = cat.add_parser("query")
    query.add_argument("--technique-id")
    query.add_argument("--include-inactive", action="store_true")
    validate = commands.add_parser("observations").add_subparsers(dest="operation", required=True)
    obs = validate.add_parser("validate")
    obs.add_argument("--file", type=Path, required=True)
    obs.add_argument("--format", choices=FORMATS, default="normalized")
    mapper = commands.add_parser("map")
    mapper.add_argument("--input", type=Path, required=True)
    mapper.add_argument("--format", choices=FORMATS, default="normalized")
    mapper.add_argument("--mode", choices=["deterministic", "hybrid"], default="hybrid")
    mapper.add_argument("--output-dir", type=Path, default=Path("reports"))
    add_llm_options(mapper)
    explanation = commands.add_parser("explain")
    explanation.add_argument("--mapping-id", required=True)
    explanation.add_argument("--report", type=Path)
    explanation.add_argument("--reports-dir", type=Path, default=Path("reports"))
    evaluator = commands.add_parser("evaluate")
    evaluator.add_argument("--dataset", type=Path, required=True)
    evaluator.add_argument("--k", type=int, default=3)
    evaluator.add_argument("--output", type=Path)
    add_llm_options(evaluator)
    commands.add_parser("rules").add_subparsers(dest="operation", required=True).add_parser(
        "validate"
    )
    args = parser.parse_args(argv)
    try:
        catalog = Catalog(args.catalog)
        if args.command == "catalog":
            if args.operation == "import":
                result = catalog.import_bundle(args.file, args.version, args.synthetic)
            elif args.operation == "info":
                result = catalog.info()
            else:
                result = catalog.query(args.technique_id, args.include_inactive)
        elif args.command == "observations":
            batch = ingest(read_json(args.file), args.format)
            result = {
                "schema_version": batch.schema_version,
                "valid_observations": len(batch.observations),
            }
        elif args.command == "explain":
            result = explain(args.mapping_id, args.report, args.reports_dir)
        else:
            loaded = catalog.load()
            rules = load_rules(args.rules)
            config = (
                ScoreConfig.model_validate(read_json(args.config)) if args.config else ScoreConfig()
            )
            if args.command == "rules":
                warnings = rules.validate_catalog(loaded)
                result = {
                    "valid_rules": len(rules.rules),
                    "rule_set_version": rules.version,
                    "rule_set_sha256": rules.digest,
                    "warnings": warnings,
                }
            else:
                engine = Engine(loaded, rules, config)
                llm = Ollama(args.model, args.ollama_url, args.llm_timeout) if args.llm else None
                if args.command == "map":
                    batch = ingest(read_json(args.input), args.format)
                    run = engine.map(batch, args.mode == "hybrid", llm)
                    paths = write_reports(run, args.output_dir)
                    result = {
                        **run.model_dump(mode="json"),
                        "report_files": [str(p) for p in paths],
                    }
                else:
                    dataset = Dataset.model_validate(read_json(args.dataset))
                    result = evaluate(engine, dataset, args.k, llm)
                    if args.output:
                        args.output.parent.mkdir(parents=True, exist_ok=True)
                        with args.output.open("x") as output:
                            json.dump(result, output, indent=2)
                            output.write("\n")
        print(json.dumps(result, indent=2))
        return 0
    except (
        OSError,
        ValueError,
        CatalogError,
        ValidationError,
        KeyError,
        TypeError,
        RecursionError,
    ) as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
