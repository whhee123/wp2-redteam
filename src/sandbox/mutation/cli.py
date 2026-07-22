"""CLI wiring for one-shot mutation generation and inspection."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from sandbox.coverage.risk_scope import CampaignRiskScopeLoader
from sandbox.coverage.store import CoverageStore
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.mutation.config import MutationConfig, MutationProviderConfig
from sandbox.mutation.diversity import DiversityGate
from sandbox.mutation.feedback import MutationFeedbackBuilder
from sandbox.mutation.models import MutationProviderKind, MutationSeed, to_test_case
from sandbox.mutation.mutator import SemanticMutator
from sandbox.mutation.normalizer import prompt_digest
from sandbox.mutation.operators import MutationOperatorRegistryLoader
from sandbox.mutation.priority import MutationPriorityCalculator
from sandbox.mutation.providers.ollama import OllamaMutationProvider
from sandbox.mutation.providers.rule_based import RuleBasedMutationProvider
from sandbox.mutation.similarity import CharacterShingleSimilarity
from sandbox.mutation.store import MutationStore


def add_mutation_parser(subparsers) -> None:
    mutation = subparsers.add_parser("mutate", help="generate coverage-guided mutations")
    commands = mutation.add_subparsers(dest="mutation_command", required=True)

    operators = commands.add_parser("operators", help="list mutation operators")
    _shared_arguments(operators, include_store=False)

    generate = commands.add_parser("generate", help="generate one mutation batch")
    source = generate.add_mutually_exclusive_group(required=True)
    source.add_argument("--case", dest="case_id")
    source.add_argument("--parent-mutation-id")
    generate.add_argument("--count", type=int, default=8)
    generate.add_argument("--seed", type=int, default=42)
    generate.add_argument("--target-risk")
    generate.add_argument("--operator")
    generate.add_argument(
        "--provider",
        choices=[item.value for item in MutationProviderKind],
        default=MutationProviderKind.RULE_BASED.value,
    )
    generate.add_argument("--model-name")
    generate.add_argument("--model-digest")
    generate.add_argument("--endpoint")
    _shared_arguments(generate)

    batch = commands.add_parser("batch", help="show a saved mutation batch")
    batch.add_argument("--batch-id", required=True)
    _shared_arguments(batch)

    stats = commands.add_parser("stats", help="show mutation history statistics")
    _shared_arguments(stats)

    export = commands.add_parser("export", help="export accepted candidates as JSONL")
    export.add_argument("--output", type=Path, required=True)
    _shared_arguments(export)


def _shared_arguments(parser: argparse.ArgumentParser, *, include_store: bool = True) -> None:
    parser.add_argument("--campaign-id", default="week4-baseline")
    parser.add_argument("--coverage-root", type=Path, default=Path("data/coverage"))
    parser.add_argument("--mutation-root", type=Path, default=Path("data/mutations"))
    parser.add_argument(
        "--taxonomy-path",
        type=Path,
        default=Path("config/risk-taxonomy.yaml"),
    )
    parser.add_argument(
        "--risk-scope-path",
        type=Path,
        default=Path("config/risk-scope-week3.yaml"),
    )
    parser.add_argument(
        "--operator-registry-path",
        type=Path,
        default=Path("config/mutation-operators.yaml"),
    )
    if not include_store:
        parser.set_defaults(mutation_store_not_required=True)


def _load_components(args):
    taxonomy = RiskTaxonomyLoader(args.taxonomy_path).load()
    scope = CampaignRiskScopeLoader(args.risk_scope_path, taxonomy).load()
    registry = MutationOperatorRegistryLoader(
        args.operator_registry_path,
        taxonomy,
    ).load()
    return taxonomy, scope, registry


def _store_metadata(taxonomy, scope, registry, config: MutationConfig) -> dict[str, str]:
    return {
        "taxonomy_version": taxonomy.taxonomy_version,
        "risk_scope_version": scope.scope_version,
        "risk_scope_digest": scope.digest,
        "operator_registry_version": registry.registry_version,
        "operator_registry_digest": registry.digest,
        "normalization_version": config.diversity.normalization_version,
        "similarity_version": config.diversity.similarity_version,
        "priority_formula_version": config.priority.formula_version,
    }


def _mutation_config(args) -> MutationConfig:
    kind = MutationProviderKind(getattr(args, "provider", MutationProviderKind.RULE_BASED))
    provider = MutationProviderConfig(
        kind=kind,
        provider_version=(
            "rule-mutator-v1" if kind == MutationProviderKind.RULE_BASED else "ollama-mutator-v1"
        ),
        model_name=getattr(args, "model_name", None),
        model_digest=getattr(args, "model_digest", None),
        endpoint=getattr(args, "endpoint", None),
    )
    return MutationConfig(
        campaign_id=args.campaign_id,
        operator_registry_path=args.operator_registry_path,
        store_root=args.mutation_root,
        provider=provider,
    )


def mutation_main(args, source: TemplateCaseSource) -> int:
    taxonomy, scope, registry = _load_components(args)
    if args.mutation_command == "operators":
        payload = [
            registry.get(operator_id).model_dump(mode="json")
            for operator_id in registry.operator_ids
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    config = _mutation_config(args)
    with MutationStore(
        config.store_root,
        config.campaign_id,
        metadata=_store_metadata(taxonomy, scope, registry, config),
    ) as mutation_store:
        if args.mutation_command == "batch":
            batch = mutation_store.get_batch(args.batch_id)
            if batch is None:
                raise ValueError(f"mutation batch not found: {args.batch_id}")
            print(json.dumps(batch.model_dump(mode="json"), ensure_ascii=False, indent=2))
            return 0
        if args.mutation_command == "stats":
            print(
                json.dumps(
                    mutation_store.snapshot().model_dump(mode="json"),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.mutation_command == "export":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            payload = "".join(
                candidate.model_dump_json() + "\n" for candidate in mutation_store.all_candidates()
            )
            args.output.write_text(payload, encoding="utf-8")
            print(str(args.output))
            return 0

        seed = _resolve_seed(args, source, mutation_store)
        with CoverageStore(
            args.coverage_root,
            args.campaign_id,
            taxonomy,
            risk_scope=scope,
            auto_snapshot_interval=0,
        ) as coverage_store:
            feedback = MutationFeedbackBuilder(taxonomy, scope).build(
                seed,
                coverage_store.snapshot(include_heatmap=False),
                schedule_weights=coverage_store.schedule_weights(),
                history=mutation_store.snapshot(),
            )
        provider = (
            RuleBasedMutationProvider()
            if config.provider.kind == MutationProviderKind.RULE_BASED
            else OllamaMutationProvider(config.provider)
        )
        similarity = CharacterShingleSimilarity()
        mutator = SemanticMutator(
            config,
            registry,
            scope,
            provider,
            DiversityGate(similarity, config.diversity),
            MutationPriorityCalculator(config.priority),
            mutation_store,
        )
        batch = asyncio.run(
            mutator.mutate(
                seed,
                feedback,
                args.count,
                random_seed=args.seed,
                target_risk=args.target_risk,
                operator_id=args.operator,
            )
        )
        print(json.dumps(batch.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return 0


def _resolve_seed(args, source: TemplateCaseSource, store: MutationStore) -> MutationSeed:
    if args.parent_mutation_id:
        parent = store.get_candidate(args.parent_mutation_id)
        case = to_test_case(parent)
        return MutationSeed(
            seed_id=parent.mutation_id,
            case=case,
            prompt_sha256=prompt_digest(case.prompt),
            parent_mutation_id=parent.mutation_id,
            mutation_depth=parent.mutation_depth,
        )
    case = source.generate(args.case_id, seed=args.seed)
    return MutationSeed(
        seed_id=case.case_id,
        case=case,
        prompt_sha256=prompt_digest(case.prompt),
    )
