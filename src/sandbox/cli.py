"""Command-line entry point for isolated execution, recording, and strict replay."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import docker

from sandbox.client.artifact_transfer import ArtifactTransfer
from sandbox.client.runtime_client import RuntimeClient
from sandbox.config import ReplayConfig, SandboxConfig, TraceConfig, WeekOneConfig
from sandbox.coverage.heatmap import HeatmapGenerator
from sandbox.coverage.input import CoverageInputResolver
from sandbox.coverage.risk_scope import CampaignRiskScopeLoader
from sandbox.coverage.store import CoverageStore
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.engine.execution_engine import RedTeamExecutionEngine
from sandbox.mutation.cli import add_mutation_parser, mutation_main
from sandbox.protocol import ModelOptions, ModelProvider
from sandbox.replay.artifact_store import ArtifactStore
from sandbox.replay.manifest import ManifestStore
from sandbox.replay.models import ForkInjection, ForkSuffixMode, ReplayMode
from sandbox.replay.replay_engine import ReplayEngine
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler
from sandbox.scoring.rule_scorer import RuleBasedScorer


def _storage_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output-dir", type=Path, default=Path("data/trajectories"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("data/artifacts"))
    parser.add_argument("--manifest-dir", type=Path, default=Path("data/replays"))


def _model_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--model-provider",
        choices=[provider.value for provider in ModelProvider],
        default=ModelProvider.FAKE.value,
    )
    parser.add_argument("--model-name", default="llama3")
    parser.add_argument("--model-digest")
    parser.add_argument("--ollama-endpoint")
    parser.add_argument("--model-network")


def _coverage_store_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--campaign-id", default="week3-baseline")
    parser.add_argument("--coverage-root", type=Path, default=Path("data/coverage"))
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


def _coverage_resolver_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--trajectory-dir", type=Path, default=Path("data/trajectories"))
    parser.add_argument("--manifest-dir", type=Path, default=Path("data/replays"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("data/artifacts"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trace-redteam")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list-cases", help="list deterministic red-team templates")
    add_mutation_parser(subparsers)

    run = subparsers.add_parser("run", help="execute one isolated red-team case")
    run.add_argument("--case", required=True, dest="case_id")
    run.add_argument("--seed", type=int, default=42)
    run.add_argument("--output-dir", type=Path, default=Path("data/trajectories"))
    run.add_argument("--image", default="trace-redteam-agent:week1")
    _model_arguments(run)

    record = subparsers.add_parser("record", help="record and seal a replay package")
    record.add_argument("--case", required=True, dest="case_id")
    record.add_argument("--seed", type=int, default=42)
    record.add_argument("--image", default="trace-redteam-agent:week2")
    _model_arguments(record)
    _storage_arguments(record)

    replay = subparsers.add_parser("replay", help="strictly replay a sealed package")
    replay.add_argument("--replay-id", required=True)
    replay.add_argument("--run-id")
    replay.add_argument(
        "--mode",
        choices=[mode.value for mode in ReplayMode],
        default=ReplayMode.STRICT.value,
    )
    _storage_arguments(replay)
    _model_arguments(replay)

    checkpoints = subparsers.add_parser(
        "checkpoints",
        help="list recoverable checkpoints in a sealed replay",
    )
    checkpoints.add_argument("--replay-id", required=True)
    _storage_arguments(checkpoints)

    fork = subparsers.add_parser("fork", help="fork execution from a recoverable checkpoint")
    fork.add_argument("--parent-replay-id", required=True)
    fork.add_argument("--checkpoint-id", required=True)
    fork.add_argument(
        "--injection-type",
        required=True,
        choices=[
            "prompt_replace",
            "prompt_append",
            "model_decision_replace",
            "tool_result_replace",
        ],
    )
    fork.add_argument("--content", required=True)
    fork.add_argument(
        "--suffix-mode",
        choices=[mode.value for mode in ForkSuffixMode],
        default=ForkSuffixMode.LIVE_AND_RECORD.value,
    )
    fork.add_argument("--operator", default="local-cli")
    _storage_arguments(fork)
    _model_arguments(fork)

    coverage = subparsers.add_parser("coverage", help="compute behavior and risk coverage")
    coverage_subparsers = coverage.add_subparsers(dest="coverage_command", required=True)

    coverage_evaluate = coverage_subparsers.add_parser(
        "evaluate", help="evaluate one committed trajectory"
    )
    coverage_target = coverage_evaluate.add_mutually_exclusive_group(required=True)
    coverage_target.add_argument("--trajectory-id")
    coverage_target.add_argument("--trajectory-path", type=Path)
    coverage_evaluate.add_argument("--case-id")
    coverage_evaluate.add_argument("--prompt")
    coverage_evaluate.add_argument("--seed", type=int)
    _coverage_store_arguments(coverage_evaluate)
    _coverage_resolver_arguments(coverage_evaluate)

    coverage_compute = coverage_subparsers.add_parser(
        "compute", help="evaluate all committed JSONL trajectories in a directory"
    )
    coverage_compute.add_argument("--data-dir", type=Path, required=True)
    _coverage_store_arguments(coverage_compute)
    _coverage_resolver_arguments(coverage_compute)

    coverage_snapshot = coverage_subparsers.add_parser(
        "snapshot", help="show cumulative campaign coverage"
    )
    _coverage_store_arguments(coverage_snapshot)

    coverage_heatmap = coverage_subparsers.add_parser(
        "heatmap", help="export sparse heatmap JSON"
    )
    coverage_heatmap.add_argument("--output", type=Path, required=True)
    coverage_heatmap.add_argument(
        "--pretty",
        action="store_true",
        help="export human-readable row, column, and cell labels",
    )
    _coverage_store_arguments(coverage_heatmap)

    coverage_taxonomy = coverage_subparsers.add_parser(
        "taxonomy", help="list the configured risk taxonomy"
    )
    coverage_taxonomy.add_argument(
        "--taxonomy-path",
        type=Path,
        default=Path("config/risk-taxonomy.yaml"),
    )
    return parser


def _config(args) -> WeekOneConfig:
    image = getattr(args, "image", "trace-redteam-agent:week2")
    provider = ModelProvider(getattr(args, "model_provider", ModelProvider.FAKE.value))
    endpoint = getattr(args, "ollama_endpoint", None)
    return WeekOneConfig(
        seed=getattr(args, "seed", 42),
        sandbox=SandboxConfig(
            image=image,
            workspace_storage=(
                "archive_volume"
                if args.command in {"record", "replay", "fork"}
                else "tmpfs"
            ),
            ollama_endpoint=endpoint,
            model_network_name=getattr(args, "model_network", None),
        ),
        tracing=TraceConfig(output_dir=args.output_dir),
        replay=ReplayConfig(
            artifact_dir=getattr(args, "artifact_dir", Path("data/artifacts")),
            manifest_dir=getattr(args, "manifest_dir", Path("data/replays")),
        ),
        model=ModelOptions(
            provider=provider,
            model_name=getattr(args, "model_name", "llama3"),
            model_digest=getattr(args, "model_digest", None),
            endpoint=endpoint,
        ),
    )


def _replay_engine(config: WeekOneConfig, source: TemplateCaseSource) -> ReplayEngine:
    docker_client = docker.from_env()
    artifact_store = ArtifactStore(config.replay.artifact_dir)
    scheduler = DockerSandboxScheduler(config.sandbox, client=docker_client)
    runtime = RuntimeClient(config.tracing, docker_client=docker_client)
    return ReplayEngine(
        config,
        scheduler,
        runtime,
        RuleBasedScorer(),
        ManifestStore(config.replay.manifest_dir),
        artifact_store,
        ArtifactTransfer(docker_client, artifact_store),
        source,
    )


def _coverage_main(args, source: TemplateCaseSource) -> int:
    taxonomy = RiskTaxonomyLoader(args.taxonomy_path).load()
    if args.coverage_command == "taxonomy":
        print(json.dumps(taxonomy.flattened(), ensure_ascii=False, indent=2))
        return 0

    risk_scope = CampaignRiskScopeLoader(args.risk_scope_path, taxonomy).load()

    with CoverageStore(
        args.coverage_root,
        args.campaign_id,
        taxonomy,
        risk_scope=risk_scope,
    ) as store:
        if args.coverage_command == "snapshot":
            print(
                json.dumps(
                    store.snapshot().model_dump(mode="json"),
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.coverage_command == "heatmap":
            payload = (
                HeatmapGenerator(taxonomy)
                .generate_pretty(
                    args.campaign_id,
                    store.all_profiles(),
                    store.all_hits(),
                )
                .model_dump(mode="json")
                if args.pretty
                else store.snapshot().heatmap_data
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(str(args.output))
            return 0

        resolver = CoverageInputResolver(
            trajectory_root=(
                args.data_dir if args.coverage_command == "compute" else args.trajectory_dir
            ),
            manifest_root=args.manifest_dir,
            artifact_root=args.artifact_dir,
            case_source=source,
        )
        if args.coverage_command == "evaluate":
            coverage_input = resolver.resolve(
                trajectory_id=args.trajectory_id,
                trajectory_path=args.trajectory_path,
                case_id=args.case_id,
                prompt=args.prompt,
                seed=args.seed,
            )
            result = store.evaluate(coverage_input)
            print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
            return 0


        results = []
        for path in sorted(args.data_dir.glob("*.jsonl")):
            results.append(store.evaluate(resolver.from_trajectory_path(path)))
        output = {
            "evaluated": len(results),
            "snapshot": store.snapshot().model_dump(mode="json"),
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0


def main() -> int:
    args = build_parser().parse_args()
    source = TemplateCaseSource()
    if args.command == "list-cases":
        for template_id in source.template_ids:
            print(template_id)
        return 0

    if args.command == "coverage":
        return _coverage_main(args, source)
    if args.command == "mutate":
        return mutation_main(args, source)


    config = _config(args)
    if args.command == "run":
        scheduler = DockerSandboxScheduler(config.sandbox)
        runtime = RuntimeClient(config.tracing)
        engine = RedTeamExecutionEngine(
            config,
            scheduler,
            runtime,
            RuleBasedScorer(),
            source,
        )
        outcome = asyncio.run(engine.run_case(args.case_id, seed=args.seed))
        print(json.dumps(outcome.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return int(
            outcome.execution.status.value != "succeeded" or not outcome.container_removed
        )

    if args.command == "checkpoints":
        artifacts = ArtifactStore(config.replay.artifact_dir)
        engine = ReplayEngine(
            config,
            scheduler=None,
            runtime=None,
            scorer=RuleBasedScorer(),
            manifest_store=ManifestStore(config.replay.manifest_dir),
            artifact_store=artifacts,
            artifact_transfer=None,
            case_source=source,
        )
        checkpoints = engine.checkpoints(args.replay_id)
        print(
            json.dumps(
                [checkpoint.model_dump(mode="json") for checkpoint in checkpoints],
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    engine = _replay_engine(config, source)
    if args.command == "record":
        manifest = asyncio.run(engine.record_template(args.case_id, seed=args.seed))
        print(json.dumps(manifest.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return 0

    if args.command == "fork":
        content = (
            args.content
            if args.injection_type in {"prompt_replace", "prompt_append"}
            else json.loads(args.content)
        )
        manifest = asyncio.run(
            engine.fork(
                args.parent_replay_id,
                args.checkpoint_id,
                ForkInjection(type=args.injection_type, content=content),
                suffix_mode=ForkSuffixMode(args.suffix_mode),
                operator=args.operator,
            )
        )
        print(json.dumps(manifest.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return 0

    result = asyncio.run(
        engine.replay(
            args.replay_id,
            mode=ReplayMode(args.mode),
            replay_run_id=args.run_id,
        )
    )
    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return int(result.status.value != "matched" or not result.container_removed)


if __name__ == "__main__":
    raise SystemExit(main())
