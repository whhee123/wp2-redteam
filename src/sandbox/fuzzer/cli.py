"""Campaign CLI wiring and production dependency assembly."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from contextlib import ExitStack
from pathlib import Path

import docker

from sandbox.client.artifact_transfer import ArtifactTransfer
from sandbox.client.runtime_client import RuntimeClient
from sandbox.config import ReplayConfig, SandboxConfig, TraceConfig, WeekOneConfig
from sandbox.coverage.input import CoverageInputResolver
from sandbox.coverage.risk_scope import CampaignRiskScopeLoader
from sandbox.coverage.store import CoverageStore
from sandbox.coverage.taxonomy import RiskTaxonomyLoader
from sandbox.engine.case_source import TemplateCaseSource
from sandbox.engine.execution_engine import RedTeamExecutionEngine
from sandbox.fuzzer.config import FuzzerConfig
from sandbox.fuzzer.engine import FuzzingEngine, initialize_campaign
from sandbox.fuzzer.models import (
    CampaignManifest,
    CampaignStatus,
    WorkItemStatus,
    fuzzer_digest,
)
from sandbox.fuzzer.profiles import TargetProfileRegistry
from sandbox.fuzzer.recovery import RecoveryManager
from sandbox.fuzzer.resources import validate_host_capacity
from sandbox.fuzzer.soak import SoakRunner
from sandbox.fuzzer.store import FuzzerStore
from sandbox.mutation.config import MutationConfig, MutationProviderConfig
from sandbox.mutation.diversity import DiversityGate
from sandbox.mutation.feedback import MutationFeedbackBuilder
from sandbox.mutation.models import MutationProviderKind
from sandbox.mutation.mutator import SemanticMutator
from sandbox.mutation.operators import MutationOperatorRegistryLoader
from sandbox.mutation.priority import MutationPriorityCalculator
from sandbox.mutation.providers.ollama import OllamaMutationProvider
from sandbox.mutation.providers.rule_based import RuleBasedMutationProvider
from sandbox.mutation.similarity import CharacterShingleSimilarity
from sandbox.mutation.store import MutationStore
from sandbox.protocol import ModelOptions, ModelProvider
from sandbox.replay.artifact_store import ArtifactStore
from sandbox.replay.manifest import ManifestStore
from sandbox.replay.replay_engine import ReplayEngine
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler
from sandbox.scoring.rule_scorer import RuleBasedScorer


def add_campaign_parser(subparsers) -> None:
    campaign = subparsers.add_parser("campaign", help="manage persistent fuzzing campaigns")
    commands = campaign.add_subparsers(dest="campaign_command", required=True)

    create = commands.add_parser("create", help="create a locked campaign")
    _common(create)
    create.add_argument("--initial-case", action="append", required=True)

    for name in ("run", "resume"):
        command = commands.add_parser(name, help=f"{name} a campaign")
        _common(command)

    status = commands.add_parser("status", help="show a campaign snapshot")
    _identity(status)

    pause = commands.add_parser("pause", help="request a safe campaign pause")
    _identity(pause)
    pause.add_argument("--wait", action="store_true")
    pause.add_argument("--wait-timeout-seconds", type=int, default=180)

    stop = commands.add_parser("stop", help="request a campaign stop without deleting data")
    _identity(stop)
    stop.add_argument("--wait", action="store_true")
    stop.add_argument("--wait-timeout-seconds", type=int, default=180)

    seeds = commands.add_parser("seeds", help="list persistent seeds")
    _identity(seeds)
    seeds.add_argument(
        "--status",
        choices=[
            item.value
            for item in __import__("sandbox.fuzzer.models", fromlist=["SeedStatus"]).SeedStatus
        ],
    )

    work = commands.add_parser("work", help="list persistent work items")
    _identity(work)
    work.add_argument("--status", choices=[item.value for item in WorkItemStatus])

    corpus = commands.add_parser("corpus", help="list retained evidence entries")
    _identity(corpus)

    export = commands.add_parser("export", help="export a derived campaign view")
    _identity(export)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--include-prompts", action="store_true")

    soak = commands.add_parser("soak", help="run isolated infrastructure probes")
    _common(soak)
    soak.add_argument("--duration-hours", type=float, required=True)
    soak.add_argument("--probe-interval-seconds", type=float, default=60.0)


def _identity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--store-root", type=Path, default=Path("data/fuzzing"))


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=Path, default=Path("config/fuzzer-default.yaml"))
    parser.add_argument("--campaign-id")
    parser.add_argument("--coverage-root", type=Path, default=Path("data/coverage"))
    parser.add_argument("--mutation-root", type=Path, default=Path("data/mutations"))
    parser.add_argument("--trajectory-dir", type=Path, default=Path("data/trajectories"))
    parser.add_argument("--artifact-dir", type=Path, default=Path("data/artifacts"))
    parser.add_argument("--manifest-dir", type=Path, default=Path("data/replays"))
    parser.add_argument("--taxonomy-path", type=Path, default=Path("config/risk-taxonomy.yaml"))
    parser.add_argument(
        "--risk-scope-path", type=Path, default=Path("config/risk-scope-week3.yaml")
    )
    parser.add_argument(
        "--target-profiles-path",
        type=Path,
        default=Path("config/target-profiles.yaml"),
    )
    parser.add_argument(
        "--operator-registry-path", type=Path, default=Path("config/mutation-operators.yaml")
    )
    parser.add_argument("--image", default="trace-redteam-agent:week2")
    parser.add_argument(
        "--model-provider",
        choices=[item.value for item in ModelProvider],
        default=ModelProvider.FAKE.value,
    )
    parser.add_argument("--model-name", default="fake-chat-model")
    parser.add_argument("--model-digest")
    parser.add_argument("--ollama-endpoint")
    parser.add_argument("--model-network")
    parser.add_argument(
        "--mutation-provider",
        choices=[item.value for item in MutationProviderKind],
        default=MutationProviderKind.RULE_BASED.value,
    )
    parser.add_argument("--mutation-model-name")
    parser.add_argument("--mutation-model-digest")
    parser.add_argument("--mutation-endpoint")


def campaign_main(args, source: TemplateCaseSource) -> int:
    if args.campaign_command in {"status", "pause", "stop", "seeds", "work", "corpus", "export"}:
        return _store_command(args)
    config = FuzzerConfig.from_yaml(args.config)
    if args.campaign_id:
        config = config.model_copy(update={"campaign_id": args.campaign_id})
    with _CampaignComponents(args, config, source) as components:
        if args.campaign_command == "create":
            initialize_campaign(
                components.store,
                config,
                components.manifest,
                source,
                args.initial_case,
            )
            print(
                json.dumps(
                    {
                        "campaign_id": config.campaign_id,
                        "status": components.store.status().value,
                        "manifest_digest": fuzzer_digest(components.manifest),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0
        if args.campaign_command == "soak":
            if components.store.is_initialized():
                _validate_locked_manifest(components.store.load_manifest(), components.manifest)
            else:
                components.store.initialize(components.manifest)
            status = asyncio.run(
                components.soak.run(
                    duration_seconds=args.duration_hours * 3_600,
                    probe_interval_seconds=args.probe_interval_seconds,
                )
            )
            print(json.dumps(_status_payload(components.store), ensure_ascii=False, indent=2))
            return int(status == CampaignStatus.FAILED)
        _validate_locked_manifest(components.store.load_manifest(), components.manifest)
        status = asyncio.run(components.engine.run())
        print(json.dumps(_status_payload(components.store), ensure_ascii=False, indent=2))
        return int(status == CampaignStatus.FAILED)


def _validate_locked_manifest(
    locked: CampaignManifest,
    current: CampaignManifest,
) -> None:
    locked_values = locked.model_dump(mode="json", exclude={"created_at"})
    current_values = current.model_dump(mode="json", exclude={"created_at"})
    if locked_values != current_values:
        changed = sorted(
            key for key in locked_values if locked_values.get(key) != current_values.get(key)
        )
        raise ValueError(f"campaign manifest drift requires a new campaign: {changed}")


def _store_command(args) -> int:
    with FuzzerStore(args.store_root, args.campaign_id) as store:
        command = args.campaign_command
        if command == "status":
            print(json.dumps(_status_payload(store), ensure_ascii=False, indent=2))
            return 0
        if command == "pause":
            store.transition_campaign(CampaignStatus.PAUSE_REQUESTED)
            return _wait_for(store, CampaignStatus.PAUSED, args) if args.wait else 0
        if command == "stop":
            store.transition_campaign(CampaignStatus.STOP_REQUESTED)
            return _wait_for(store, CampaignStatus.COMPLETED, args) if args.wait else 0
        if command == "seeds":
            from sandbox.fuzzer.models import SeedStatus

            status = SeedStatus(args.status) if args.status else None
            payload = [item.model_dump(mode="json") for item in store.list_seeds(status)]
        elif command == "work":
            status = WorkItemStatus(args.status) if args.status else None
            payload = [item.model_dump(mode="json") for item in store.list_work(status)]
        elif command == "corpus":
            payload = [item.model_dump(mode="json") for item in store.corpus_entries()]
        else:
            payload = _export_payload(store, include_prompts=args.include_prompts)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(str(args.output))
            return 0
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0


def _status_payload(store: FuzzerStore) -> dict:
    values = store.campaign_values()
    return {
        "campaign_id": store.campaign_id,
        "status": store.status().value,
        "stop_reason": store.stop_reason().value if store.stop_reason() else None,
        "iteration": store.iteration(),
        "active_runtime_seconds": values["active_runtime_seconds"],
        "execution_attempts": values["execution_attempts"],
        "retry_count": values["retry_count"],
        "seed_counts": store.counts("seeds", "status"),
        "work_counts": store.counts("work_items", "status"),
        "corpus_size": len(store.corpus_entries()),
    }


def _wait_for(store: FuzzerStore, target: CampaignStatus, args) -> int:
    deadline = time.monotonic() + args.wait_timeout_seconds
    while time.monotonic() < deadline:
        if store.status() == target:
            print(json.dumps(_status_payload(store), ensure_ascii=False, indent=2))
            return 0
        time.sleep(0.2)
    print(json.dumps(_status_payload(store), ensure_ascii=False, indent=2))
    return 2


def _export_payload(store: FuzzerStore, *, include_prompts: bool) -> dict:
    seeds = []
    for seed in store.list_seeds():
        item = seed.model_dump(mode="json")
        if not include_prompts:
            item["case"]["prompt"] = "<redacted>"
        seeds.append(item)
    return {
        "manifest": store.load_manifest().model_dump(mode="json"),
        "campaign": _status_payload(store),
        "seeds": seeds,
        "work_items": [item.model_dump(mode="json") for item in store.list_work()],
        "corpus": [item.model_dump(mode="json") for item in store.corpus_entries()],
        "audit": store.audit_events(),
    }


class _CampaignComponents:
    def __init__(self, args, config: FuzzerConfig, source: TemplateCaseSource) -> None:
        self.args = args
        self.config = config
        self.source = source
        self.stack = ExitStack()

    def __enter__(self):
        args = self.args
        config = self.config
        taxonomy = RiskTaxonomyLoader(args.taxonomy_path).load()
        scope = CampaignRiskScopeLoader(args.risk_scope_path, taxonomy).load()
        registry = MutationOperatorRegistryLoader(args.operator_registry_path, taxonomy).load()
        target_profile = TargetProfileRegistry.load(args.target_profiles_path).get(
            config.target_profile_id
        )
        if target_profile.image_ref != args.image:
            raise ValueError("target profile image does not match --image")
        if target_profile.model_provider != args.model_provider:
            raise ValueError("target profile model provider does not match CLI")
        if target_profile.model_name != args.model_name:
            raise ValueError("target profile model name does not match CLI")
        if target_profile.model_digest != args.model_digest:
            raise ValueError("target profile model digest does not match CLI")
        if target_profile.risk_scope_path.resolve() != args.risk_scope_path.resolve():
            raise ValueError("target profile risk scope does not match CLI")
        sandbox_config = SandboxConfig(
            image=args.image,
            execution_timeout_seconds=target_profile.execution_timeout_seconds,
            ollama_endpoint=args.ollama_endpoint,
            model_network_name=args.model_network,
        )
        validate_host_capacity(config, sandbox_config.limits)
        provider_kind = MutationProviderKind(args.mutation_provider)
        mutation_config = MutationConfig(
            campaign_id=config.campaign_id,
            operator_registry_path=args.operator_registry_path,
            store_root=args.mutation_root,
            provider=MutationProviderConfig(
                kind=provider_kind,
                provider_version=(
                    "rule-mutator-v1"
                    if provider_kind == MutationProviderKind.RULE_BASED
                    else "ollama-mutator-v1"
                ),
                model_name=args.mutation_model_name,
                model_digest=args.mutation_model_digest,
                endpoint=args.mutation_endpoint,
            ),
        )
        metadata = {
            "taxonomy_version": taxonomy.taxonomy_version,
            "risk_scope_version": scope.scope_version,
            "risk_scope_digest": scope.digest,
            "operator_registry_version": registry.registry_version,
            "operator_registry_digest": registry.digest,
            "normalization_version": mutation_config.diversity.normalization_version,
            "similarity_version": mutation_config.diversity.similarity_version,
            "priority_formula_version": mutation_config.priority.formula_version,
        }
        self.store = self.stack.enter_context(FuzzerStore(config.store_root, config.campaign_id))
        mutation_store = self.stack.enter_context(
            MutationStore(args.mutation_root, config.campaign_id, metadata=metadata)
        )
        coverage_store = self.stack.enter_context(
            CoverageStore(
                args.coverage_root,
                config.campaign_id,
                taxonomy,
                risk_scope=scope,
                auto_snapshot_interval=0,
            )
        )
        provider = (
            RuleBasedMutationProvider()
            if provider_kind == MutationProviderKind.RULE_BASED
            else OllamaMutationProvider(mutation_config.provider)
        )
        mutator = SemanticMutator(
            mutation_config,
            registry,
            scope,
            provider,
            DiversityGate(CharacterShingleSimilarity(), mutation_config.diversity),
            MutationPriorityCalculator(mutation_config.priority),
            mutation_store,
        )
        self.manifest = CampaignManifest(
            campaign_id=config.campaign_id,
            config_digest=fuzzer_digest(config),
            taxonomy_version=taxonomy.taxonomy_version,
            taxonomy_digest=fuzzer_digest(taxonomy.taxonomy),
            risk_scope_version=scope.scope_version,
            risk_scope_digest=scope.digest,
            mutation_registry_version=registry.registry_version,
            mutation_registry_digest=registry.digest,
            mutation_provider=provider_kind.value,
            mutation_provider_version=provider.version,
            mutation_model_name=provider.model_name,
            mutation_model_digest=provider.model_digest,
            agent_model_name=args.model_name,
            agent_model_digest=args.model_digest,
            agent_model_runtime_image=target_profile.model_runtime_image,
            agent_model_runtime_digest=target_profile.model_runtime_digest,
            agent_image=args.image,
            agent_image_digest=target_profile.image_digest,
            target_profile_id=config.target_profile_id,
            energy_formula_version=config.energy.formula_version,
            corpus_policy_version=config.corpus.policy_version,
            scheduler_policy_version="single-host-deterministic-v1",
            random_seed=config.random_seed,
        )
        if args.campaign_command == "create":
            self.engine = None
            return self

        model_provider = ModelProvider(args.model_provider)
        endpoint = args.ollama_endpoint
        runtime_config = WeekOneConfig(
            seed=config.random_seed,
            max_steps=target_profile.max_steps,
            sandbox=sandbox_config,
            tracing=TraceConfig(output_dir=args.trajectory_dir),
            replay=ReplayConfig(artifact_dir=args.artifact_dir, manifest_dir=args.manifest_dir),
            model=ModelOptions(
                provider=model_provider,
                model_name=args.model_name,
                model_digest=args.model_digest,
                endpoint=endpoint,
            ),
        )
        docker_client = docker.from_env()
        scheduler = DockerSandboxScheduler(runtime_config.sandbox, client=docker_client)
        runtime = RuntimeClient(runtime_config.tracing, docker_client=docker_client)
        execution = RedTeamExecutionEngine(
            runtime_config, scheduler, runtime, RuleBasedScorer(), self.source
        )
        resolver = CoverageInputResolver(
            trajectory_root=args.trajectory_dir,
            manifest_root=args.manifest_dir,
            artifact_root=args.artifact_dir,
            case_source=self.source,
        )
        from sandbox.fuzzer.executor import CandidateExecutor

        replay_config = runtime_config.model_copy(
            update={
                "sandbox": runtime_config.sandbox.model_copy(
                    update={"workspace_storage": "archive_volume"}
                )
            }
        )
        replay_scheduler = DockerSandboxScheduler(replay_config.sandbox, client=docker_client)
        replay_runtime = RuntimeClient(replay_config.tracing, docker_client=docker_client)
        artifact_store = ArtifactStore(args.artifact_dir)
        replay_engine = ReplayEngine(
            replay_config,
            replay_scheduler,
            replay_runtime,
            RuleBasedScorer(),
            ManifestStore(args.manifest_dir),
            artifact_store,
            ArtifactTransfer(docker_client, artifact_store),
            self.source,
        )
        executor = CandidateExecutor(
            execution,
            mutation_store,
            case_source=self.source,
            replay_engine=replay_engine,
            coverage_resolver=resolver,
            template_seed=config.random_seed,
        )
        self.executor = executor
        self.recovery = RecoveryManager(
            self.store,
            scheduler=scheduler,
            trajectory_root=args.trajectory_dir,
            max_transient_attempts=config.retry.max_transient_attempts,
            recovery_grace_seconds=config.leases.recovery_grace_seconds,
        )
        self.soak = SoakRunner(
            self.store,
            executor,
            self.recovery,
            lease_seconds=config.leases.lease_seconds,
            heartbeat_seconds=config.leases.heartbeat_seconds,
        )
        self.engine = FuzzingEngine(
            config,
            store=self.store,
            mutation_store=mutation_store,
            coverage_store=coverage_store,
            mutator=mutator,
            feedback_builder=MutationFeedbackBuilder(taxonomy, scope),
            executor=executor,
            recovery=self.recovery,
            case_source=self.source,
        )
        return self

    def __exit__(self, *args) -> None:
        self.stack.close()
