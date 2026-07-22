from __future__ import annotations

import pytest

from sandbox.config import SandboxLimits
from sandbox.fuzzer.circuit_breaker import SystemicFailureCircuitBreaker
from sandbox.fuzzer.config import ConcurrencyConfig, FuzzerConfig
from sandbox.fuzzer.exceptions import CampaignConfigurationError
from sandbox.fuzzer.models import FailureKind
from sandbox.fuzzer.resources import docker_memory_limit_bytes, validate_host_capacity


def test_systemic_failure_circuit_uses_rolling_threshold() -> None:
    circuit = SystemicFailureCircuitBreaker(window_size=4, threshold=0.5)

    assert circuit.record("success") is False
    assert circuit.record(FailureKind.SYSTEMIC_INFRASTRUCTURE.value) is False
    assert circuit.record("success") is False
    assert circuit.record(FailureKind.SYSTEMIC_INFRASTRUCTURE.value) is True
    assert circuit.systemic_failures == 2

    assert circuit.record("success") is True
    assert circuit.record("success") is False
    assert circuit.systemic_failures == 1


def test_integrity_failure_opens_circuit_immediately() -> None:
    circuit = SystemicFailureCircuitBreaker(window_size=20, threshold=0.5)
    assert circuit.record(FailureKind.INTEGRITY_FAILURE.value) is True


def test_host_capacity_accepts_worker_aggregate_within_limits() -> None:
    config = FuzzerConfig(
        concurrency=ConcurrencyConfig(
            sandbox_workers=2,
            execution_queue_size=2,
            result_queue_size=2,
            max_pending_work_items=2,
            host_memory_limit_bytes=1024**3,
            host_nano_cpus=2_000_000_000,
        )
    )
    validate_host_capacity(config, SandboxLimits(memory_limit="512m"))


def test_host_capacity_rejects_oversubscribed_memory_or_cpu() -> None:
    base = {
        "sandbox_workers": 2,
        "execution_queue_size": 2,
        "result_queue_size": 2,
        "max_pending_work_items": 2,
    }
    memory_config = FuzzerConfig(
        concurrency=ConcurrencyConfig(
            **base,
            host_memory_limit_bytes=512 * 1024**2,
        )
    )
    with pytest.raises(CampaignConfigurationError, match="host_memory_limit_bytes"):
        validate_host_capacity(memory_config, SandboxLimits(memory_limit="512m"))

    cpu_config = FuzzerConfig(
        concurrency=ConcurrencyConfig(
            **base,
            host_nano_cpus=1_000_000_000,
        )
    )
    with pytest.raises(CampaignConfigurationError, match="host_nano_cpus"):
        validate_host_capacity(cpu_config, SandboxLimits())


def test_docker_memory_limit_parser_is_binary_and_strict() -> None:
    assert docker_memory_limit_bytes("512m") == 512 * 1024**2
    with pytest.raises(CampaignConfigurationError, match="unsupported"):
        docker_memory_limit_bytes("0.5g")
