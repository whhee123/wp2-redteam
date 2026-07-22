"""Aggregate host-capacity checks for bounded sandbox concurrency."""

from __future__ import annotations

import re

from sandbox.config import SandboxLimits
from sandbox.fuzzer.config import FuzzerConfig
from sandbox.fuzzer.exceptions import CampaignConfigurationError

_MEMORY_LIMIT = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>[kmgt]?)$", re.IGNORECASE)
_UNIT_BYTES = {
    "": 1,
    "k": 1024,
    "m": 1024**2,
    "g": 1024**3,
    "t": 1024**4,
}


def docker_memory_limit_bytes(value: str) -> int:
    match = _MEMORY_LIMIT.fullmatch(value.strip())
    if match is None:
        raise CampaignConfigurationError(f"unsupported Docker memory limit: {value!r}")
    return int(match.group("amount")) * _UNIT_BYTES[match.group("unit").lower()]


def validate_host_capacity(config: FuzzerConfig, limits: SandboxLimits) -> None:
    workers = config.concurrency.sandbox_workers
    required_memory = workers * docker_memory_limit_bytes(limits.memory_limit)
    memory_cap = config.concurrency.host_memory_limit_bytes
    if memory_cap is not None and required_memory > memory_cap:
        raise CampaignConfigurationError(
            "sandbox workers exceed host_memory_limit_bytes "
            f"({required_memory} required, {memory_cap} configured)"
        )

    required_cpus = workers * limits.nano_cpus
    cpu_cap = config.concurrency.host_nano_cpus
    if cpu_cap is not None and required_cpus > cpu_cap:
        raise CampaignConfigurationError(
            "sandbox workers exceed host_nano_cpus "
            f"({required_cpus} required, {cpu_cap} configured)"
        )
