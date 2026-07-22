"""Measure cached-image sandbox allocation and Runtime readiness latency."""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from uuid import uuid4

from sandbox.config import WeekOneConfig
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler


def percentile(samples: list[float], percentile_value: int) -> float:
    if len(samples) == 1:
        return samples[0]
    return statistics.quantiles(samples, n=100, method="inclusive")[percentile_value - 1]


async def benchmark(runs: int) -> dict:
    config = WeekOneConfig()
    scheduler = DockerSandboxScheduler(config.sandbox)
    create_samples: list[float] = []
    ready_samples: list[float] = []

    for _ in range(runs):
        execution_id = f"benchmark-{uuid4().hex}"
        handle = None
        started = time.perf_counter()
        try:
            handle = await scheduler.create(
                execution_id,
                config.sandbox.image,
                config.sandbox.limits,
            )
            created = time.perf_counter()
            await scheduler.wait_until_ready(handle)
            ready = time.perf_counter()
            create_samples.append(created - started)
            ready_samples.append(ready - started)
        finally:
            if handle is not None:
                await scheduler.destroy(handle)

    return {
        "runs": runs,
        "image": config.sandbox.image,
        "image_cached": True,
        "create_seconds": {
            "samples": create_samples,
            "p50": statistics.median(create_samples),
            "p95": percentile(create_samples, 95),
        },
        "ready_seconds": {
            "samples": ready_samples,
            "p50": statistics.median(ready_samples),
            "p95": percentile(ready_samples, 95),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=10)
    args = parser.parse_args()
    if args.runs < 2:
        parser.error("--runs must be at least 2")
    print(json.dumps(asyncio.run(benchmark(args.runs)), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
