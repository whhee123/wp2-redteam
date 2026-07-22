from __future__ import annotations

from unittest.mock import MagicMock

from sandbox.config import SandboxConfig, SandboxLimits
from sandbox.fuzzer.models import SandboxRunContext
from sandbox.scheduler.docker_scheduler import DockerSandboxScheduler


def _scheduler() -> tuple[DockerSandboxScheduler, MagicMock, MagicMock]:
    container = MagicMock()
    container.id = "container-1"
    container.image.attrs = {"RepoDigests": []}
    container.image.id = "sha256:test"
    client = MagicMock()
    client.containers.run.return_value = container
    scheduler = DockerSandboxScheduler(
        SandboxConfig(), client=client, scheduler_instance_id="scheduler-1"
    )
    return scheduler, client, container


def test_scheduler_adds_explicit_campaign_labels() -> None:
    scheduler, client, _container = _scheduler()
    context = SandboxRunContext(
        campaign_id="week5-test",
        work_item_id="sha256:" + "1" * 64,
        attempt=2,
    )
    scheduler._create_sync("fuzz-" + "a" * 24, "image:test", SandboxLimits(), context)
    labels = client.containers.run.call_args.kwargs["labels"]
    assert labels["trace-g.campaign-id"] == "week5-test"
    assert labels["trace-g.work-item-id"] == context.work_item_id
    assert labels["trace-g.attempt"] == "2"


def test_campaign_cleanup_skips_active_and_removes_only_exact_campaign() -> None:
    scheduler, client, container = _scheduler()
    container.labels = {
        "trace-g.campaign-id": "week5-test",
        "trace-g.execution-id": "fuzz-" + "a" * 24,
        "trace-g.created-unix": "1",
        "trace-g.workspace-volume": "",
    }
    client.containers.list.return_value = [container]

    skipped = scheduler._cleanup_campaign_orphans_sync("week5-test", {"fuzz-" + "a" * 24}, 0)
    assert skipped.skipped == ["container-1"]
    container.remove.assert_not_called()

    removed = scheduler._cleanup_campaign_orphans_sync("week5-test", set(), 0)
    assert removed.removed == ["container-1"]
    container.remove.assert_called_once_with(force=True, v=True)


def test_campaign_cleanup_removes_orphan_volume_without_container() -> None:
    scheduler, client, _container = _scheduler()
    client.containers.list.return_value = []
    volume = MagicMock()
    volume.name = "trace-g-workspace-orphan"
    volume.attrs = {
        "Labels": {
            "trace-g.campaign-id": "week5-test",
            "trace-g.execution-id": "fuzz-" + "b" * 24,
            "trace-g.created-unix": "1",
        }
    }
    client.volumes.list.return_value = [volume]

    report = scheduler._cleanup_campaign_orphans_sync("week5-test", set(), 0)

    assert report.removed == ["volume:trace-g-workspace-orphan"]
    volume.remove.assert_called_once_with(force=True)
