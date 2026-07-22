"""Versioned target-profile registry loading."""

from __future__ import annotations

from pathlib import Path

import yaml

from sandbox.fuzzer.exceptions import CampaignConfigurationError
from sandbox.fuzzer.models import TargetProfile


class TargetProfileRegistry:
    def __init__(self, profiles: list[TargetProfile]) -> None:
        self._profiles: dict[str, TargetProfile] = {}
        for profile in profiles:
            if profile.profile_id in self._profiles:
                raise CampaignConfigurationError(f"duplicate target profile: {profile.profile_id}")
            if profile.model_provider == "ollama":
                required = {
                    "model_digest": profile.model_digest,
                    "image_digest": profile.image_digest,
                    "model_runtime_image": profile.model_runtime_image,
                    "model_runtime_digest": profile.model_runtime_digest,
                }
                missing = sorted(name for name, value in required.items() if not value)
                if missing:
                    raise CampaignConfigurationError(
                        f"Ollama target profile {profile.profile_id} is missing locks: {missing}"
                    )
            self._profiles[profile.profile_id] = profile

    @classmethod
    def load(cls, path: Path) -> TargetProfileRegistry:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls([TargetProfile.model_validate(item) for item in payload.get("profiles", [])])

    @property
    def profile_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._profiles))

    def get(self, profile_id: str) -> TargetProfile:
        try:
            return self._profiles[profile_id]
        except KeyError as exc:
            raise CampaignConfigurationError(f"unknown target profile: {profile_id}") from exc
