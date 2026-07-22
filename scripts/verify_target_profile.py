from __future__ import annotations

import argparse
import json
from pathlib import Path

import docker

from sandbox.fuzzer.profile_lock import verify_target_profile
from sandbox.fuzzer.profiles import TargetProfileRegistry


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify current Ollama model and Agent image against a locked profile."
    )
    parser.add_argument("--profile-path", type=Path, required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--ollama-container", default="trace-g-ollama")
    parser.add_argument(
        "--ollama-admin-endpoint",
        default="http://127.0.0.1:11434",
    )
    args = parser.parse_args()
    profile = TargetProfileRegistry.load(args.profile_path).get(args.profile_id)
    client = docker.from_env()
    try:
        verify_target_profile(
            client=client,
            ollama_admin_endpoint=args.ollama_admin_endpoint,
            profile=profile,
            model_runtime_container=args.ollama_container,
        )
    finally:
        client.close()
    print(
        json.dumps(
            {
                "profile_id": profile.profile_id,
                "model_digest": profile.model_digest,
                "model_runtime_digest": profile.model_runtime_digest,
                "image_digest": profile.image_digest,
                "verified": True,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
