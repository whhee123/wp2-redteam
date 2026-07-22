from __future__ import annotations

import argparse
import json
from pathlib import Path

import docker

from sandbox.fuzzer.profile_lock import lock_target_profile, write_target_profile


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Lock an Ollama server profile to observed model and image digests."
    )
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--model-name", required=True)
    parser.add_argument("--image", default="trace-redteam-agent:server")
    parser.add_argument("--ollama-image", required=True)
    parser.add_argument("--ollama-container", default="trace-g-ollama")
    parser.add_argument(
        "--ollama-admin-endpoint",
        default="http://127.0.0.1:11434",
    )
    parser.add_argument(
        "--risk-scope-path",
        type=Path,
        default=Path("config/risk-scope-week3.yaml"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("config/target-profiles.server.yaml"),
    )
    parser.add_argument("--max-steps", type=int, default=40)
    parser.add_argument("--execution-timeout-seconds", type=int, default=300)
    args = parser.parse_args()

    client = docker.from_env()
    try:
        profile = lock_target_profile(
            client=client,
            ollama_admin_endpoint=args.ollama_admin_endpoint,
            profile_id=args.profile_id,
            model_name=args.model_name,
            image_ref=args.image,
            model_runtime_image=args.ollama_image,
            model_runtime_container=args.ollama_container,
            risk_scope_path=args.risk_scope_path,
            max_steps=args.max_steps,
            execution_timeout_seconds=args.execution_timeout_seconds,
        )
        write_target_profile(args.output, profile)
    finally:
        client.close()
    print(
        json.dumps(
            {
                "profile_path": str(args.output),
                "profile_id": profile.profile_id,
                "model_digest": profile.model_digest,
                "model_runtime_digest": profile.model_runtime_digest,
                "image_digest": profile.image_digest,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
