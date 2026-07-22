#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODEL_NETWORK="${MODEL_NETWORK:-trace-g-model-internal}"
OLLAMA_CONTAINER="${OLLAMA_CONTAINER:-trace-g-ollama}"
AGENT_IMAGE="${AGENT_IMAGE:-trace-redteam-agent:server}"
OLLAMA_IMAGE="${OLLAMA_IMAGE:?Set OLLAMA_IMAGE to an explicit version or digest}"
PROFILE_PATH="${PROFILE_PATH:-config/target-profiles.server.yaml}"
PROFILE_ID="${PROFILE_ID:-server-local-model}"

command -v docker >/dev/null
command -v python >/dev/null
docker version >/dev/null
docker compose version >/dev/null
nvidia-smi >/dev/null
docker run --rm --gpus all --entrypoint nvidia-smi "$OLLAMA_IMAGE" >/dev/null

test "$(docker network inspect -f '{{.Internal}}' "$MODEL_NETWORK")" = "true"
test "$(docker network inspect -f '{{index .Labels "trace-g.network-policy"}}' "$MODEL_NETWORK")" = "ollama-only"
test "$(docker inspect -f '{{.State.Health.Status}}' "$OLLAMA_CONTAINER")" = "healthy"
python - "$OLLAMA_CONTAINER" "$MODEL_NETWORK" <<'PY'
import json
import subprocess
import sys

container, expected = sys.argv[1:]
payload = subprocess.check_output(
    ["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", container],
    text=True,
)
networks = set(json.loads(payload))
if networks != {expected}:
    raise SystemExit(
        f"ERROR: Ollama network attachments are {sorted(networks)}, expected only {expected!r}"
    )
PY
test -f "$PROFILE_PATH"
docker image inspect "$AGENT_IMAGE" >/dev/null
python scripts/verify_target_profile.py \
  --profile-path "$PROFILE_PATH" \
  --profile-id "$PROFILE_ID" \
  --ollama-container "$OLLAMA_CONTAINER"

docker run --rm --network "$MODEL_NETWORK" --entrypoint python "$AGENT_IMAGE" -c \
  'import json, urllib.request; data=json.load(urllib.request.urlopen("http://ollama:11434/api/tags", timeout=5)); assert data["models"]'

docker run --rm --network "$MODEL_NETWORK" --entrypoint python "$AGENT_IMAGE" -c \
  'import urllib.error, urllib.request;
try:
 urllib.request.urlopen("https://example.com", timeout=3)
except urllib.error.HTTPError as exc:
 raise SystemExit(f"ERROR: external HTTP peer was reached: {exc.code}")
except urllib.error.URLError:
 raise SystemExit(0)
raise SystemExit("ERROR: model network has external egress")'

python -m ruff check .
python -m pytest -q
TRACE_G_RUN_DOCKER_E2E=1 TRACE_G_E2E_IMAGE="$AGENT_IMAGE" python -m pytest tests/e2e -q
echo "TRACE-G server preflight passed"
