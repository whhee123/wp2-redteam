#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

: "${MODEL_NAME:?Set MODEL_NAME to the exact Ollama model tag}"
PROFILE_ID="${PROFILE_ID:-server-local-model}"
AGENT_IMAGE="${AGENT_IMAGE:-trace-redteam-agent:server}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker-compose.server.yaml}"
ENV_FILE="${ENV_FILE:-deploy/.env.server}"
OLLAMA_CONTAINER="${OLLAMA_CONTAINER:-trace-g-ollama}"
OLLAMA_IMAGE="${OLLAMA_IMAGE:?Set OLLAMA_IMAGE to an explicit version or digest}"

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --wait ollama
docker build --pull -f agent_image/Dockerfile -t "$AGENT_IMAGE" .

# The production network is internal. Add temporary egress only while an
# operator explicitly pulls a model, then remove it before any Agent runs.
cleanup() {
  docker network disconnect bridge "$OLLAMA_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Remove a stale temporary attachment left by an interrupted earlier run.
docker network disconnect bridge "$OLLAMA_CONTAINER" >/dev/null 2>&1 || true
docker network connect bridge "$OLLAMA_CONTAINER"
docker exec "$OLLAMA_CONTAINER" ollama pull "$MODEL_NAME"

if ! docker network disconnect bridge "$OLLAMA_CONTAINER"; then
  echo "ERROR: failed to remove temporary bridge network from Ollama" >&2
  exit 1
fi
trap - EXIT

if docker inspect -f '{{json .NetworkSettings.Networks}}' "$OLLAMA_CONTAINER" \
  | python -c 'import json,sys; raise SystemExit(0 if "bridge" in json.load(sys.stdin) else 1)'; then
  echo "ERROR: Ollama remains attached to the external bridge network" >&2
  exit 1
fi

python scripts/lock_target_profile.py \
  --profile-id "$PROFILE_ID" \
  --model-name "$MODEL_NAME" \
  --ollama-image "$OLLAMA_IMAGE" \
  --ollama-container "$OLLAMA_CONTAINER" \
  --image "$AGENT_IMAGE" \
  --output config/target-profiles.server.yaml

echo "Locked profile written to config/target-profiles.server.yaml"
