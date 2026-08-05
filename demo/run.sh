#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
export RESOURCE_URL="${RESOURCE_URL:-http://localhost:8080/mcp}"
export DEV_MODE="${DEV_MODE:-true}"
if [[ -z "${CLIENT_ID:-}" && -f /tmp/authserver-demo.client-id ]]; then
  export CLIENT_ID="$(cat /tmp/authserver-demo.client-id)"
fi
if [[ -z "${CLIENT_SECRET:-}" && -f /tmp/authserver-demo.key ]]; then
  export CLIENT_SECRET="$(cat /tmp/authserver-demo.key)"
fi

if [[ -f "$SCRIPT_DIR/.env" ]]; then
  set -a
  source "$SCRIPT_DIR/.env"
  set +a
fi

cd "$REPO_ROOT"
dotnet run --project demo --urls "http://localhost:8080"
