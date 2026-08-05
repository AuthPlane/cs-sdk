#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RUN_SETUP=1
RESOURCE_URL="${RESOURCE_URL:-http://localhost:8080/mcp}"
ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ADMIN_KEY="${ADMIN_KEY:-b480b9760e730abe43b98d0ba01418961df392de0fc6358c36a9a62a8764a7c1}"
SERVER_LOG="/tmp/csharp-adapters-manual-e2e-smoke.log"

usage() {
  cat <<'EOF'
Usage:
  manual-e2e-smoke.sh [--skip-setup]
EOF
}

while [ "${#}" -gt 0 ]; do
  case "$1" in
    --skip-setup)
      RUN_SETUP=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

cleanup() {
  if [ -n "${SERVER_PID:-}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" || true
  fi
}
trap cleanup EXIT

register_scope() {
  local scope_name="$1"
  local status
  status="$(
    curl -sS -o /dev/null -w "%{http_code}" \
      -X POST "${ADMIN_URL}/admin/scopes" \
      -H "Authorization: Bearer ${ADMIN_KEY}" \
      -H "Content-Type: application/json" \
      -d "{\"resource\":\"${RESOURCE_URL}\",\"name\":\"${scope_name}\",\"description\":\"Manual E2E smoke scope ${scope_name}\"}" \
      || true
  )"
  if [ "${status}" != "201" ] && [ "${status}" != "409" ]; then
    echo "WARN: could not ensure scope ${scope_name} for ${RESOURCE_URL} (status=${status}); continuing" >&2
  fi
}

if [ "${RUN_SETUP}" -eq 1 ]; then
  bash "${SCRIPT_DIR}/manual-e2e-setup.sh"
fi

echo "==> Ensuring authserver scopes for resource: ${RESOURCE_URL}"
register_scope "tools/add"
register_scope "tools/multiply"

echo "==> Starting C# demo server"
(
  cd "${REPO_ROOT}"
  ./demo/run.sh >"${SERVER_LOG}" 2>&1
) &
SERVER_PID=$!

PRM_URL="${RESOURCE_URL%/mcp}/.well-known/oauth-protected-resource/mcp"
echo "==> Waiting for PRM: ${PRM_URL}"
for _ in $(seq 1 45); do
  status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
  if [ "${status}" = "200" ] || [ "${status}" = "401" ]; then
    break
  fi
  sleep 1
done
status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
if [ "${status}" != "200" ] && [ "${status}" != "401" ]; then
  echo "ERROR: PRM endpoint not ready (status=${status})" >&2
  echo "Server log: ${SERVER_LOG}" >&2
  exit 1
fi

if [ ! -f /tmp/authserver-demo.client-id ] || [ ! -f /tmp/authserver-demo.key ]; then
  echo "ERROR: missing /tmp/authserver-demo.client-id or /tmp/authserver-demo.key" >&2
  exit 1
fi

CLIENT_ID="$(cat /tmp/authserver-demo.client-id)"
CLIENT_SECRET="$(cat /tmp/authserver-demo.key)"

echo "==> Minting token (tools/add)"
TOKEN_JSON="$(
  curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "resource=${RESOURCE_URL}" \
    -d "scope=tools/add" \
    "${ISSUER_URL}/oauth/token"
)"

TOKEN_ERROR="$(
  echo "${TOKEN_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error",""))'
)"
if [ "${TOKEN_ERROR}" = "invalid_scope" ]; then
  TOKEN_JSON="$(
    curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials" \
      -d "resource=${RESOURCE_URL}" \
      "${ISSUER_URL}/oauth/token"
  )"
fi

ACCESS_TOKEN="$(
  echo "${TOKEN_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'
)"
if [ -z "${ACCESS_TOKEN}" ]; then
  echo "ERROR: token mint failed" >&2
  echo "${TOKEN_JSON}" >&2
  exit 1
fi

echo "==> Checking unauthenticated /mcp is blocked"
mcp_status="$(
  curl -sS -o /dev/null -w "%{http_code}" -X POST "${RESOURCE_URL}" \
    -H "Content-Type: application/json" \
    -d '{}' || true
)"
if [ "${mcp_status}" = "200" ]; then
  echo "ERROR: unauthenticated /mcp request unexpectedly returned 200" >&2
  exit 1
fi

echo ""
echo "Smoke check passed (csharp-adapters)"
echo "PRM: ${PRM_URL}"
echo "Server log: ${SERVER_LOG}"
