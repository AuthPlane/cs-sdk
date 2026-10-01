#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUTHSERVER_DIR="${AUTHSERVER_DIR:-$REPO_ROOT/../authserver}"
AUTHSERVER_REF="${AUTHSERVER_REF:-}"

usage() {
  cat <<'EOF'
Usage:
  manual-e2e-setup.sh

Environment (optional):
  AUTHSERVER_DIR   Path to local authserver repo (default: ../authserver)
  AUTHSERVER_REF   Git ref of authserver to check out before building
                   (default: leave the checkout as is)

What this script does:
  1) Optionally checks out AUTHSERVER_REF in the authserver repo
  2) Builds authserver binary if needed
  3) Starts authserver demo server
  4) Leaves demo client credentials in:
     - /tmp/authserver-demo.client-id
     - /tmp/authserver-demo.key
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ ! -d "${AUTHSERVER_DIR}" ]; then
  echo "ERROR: authserver repo not found at ${AUTHSERVER_DIR}" >&2
  exit 1
fi

echo "==> Starting authserver demo server"
(
  cd "${AUTHSERVER_DIR}"
  if [ -n "${AUTHSERVER_REF}" ]; then
    echo "==> Checking out authserver ${AUTHSERVER_REF}"
    git checkout "${AUTHSERVER_REF}"
    # The binary below is only rebuilt when missing; a ref change must not
    # run a stale build.
    rm -f bin/authserver
  fi
  if [ ! -x "bin/authserver" ]; then
    go build -o bin/authserver ./cmd/authserver
  fi
  ./demo/mcp-demo-server-start.sh
)

echo ""
echo "Setup completed."
