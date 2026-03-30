#!/usr/bin/env bash
set -euo pipefail

DAEMON_URL="${DAEMON_URL:-http://127.0.0.1:19090}"
CLI_BIN="${OPENCLAW_BIN:-openclaw}"

banner() {
  printf '\n== %s ==\n' "$1"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '[x] missing command: %s\n' "$1" >&2
    exit 1
  }
}

json_post() {
  local path="$1"
  local body="$2"
  curl -sS -X POST "${DAEMON_URL}${path}" -H 'Content-Type: application/json' -d "${body}"
}

main() {
  require_cmd curl

  banner "CordClaw 5-Minute Demo"
  printf 'Daemon URL: %s\n' "${DAEMON_URL}"

  banner "1) Governance status"
  curl -sS "${DAEMON_URL}/status"

  banner "2) Dangerous command simulation (expected DENY)"
  json_post "/simulate" '{"tool":"exec","command":"rm -rf /"}'

  banner "3) Safe command simulation"
  json_post "/simulate" '{"tool":"exec","command":"npm test"}'

  banner "4) Outbound messaging simulation"
  json_post "/simulate" '{"tool":"sessions_send","channel":"slack://ops","command":"post release notice"}'

  banner "5) Recent audit decisions"
  curl -sS "${DAEMON_URL}/audit?limit=5"

  if command -v "${CLI_BIN}" >/dev/null 2>&1; then
    banner "6) OpenClaw CLI integration"
    "${CLI_BIN}" cordclaw status || true
    "${CLI_BIN}" cordclaw simulate --tool exec --command "rm -rf /" || true
  else
    banner "6) OpenClaw CLI integration (skipped: openclaw not installed)"
  fi

  banner "Demo complete"
}

main "$@"
