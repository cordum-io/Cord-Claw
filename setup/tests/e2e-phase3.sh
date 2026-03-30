#!/usr/bin/env bash
set -euo pipefail

STACK_DIR="${CORDCLAW_HOME:-${HOME}/.cordclaw}"
COMPOSE_FILE="${STACK_DIR}/docker-compose.yaml"
ENV_FILE="${STACK_DIR}/.env"
DAEMON_URL="${DAEMON_URL:-http://127.0.0.1:19090}"

log() {
  printf '%s\n' "$*"
}

die() {
  printf '[x] %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

compose() {
  docker compose -f "${COMPOSE_FILE}" --env-file "${ENV_FILE}" "$@"
}

check_prereqs() {
  require_cmd docker
  require_cmd curl
  [ -f "${COMPOSE_FILE}" ] || die "Compose file not found: ${COMPOSE_FILE}"
  [ -f "${ENV_FILE}" ] || die "Env file not found: ${ENV_FILE}"
}

wait_http_ok() {
  local url="$1" timeout="${2:-45}" i
  for i in $(seq 1 "${timeout}"); do
    if curl -sf "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

gateway_up() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8081/api/v1/status" || true)"
  if [ "${code}" != "000" ]; then
    return 0
  fi

  code="$(curl -k -s -o /dev/null -w '%{http_code}' "https://127.0.0.1:8081/api/v1/status" || true)"
  if [ "${code}" != "000" ]; then
    return 0
  fi

  return 1
}

validate_stack_health() {
  log "[+] Validating gateway + daemon health"
  local i
  for i in $(seq 1 45); do
    if gateway_up; then
      break
    fi
    sleep 1
  done
  gateway_up || die "Gateway not reachable on :8081 (http or https)"
  wait_http_ok "${DAEMON_URL}/health" 20 || die "Daemon not healthy on :19090"
}

apply_profile() {
  local profile="$1"
  local src="${STACK_DIR}/templates/policy-${profile}.yaml"
  [ -f "${src}" ] || die "Missing profile template: ${src}"

  log "[+] Applying profile: ${profile}"
  cp "${src}" "${STACK_DIR}/config/safety.yaml"
  compose restart safety-kernel >/dev/null
  sleep 3
  local i
  for i in $(seq 1 30); do
    if gateway_up; then
      return
    fi
    sleep 1
  done
  die "Gateway unhealthy after ${profile} profile apply"
}

smoke_policy_check() {
  local payload="$1"
  local out
  out="$(curl -sS -X POST "${DAEMON_URL}/check" -H 'Content-Type: application/json' -d "${payload}")"
  printf '%s' "${out}" | grep -q '"decision"' || die "Policy response missing decision: ${out}"
  printf '%s' "${out}" | grep -q '"governanceStatus"' || die "Policy response missing governanceStatus: ${out}"
  log "    response: ${out}"
}

test_profiles() {
  log "[+] Testing strict/moderate/permissive profile activation"
  local profile
  for profile in strict moderate permissive; do
    apply_profile "${profile}"
    smoke_policy_check '{"tool":"exec","command":"echo profile-check"}'
  done
}

test_fail_closed_cache_behavior() {
  log "[+] Testing graduated fail-closed behavior"

  local cached_payload uncached_payload
  cached_payload='{"tool":"exec","command":"echo cached"}'
  uncached_payload='{"tool":"exec","command":"echo uncached-marker-'"$(date +%s)"'"}'

  log "    priming cache"
  smoke_policy_check "${cached_payload}"

  log "    stopping safety-kernel"
  compose stop safety-kernel >/dev/null
  sleep 2

  log "    checking cached action under outage"
  smoke_policy_check "${cached_payload}"

  log "    checking uncached action under outage"
  smoke_policy_check "${uncached_payload}"

  log "    starting safety-kernel"
  compose start safety-kernel >/dev/null
  local i
  for i in $(seq 1 45); do
    if gateway_up; then
      return
    fi
    sleep 1
  done
  die "Gateway did not recover after safety-kernel restart"
}

test_openclaw_plugin_path() {
  if ! command -v openclaw >/dev/null 2>&1; then
    log "[~] openclaw CLI not installed, skipping OpenClaw plugin e2e checks"
    return
  fi

  log "[+] Running OpenClaw plugin smoke tests"
  openclaw cordclaw status || die "openclaw cordclaw status failed"
  openclaw cordclaw simulate --tool exec --command "echo hello-from-openclaw" || die "openclaw simulate failed"
}

main() {
  check_prereqs
  validate_stack_health
  test_profiles
  test_fail_closed_cache_behavior
  test_openclaw_plugin_path
  log "[+] Phase 3 e2e checks completed"
}

main "$@"
