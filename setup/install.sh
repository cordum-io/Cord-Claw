#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
STACK_DIR="${CORDCLAW_HOME:-${HOME}/.cordclaw}"
PACK_SRC_DIR="${PACK_SRC_DIR:-${REPO_ROOT}/pack}"

CORDCLAW_VERSION="${CORDCLAW_VERSION:-latest}"
CORDUM_VERSION="${CORDUM_VERSION:-latest}"
OPENCLAW_SKIP="${OPENCLAW_SKIP:-false}"
CORDCLAW_PROFILE="${CORDCLAW_PROFILE:-moderate}"
CORDUM_UPGRADE="${CORDUM_UPGRADE:-prompt}"

CORDUM_API_KEY="${CORDUM_API_KEY:-$(openssl rand -hex 32)}"
REDIS_PASSWORD="${REDIS_PASSWORD:-$(openssl rand -hex 16)}"
DAEMON_SKIPPED="false"

log() {
  printf '%s\n' "$*"
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

die() {
  printf '[x] %s\n' "$*" >&2
  exit 1
}

print_header() {
  log "====================================="
  log "  CordClaw Installer"
  log "  Pre-dispatch governance for OpenClaw"
  log "====================================="
  log ""
}

resolve_cordum_upgrade_choice() {
  case "${CORDUM_UPGRADE}" in
    true|false)
      ;;
    prompt|"")
      if [ -t 0 ]; then
        local answer
        log "Cordum upgrade adds dashboard, centralized audit, and tenant operations."
        printf "Enable full Cordum stack now? [Y/n]: "
        read -r answer || true
        case "${answer:-Y}" in
          n|N|no|NO)
            CORDUM_UPGRADE="false"
            ;;
          *)
            CORDUM_UPGRADE="true"
            ;;
        esac
      else
        CORDUM_UPGRADE="false"
        warn "Non-interactive shell detected; defaulting to standalone mode."
        warn "Set CORDUM_UPGRADE=true to force full Cordum stack install."
      fi
      ;;
    *)
      die "Invalid CORDUM_UPGRADE='${CORDUM_UPGRADE}'. Expected prompt|true|false."
      ;;
  esac

  log "[+] Selected install mode: CORDUM_UPGRADE=${CORDUM_UPGRADE}"
}

check_prereqs() {
  local missing=()

  command -v curl >/dev/null 2>&1 || missing+=("curl")
  command -v openssl >/dev/null 2>&1 || missing+=("openssl")
  command -v node >/dev/null 2>&1 || missing+=("node")
  command -v npm >/dev/null 2>&1 || missing+=("npm")

  if [ "${CORDUM_UPGRADE}" = "true" ]; then
    command -v docker >/dev/null 2>&1 || missing+=("docker")
    docker compose version >/dev/null 2>&1 || missing+=("docker compose")
  fi

  if [ ${#missing[@]} -gt 0 ]; then
    die "Missing prerequisites: ${missing[*]}"
  fi

  if [ "${CORDUM_UPGRADE}" = "true" ] && [ ! -d "${PACK_SRC_DIR}" ]; then
    die "Pack source directory not found: ${PACK_SRC_DIR}"
  fi

  if [ "${CORDUM_UPGRADE}" = "true" ] && [ ! -f "${SCRIPT_DIR}/docker-compose.cordclaw.yaml" ]; then
    die "Missing compose template: ${SCRIPT_DIR}/docker-compose.cordclaw.yaml"
  fi

  if [ ! -f "${SCRIPT_DIR}/config/openclaw.yaml" ]; then
    die "Missing OpenClaw config template: ${SCRIPT_DIR}/config/openclaw.yaml"
  fi

  if [ ! -f "${SCRIPT_DIR}/templates/policy-${CORDCLAW_PROFILE}.yaml" ]; then
    die "Unknown profile '${CORDCLAW_PROFILE}'. Expected strict|moderate|permissive."
  fi
}

resolve_os_arch() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "${os}" in
    linux*) os="linux" ;;
    darwin*) os="darwin" ;;
    msys*|mingw*|cygwin*) os="windows" ;;
    *) die "Unsupported OS: ${os}" ;;
  esac

  case "${arch}" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "Unsupported architecture: ${arch}" ;;
  esac

  printf '%s %s\n' "${os}" "${arch}"
}

install_daemon() {
  if command -v cordclaw-daemon >/dev/null 2>&1; then
    log "[~] cordclaw-daemon already installed: $(cordclaw-daemon --version 2>/dev/null || echo unknown)"
    return
  fi

  local os arch url target_dir target_bin
  read -r os arch < <(resolve_os_arch)
  url="https://github.com/cordum-io/cordclaw/releases/download/${CORDCLAW_VERSION}/cordclaw-daemon-${os}-${arch}"

  target_dir="/usr/local/bin"
  target_bin="${target_dir}/cordclaw-daemon"
  if [ ! -w "${target_dir}" ]; then
    target_dir="${HOME}/.local/bin"
    target_bin="${target_dir}/cordclaw-daemon"
    mkdir -p "${target_dir}"
    export PATH="${target_dir}:${PATH}"
    warn "No write access to /usr/local/bin; installing daemon into ${target_bin}"
  fi

  log "[+] Downloading cordclaw-daemon (${os}/${arch})..."
  curl -fsSL "${url}" -o "${target_bin}"
  chmod +x "${target_bin}"
  log "[+] cordclaw-daemon installed: $(cordclaw-daemon --version 2>/dev/null || echo unknown)"
}

install_openclaw() {
  if [ "${OPENCLAW_SKIP}" = "true" ]; then
    log "[~] Skipping OpenClaw installation (OPENCLAW_SKIP=true)"
    return
  fi

  if command -v openclaw >/dev/null 2>&1; then
    log "[~] OpenClaw already installed: $(openclaw --version 2>/dev/null || echo unknown)"
    return
  fi

  log "[+] Installing OpenClaw..."
  curl -fsSL https://get.openclaw.ai | bash
  log "[+] OpenClaw installation complete"
}

prepare_stack() {
  log "[+] Preparing local stack directory: ${STACK_DIR}"
  mkdir -p "${STACK_DIR}/config" "${STACK_DIR}/templates"

  cp "${SCRIPT_DIR}/config/openclaw.yaml" "${STACK_DIR}/config/openclaw.yaml"
  cp "${SCRIPT_DIR}/templates/policy-strict.yaml" "${STACK_DIR}/templates/policy-strict.yaml"
  cp "${SCRIPT_DIR}/templates/policy-moderate.yaml" "${STACK_DIR}/templates/policy-moderate.yaml"
  cp "${SCRIPT_DIR}/templates/policy-permissive.yaml" "${STACK_DIR}/templates/policy-permissive.yaml"

  cp "${SCRIPT_DIR}/templates/policy-${CORDCLAW_PROFILE}.yaml" "${STACK_DIR}/config/safety.yaml"

  if [ "${CORDUM_UPGRADE}" = "true" ]; then
    mkdir -p "${STACK_DIR}/packs"
    cp "${SCRIPT_DIR}/docker-compose.cordclaw.yaml" "${STACK_DIR}/docker-compose.yaml"
    rm -rf "${STACK_DIR}/packs/cordclaw"
    cp -R "${PACK_SRC_DIR}" "${STACK_DIR}/packs/cordclaw"
  fi

  cat > "${STACK_DIR}/.env" <<EOF
CORDUM_VERSION=${CORDUM_VERSION}
CORDUM_API_KEY=${CORDUM_API_KEY}
REDIS_PASSWORD=${REDIS_PASSWORD}
EOF
}

wait_for_gateway() {
  local ok=1 i
  for i in $(seq 1 45); do
    if curl -sf "http://127.0.0.1:8081/api/v1/status" >/dev/null 2>&1; then
      ok=0
      break
    fi
    if curl -skf "https://127.0.0.1:8081/api/v1/status" >/dev/null 2>&1; then
      ok=0
      break
    fi
    sleep 2
  done

  if [ "${ok}" -ne 0 ]; then
    die "Gateway did not become healthy on :8081"
  fi
}

start_cordum() {
  log "[+] Starting Cordum stack via docker compose..."
  (
    cd "${STACK_DIR}"
    docker compose --env-file "${STACK_DIR}/.env" up -d
  )
  wait_for_gateway
  log "[+] Cordum stack is healthy"
  log "    Dashboard: http://localhost:8082"
}

start_daemon() {
  if ! command -v cordclaw-daemon >/dev/null 2>&1; then
    die "cordclaw-daemon is not installed"
  fi

  if [ "${CORDUM_UPGRADE}" = "true" ]; then
    export CORDCLAW_KERNEL_ADDR="${CORDCLAW_KERNEL_ADDR:-127.0.0.1:50051}"
    export CORDCLAW_API_KEY="${CORDCLAW_API_KEY:-${CORDUM_API_KEY}}"
  else
    if [ -z "${CORDCLAW_KERNEL_ADDR:-}" ] || [ -z "${CORDCLAW_API_KEY:-}" ]; then
      DAEMON_SKIPPED="true"
      warn "Skipping cordclaw-daemon startup in standalone mode."
      warn "Set CORDCLAW_KERNEL_ADDR and CORDCLAW_API_KEY to connect to an existing Cordum Safety Kernel."
      return
    fi
  fi

  export CORDCLAW_TENANT_ID="${CORDCLAW_TENANT_ID:-default}"
  export CORDCLAW_KERNEL_INSECURE="${CORDCLAW_KERNEL_INSECURE:-true}"
  export CORDCLAW_FAIL_MODE="${CORDCLAW_FAIL_MODE:-graduated}"

  if curl -sf "http://127.0.0.1:19090/health" >/dev/null 2>&1; then
    log "[~] cordclaw-daemon already healthy on :19090"
    return
  fi

  log "[+] Starting cordclaw-daemon..."
  nohup cordclaw-daemon > "${STACK_DIR}/cordclaw-daemon.log" 2>&1 &

  local i
  for i in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:19090/health" >/dev/null 2>&1; then
      log "[+] cordclaw-daemon healthy"
      return
    fi
    sleep 1
  done

  die "cordclaw-daemon failed to become healthy. See ${STACK_DIR}/cordclaw-daemon.log"
}

install_pack() {
  log "[+] Installing CordClaw pack into gateway..."
  (
    cd "${STACK_DIR}"
    docker compose --env-file "${STACK_DIR}/.env" exec -T gateway sh -lc \
      'cordumctl pack install /packs/cordclaw --upgrade || cordumctl pack install /packs/cordclaw'
  )
  log "[+] Pack install completed"
}

configure_openclaw_plugin() {
  if ! command -v openclaw >/dev/null 2>&1; then
    warn "openclaw CLI not found; skipping plugin installation and OpenClaw verification"
    return
  fi

  log "[+] Installing OpenClaw plugin..."
  openclaw plugins install @cordum/cordclaw

  mkdir -p "${HOME}/.openclaw"
  local cfg="${HOME}/.openclaw/config.yaml"
  touch "${cfg}"

  if grep -Eq '^[[:space:]]*cordclaw:' "${cfg}"; then
    log "[~] CordClaw plugin config already present in ${cfg}"
  else
    cat >> "${cfg}" <<'EOF'

# CordClaw governance
plugins:
  entries:
    cordclaw:
      enabled: true
      config:
        daemonUrl: "http://127.0.0.1:19090"
        timeoutMs: 500
        failMode: "deny"
        logDecisions: true
EOF
    log "[+] Appended CordClaw plugin config to ${cfg}"
  fi
}

verify_installation() {
  log ""
  log "[+] Running installation verification..."

  if [ "${CORDUM_UPGRADE}" = "true" ]; then
    if curl -sf "http://127.0.0.1:8081/api/v1/status" >/dev/null 2>&1 || curl -skf "https://127.0.0.1:8081/api/v1/status" >/dev/null 2>&1; then
      log "    Cordum gateway: OK"
    else
      die "Cordum gateway check failed"
    fi
  else
    log "    Cordum gateway: skipped (standalone mode)"
  fi

  if [ "${DAEMON_SKIPPED}" = "true" ]; then
    log "    cordclaw-daemon: skipped (set CORDCLAW_KERNEL_ADDR + CORDCLAW_API_KEY to start)"
  else
    if curl -sf "http://127.0.0.1:19090/health" >/dev/null 2>&1; then
      log "    cordclaw-daemon: OK"
    else
      die "CordClaw daemon check failed"
    fi
  fi

  if command -v openclaw >/dev/null 2>&1; then
    openclaw cordclaw status || true
    openclaw cordclaw simulate --tool exec --command "rm -rf /" || true
    log "    OpenClaw plugin: checked"
  else
    warn "OpenClaw CLI unavailable; skipped OpenClaw runtime checks"
  fi

  log ""
  log "====================================="
  log "  CordClaw setup completed"
  log "====================================="
  if [ "${CORDUM_UPGRADE}" = "true" ]; then
    log "Cordum API key: ${CORDUM_API_KEY}"
  fi
  log "Stack directory: ${STACK_DIR}"
  log "Use CORDCLAW_PROFILE=strict|moderate|permissive to switch baseline policy"
  log "Use CORDUM_UPGRADE=true to enable full Cordum stack features"
}

main() {
  print_header
  resolve_cordum_upgrade_choice
  check_prereqs
  install_daemon
  install_openclaw
  prepare_stack
  if [ "${CORDUM_UPGRADE}" = "true" ]; then
    start_cordum
  else
    log "[~] Skipping Cordum stack startup (standalone mode)"
  fi
  start_daemon
  if [ "${CORDUM_UPGRADE}" = "true" ]; then
    install_pack
  else
    log "[~] Skipping CordClaw pack install (gateway not started)"
  fi
  configure_openclaw_plugin
  verify_installation
}

main "$@"
