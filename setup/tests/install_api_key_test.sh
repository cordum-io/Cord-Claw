#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALL="${ROOT}/setup/install.sh"

ENV_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CONTAINER_KEY="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
STACK_KEY="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
OTHER_KEY="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
CONCURRENT_KEY_ONE="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
CONCURRENT_KEY_TWO="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

TMP_ROOT="$(mktemp -d)"
cleanup() {
  rm -rf "${TMP_ROOT}"
}
trap cleanup EXIT

fail() {
  printf '[x] %s\n' "$*" >&2
  exit 1
}

pass() {
  printf '[+] %s\n' "$*"
}

sha256() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

file_mode() {
  case "$(uname -s)" in
    MSYS*|MINGW*|CYGWIN*)
      (umask 077 && stat -c '%a' "$1")
      ;;
    *)
      stat -c '%a' "$1"
      ;;
  esac
}

assert_contains() {
  local haystack="$1" needle="$2" label="$3"
  grep -Fq -- "${needle}" <<<"${haystack}" || fail "${label}: missing ${needle}; output=${haystack}"
}

assert_not_contains() {
  local haystack="$1" needle="$2" label="$3"
  if grep -Fq -- "${needle}" <<<"${haystack}"; then
    fail "${label}: leaked secret value"
  fi
}

new_stack_dir() {
  local dir
  dir="$(mktemp -d "${TMP_ROOT}/stack.XXXXXX")"
  printf '%s\n' "${dir}"
}

new_fakebin() {
  local dir
  dir="$(mktemp -d "${TMP_ROOT}/fakebin.XXXXXX")"
  cat > "${dir}/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${1:-}" in
  ps)
    if [ -n "${FAKE_DOCKER_NAMES:-}" ]; then
      printf '%b\n' "${FAKE_DOCKER_NAMES}"
    fi
    ;;
  inspect)
    name="${2:-}"
    if [ -n "${FAKE_DOCKER_KEY:-}" ]; then
      printf 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
      printf 'CORDUM_API_KEY=%s\n' "${FAKE_DOCKER_KEY}"
      printf 'SERVICE=cordum-api-gateway\n'
    elif [ "${name}" = "missing" ]; then
      exit 1
    fi
    ;;
  compose)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF
  chmod +x "${dir}/docker"
  printf '%s\n' "${dir}"
}

new_fakebin_with_delayed_openssl() {
  local dir
  dir="$(new_fakebin)"
  cat > "${dir}/openssl" <<EOF
#!/usr/bin/env bash
set -euo pipefail

if [ "\${1:-}" = "rand" ] && [ "\${2:-}" = "-hex" ] && [ "\${3:-}" = "32" ]; then
  state="\${FAKE_OPENSSL_STATE:?FAKE_OPENSSL_STATE is required}"
  mkdir -p "\$(dirname -- "\${state}")"
  lock="\${state}.lock"
  while ! mkdir "\${lock}" 2>/dev/null; do
    sleep 0.01
  done
  trap 'rmdir "\${lock}"' EXIT
  count=0
  if [ -f "\${state}" ]; then
    count="\$(cat "\${state}")"
  fi
  count=\$((count + 1))
  printf '%s' "\${count}" > "\${state}"
  sleep 1
  if [ "\${count}" -eq 1 ]; then
    printf '%s\n' "${CONCURRENT_KEY_ONE}"
  else
    printf '%s\n' "${CONCURRENT_KEY_TWO}"
  fi
  exit 0
fi

exec /usr/bin/openssl "\$@"
EOF
  chmod +x "${dir}/openssl"
  printf '%s\n' "${dir}"
}

run_resolver() {
  local stack_dir="$1" fakebin="$2"
  shift 2
  CORDCLAW_HOME="${stack_dir}" \
    CORDCLAW_TEST_MODE=resolve-api-key \
    CORDUM_UPGRADE=false \
    PATH="${fakebin}:${PATH}" \
    "$@" bash "${INSTALL}"
}

run_prepare_stack() {
  local stack_dir="$1" fakebin="$2"
  shift 2
  CORDCLAW_HOME="${stack_dir}" \
    CORDCLAW_TEST_MODE=prepare-stack \
    CORDUM_UPGRADE=false \
    PATH="${fakebin}:${PATH}" \
    "$@" bash "${INSTALL}"
}

extract_probe_value() {
  local file="$1" name="$2"
  sed -n "s/^${name}=//p" "${file}" | tail -n1
}

test_env_wins() {
  local stack fakebin out
  stack="$(new_stack_dir)"
  fakebin="$(new_fakebin)"
  out="$(CORDUM_API_KEY="${ENV_KEY}" run_resolver "${stack}" "${fakebin}")"

  assert_contains "${out}" "source=env" "env precedence"
  assert_contains "${out}" "key_len=64" "env key length"
  assert_contains "${out}" "key_sha256=$(sha256 "${ENV_KEY}")" "env key hash"
  assert_not_contains "${out}" "${ENV_KEY}" "env dry-run output"
  pass "env var wins when other sources are absent"
}

test_container_wins_without_env() {
  local stack fakebin out
  stack="$(new_stack_dir)"
  mkdir -p "${stack}"
  printf 'CORDUM_API_KEY=%s\n' "${STACK_KEY}" > "${stack}/.env"
  fakebin="$(new_fakebin)"
  out="$(FAKE_DOCKER_NAMES=$'cordum-api-gateway-1\nother' FAKE_DOCKER_KEY="${CONTAINER_KEY}" run_resolver "${stack}" "${fakebin}")"

  assert_contains "${out}" "source=container" "container precedence"
  assert_contains "${out}" "key_sha256=$(sha256 "${CONTAINER_KEY}")" "container key hash"
  assert_not_contains "${out}" "${CONTAINER_KEY}" "container dry-run output"
  assert_not_contains "${out}" "${STACK_KEY}" "container dry-run output"
  pass "running container key wins when env is unset"
}

test_stack_env_wins_without_env_or_container() {
  local stack fakebin out
  stack="$(new_stack_dir)"
  printf 'CORDUM_API_KEY="%s"\n' "${STACK_KEY}" > "${stack}/.env"
  fakebin="$(new_fakebin)"
  out="$(FAKE_DOCKER_NAMES="" run_resolver "${stack}" "${fakebin}")"

  assert_contains "${out}" "source=stack_env" "stack .env precedence"
  assert_contains "${out}" "key_sha256=$(sha256 "${STACK_KEY}")" "stack .env key hash"
  assert_not_contains "${out}" "${STACK_KEY}" "stack .env dry-run output"
  pass "existing stack .env wins when env/container are absent"
}

test_generated_fallback_writes_restrictive_temp_env() {
  local stack fakebin out generated
  stack="$(new_stack_dir)"
  fakebin="$(new_fakebin)"
  out="$(FAKE_DOCKER_NAMES="" run_prepare_stack "${stack}" "${fakebin}")"

  assert_contains "${out}" "source=generated" "generated fallback source"
  assert_contains "${out}" "key_len=64" "generated key length"
  assert_contains "${out}" "env_file_mode=600" "generated env file mode"
  [ -f "${stack}/.env" ] || fail "generated fallback did not write temp .env"
  generated="$(grep '^CORDUM_API_KEY=' "${stack}/.env" | cut -d= -f2-)"
  [[ "${generated}" =~ ^[0-9a-f]{64}$ ]] || fail "generated key is not 64 lowercase hex"
  assert_not_contains "${out}" "${generated}" "generated prepare output"
  pass "generated fallback is 64 lowercase hex and temp .env is restrictive"
}

test_concurrent_prepare_stack_serializes_env() {
  local stack fakebin state out1 out2 err1 err2 status1 status2 final_key final_hash hash1 hash2 count mode
  stack="$(new_stack_dir)"
  fakebin="$(new_fakebin_with_delayed_openssl)"
  state="${TMP_ROOT}/openssl-counter"
  out1="${TMP_ROOT}/concurrent-1.out"
  out2="${TMP_ROOT}/concurrent-2.out"
  err1="${TMP_ROOT}/concurrent-1.err"
  err2="${TMP_ROOT}/concurrent-2.err"

  FAKE_DOCKER_NAMES="" FAKE_OPENSSL_STATE="${state}" run_prepare_stack "${stack}" "${fakebin}" >"${out1}" 2>"${err1}" &
  local pid1=$!
  FAKE_DOCKER_NAMES="" FAKE_OPENSSL_STATE="${state}" run_prepare_stack "${stack}" "${fakebin}" >"${out2}" 2>"${err2}" &
  local pid2=$!

  status1=0
  wait "${pid1}" || status1=$?
  status2=0
  wait "${pid2}" || status2=$?

  [ "${status1}" -eq 0 ] || fail "first concurrent prepare-stack exited ${status1}; stderr=$(cat "${err1}")"
  [ "${status2}" -eq 0 ] || fail "second concurrent prepare-stack exited ${status2}; stderr=$(cat "${err2}")"
  [ -f "${stack}/.env" ] || fail "concurrent prepare-stack did not write .env"

  count="$(grep -c '^CORDUM_API_KEY=' "${stack}/.env")"
  [ "${count}" -eq 1 ] || fail "concurrent .env should contain exactly one CORDUM_API_KEY= line; found ${count}"
  final_key="$(grep '^CORDUM_API_KEY=' "${stack}/.env" | cut -d= -f2-)"
  [[ "${final_key}" =~ ^[0-9a-f]{64}$ ]] || fail "concurrent final key is not 64 lowercase hex"
  final_hash="$(sha256 "${final_key}")"
  hash1="$(extract_probe_value "${out1}" key_sha256)"
  hash2="$(extract_probe_value "${out2}" key_sha256)"
  [ "${hash1}" = "${final_hash}" ] || fail "first concurrent key hash diverged from final .env; first=${hash1} final=${final_hash}"
  [ "${hash2}" = "${final_hash}" ] || fail "second concurrent key hash diverged from final .env; second=${hash2} final=${final_hash}"
  mode="$(file_mode "${stack}/.env")"
  [ "${mode}" = "600" ] || fail "concurrent env file mode=${mode}, want 600"

  assert_not_contains "$(cat "${out1}" "${out2}" "${err1}" "${err2}")" "${final_key}" "concurrent prepare output"
  assert_not_contains "$(cat "${out1}" "${out2}" "${err1}" "${err2}")" "${CONCURRENT_KEY_ONE}" "concurrent prepare output"
  assert_not_contains "$(cat "${out1}" "${out2}" "${err1}" "${err2}")" "${CONCURRENT_KEY_TWO}" "concurrent prepare output"
  pass "concurrent prepare-stack serializes .env writes and keeps one shared key"
}

test_full_precedence_order() {
  local stack fakebin out
  stack="$(new_stack_dir)"
  printf 'CORDUM_API_KEY=%s\n' "${STACK_KEY}" > "${stack}/.env"
  fakebin="$(new_fakebin)"
  out="$(CORDUM_API_KEY="${ENV_KEY}" FAKE_DOCKER_NAMES="cordum-api-gateway-1" FAKE_DOCKER_KEY="${CONTAINER_KEY}" run_resolver "${stack}" "${fakebin}")"

  assert_contains "${out}" "source=env" "full precedence source"
  assert_contains "${out}" "key_sha256=$(sha256 "${ENV_KEY}")" "full precedence env hash"
  assert_not_contains "${out}" "${ENV_KEY}" "full precedence output"
  assert_not_contains "${out}" "${CONTAINER_KEY}" "full precedence output"
  assert_not_contains "${out}" "${STACK_KEY}" "full precedence output"
  pass "full precedence order keeps env var first"
}

test_compose_name_drift() {
  local stack fakebin out
  stack="$(new_stack_dir)"
  fakebin="$(new_fakebin)"
  out="$(FAKE_DOCKER_NAMES=$'unrelated\ncordum_api-gateway_1' FAKE_DOCKER_KEY="${CONTAINER_KEY}" run_resolver "${stack}" "${fakebin}")"

  assert_contains "${out}" "source=container" "compose v1/v2 container drift"
  assert_contains "${out}" "key_sha256=$(sha256 "${CONTAINER_KEY}")" "compose drift key hash"
  assert_not_contains "${out}" "${CONTAINER_KEY}" "compose drift output"
  pass "container-name drift is handled"
}

test_installer_does_not_echo_raw_keys() {
  if grep -Fq 'Cordum API key: ${CORDUM_API_KEY}' "${INSTALL}"; then
    fail "install.sh still contains a raw Cordum API key log line"
  fi

  local stack fakebin out
  stack="$(new_stack_dir)"
  fakebin="$(new_fakebin)"
  out="$(CORDUM_API_KEY="${OTHER_KEY}" run_resolver "${stack}" "${fakebin}")"
  assert_not_contains "${out}" "${OTHER_KEY}" "raw-key output"
  pass "installer test modes do not echo raw keys"
}

main() {
  test_env_wins
  test_container_wins_without_env
  test_stack_env_wins_without_env_or_container
  test_concurrent_prepare_stack_serializes_env
  test_generated_fallback_writes_restrictive_temp_env
  test_full_precedence_order
  test_compose_name_drift
  test_installer_does_not_echo_raw_keys
}

main "$@"
