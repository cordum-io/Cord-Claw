# CordClaw setup

`setup/install.sh` installs the local CordClaw daemon/OpenClaw wiring and can
optionally start the Cordum stack. The important invariant is that
`CORDUM_API_KEY` is a **single source of truth** across Cordum API gateway,
CordClaw daemon, and OpenClaw plugin configuration. A CordClaw install must
reuse the key from an existing Cordum stack instead of generating a new,
divergent key.

## Cordum API key precedence

`install.sh` resolves `CORDUM_API_KEY` in this order:

1. `CORDUM_API_KEY` already exported in the operator environment.
2. `CORDUM_API_KEY` from a running `cordum-api-gateway` container.
3. `CORDUM_API_KEY` from the existing CordClaw stack `.env`.
4. A freshly generated 32-byte value, rendered as 64 lowercase hex characters.

The generated fallback is only for clean first installs. Re-running the
installer against an existing Cordum stack should adopt the running gateway key
non-interactively.

## Local Docker install

For a local Cordum stack, leave `CORDUM_API_KEY` unset and let the installer
adopt the running gateway key:

```bash
unset CORDUM_API_KEY
CORDUM_UPGRADE=true ./setup/install.sh
```

To inspect the running gateway key without printing it, compare hashes:

```bash
docker inspect cordum-api-gateway-1 \
  --format '{{range .Config.Env}}{{println .}}{{end}}' \
  | grep '^CORDUM_API_KEY=' \
  | cut -d= -f2- \
  | sha256sum \
  | awk '{print "gateway_key_sha256=" $1}'

grep '^CORDUM_API_KEY=' "${CORDCLAW_HOME:-$HOME/.cordclaw}/.env" \
  | cut -d= -f2- \
  | sha256sum \
  | awk '{print "cordclaw_env_key_sha256=" $1}'
```

The hashes should match after install or re-install. Do not paste full API keys
into logs, issue comments, or PR bodies.

## Concurrent installs and `.env` safety

Stack preparation is serialized with a portable `${CORDCLAW_HOME:-$HOME/.cordclaw}/.install.lock`
directory lock. The lock wraps both API-key resolution and stack file writes so
two first installs cannot generate divergent fallback keys. If another installer
is active, a second process waits up to `CORDCLAW_LOCK_TIMEOUT_SECONDS` seconds
(default `120`) and then fails closed with the lock path only; diagnostics never
include raw API keys.

The stack `.env` file is written to a same-directory temporary file with a
restrictive umask, chmodded to mode `600`, and atomically moved into place. If a
write fails, the temporary file is removed. Hash-only diagnostics remain the
supported way to compare keys.

## Non-Docker and Kubernetes operators

If Cordum is not running on the same Docker host, provide the intended key
explicitly:

```bash
export CORDUM_API_KEY='<value from your Cordum gateway secret store>'
CORDUM_UPGRADE=false ./setup/install.sh
```

For Kubernetes, source `CORDUM_API_KEY` from the same Secret consumed by the
Cordum API gateway and CordClaw daemon deployment. Do not generate a separate
CordClaw-only key.

## Troubleshooting 401 responses

`401 Unauthorized` from the Cordum gateway usually means the CordClaw `.env`
key diverged from the running gateway key.

1. Compare the two SHA-256 hashes using the commands above.
2. If they differ, unset any stale shell override and re-run the installer:

   ```bash
   unset CORDUM_API_KEY
   ./setup/install.sh
   ```

3. Verify the authenticated status endpoint with the running key without
   printing the key:

   ```bash
   key="$(docker inspect cordum-api-gateway-1 \
     --format '{{range .Config.Env}}{{println .}}{{end}}' \
     | grep '^CORDUM_API_KEY=' \
     | cut -d= -f2-)"

   curl -skf -H "X-API-Key: ${key}" \
     https://127.0.0.1:8081/api/v1/status >/dev/null
   ```

The installer's diagnostic modes print only source names, key lengths, and
SHA-256 hashes:

```bash
./setup/install.sh --dry-run-key
CORDCLAW_TEST_MODE=prepare-stack CORDCLAW_HOME="$(mktemp -d)" ./setup/install.sh
```

