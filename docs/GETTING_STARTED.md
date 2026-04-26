# CordClaw Getting Started

This tutorial walks from install to real policy decisions in a local setup, then shows how to point CordClaw at an existing Cordum deployment.

You will do all of the following:

1. Install CordClaw and the local Cordum stack
2. Verify your first decision
3. Confirm dangerous commands are blocked
4. Customize policy behavior
5. Switch policy profiles
6. Inspect the audit trail
7. Run simulation payloads from `examples/`
8. Connect the daemon to an existing Cordum environment

## Prerequisites

- Docker + `docker compose`
- `curl`
- `openssl`
- Node.js + npm
- Optional: OpenClaw CLI (`openclaw`) for plugin commands

## 1) Install CordClaw and local Cordum

From the repo root:

```bash
cd setup
OPENCLAW_SKIP=true ./install.sh
```

Notes:

- The installer creates a local stack directory at `~/.cordclaw` by default.
- Use `CORDCLAW_PROFILE=strict|moderate|permissive` to choose the baseline profile during install.
- If you want OpenClaw plugin install/config as part of setup, remove `OPENCLAW_SKIP=true`.
- The Docker stack mounts a `cordclaw-daemon-state` volume at `/var/lib/cordclaw`.
  The daemon stores cron-origin decisions there by default so cron jobs that
  were allowed by policy stay recognized after a daemon restart.

## 2) Verify your first governance decision

Check daemon health and governance status:

```bash
curl -sS http://127.0.0.1:19090/health | jq .
openclaw cordclaw status
```

If OpenClaw CLI is not installed, use:

```bash
curl -sS http://127.0.0.1:19090/status | jq .
```

Run a safe simulation:

```bash
openclaw cordclaw simulate --tool exec --command "echo hello"
```

CLI-free equivalent:

```bash
curl -sS -X POST http://127.0.0.1:19090/simulate \
  -H "Content-Type: application/json" \
  -d '{"tool":"exec","command":"echo hello"}' | jq .
```

Expected result: `ALLOW` or `CONSTRAIN`, depending on active policy profile.

## 3) Confirm dangerous command blocking

Simulate a destructive command:

```bash
openclaw cordclaw simulate --tool exec --command "rm -rf /"
```

CLI-free equivalent:

```bash
curl -sS -X POST http://127.0.0.1:19090/simulate \
  -H "Content-Type: application/json" \
  -d @examples/simulate/deny-destructive-exec.json | jq .
```

Expected result: `DENY` with a reason describing destructive command blocking.

## 4) Customize policy behavior

A ready-to-edit custom policy is provided at:

- `examples/policies/custom-moderate.yaml`

Apply it to the local stack:

```bash
cp examples/policies/custom-moderate.yaml ~/.cordclaw/config/safety.yaml
cd ~/.cordclaw
docker compose --env-file .env restart safety-kernel
docker compose --env-file .env exec -T gateway sh -lc 'cordumctl pack install /packs/cordclaw --upgrade'
```

Re-test package install simulation:

```bash
openclaw cordclaw simulate --tool exec --command "npm install lodash"
```

CLI-free equivalent:

```bash
curl -sS -X POST http://127.0.0.1:19090/simulate \
  -H "Content-Type: application/json" \
  -d @examples/simulate/require-approval-package-install.json | jq .
```

With the example custom policy, package-install commands are allowed with constraints instead of requiring approval.

## 5) Switch between strict, moderate, permissive profiles

The installer copies all profile templates into `~/.cordclaw/templates/`.

Switch profiles by replacing `~/.cordclaw/config/safety.yaml` and restarting:

```bash
cp ~/.cordclaw/templates/policy-strict.yaml ~/.cordclaw/config/safety.yaml
cd ~/.cordclaw
docker compose --env-file .env restart safety-kernel
```

Then validate behavior:

```bash
openclaw cordclaw simulate --tool exec --command "echo check profile"
openclaw cordclaw simulate --tool exec --command "rm -rf /"
```

Repeat with `policy-moderate.yaml` or `policy-permissive.yaml` to compare outcomes.

## 6) Inspect the audit trail

View recent decisions from daemon audit:

```bash
openclaw cordclaw audit --limit 20
curl -sS "http://127.0.0.1:19090/audit?limit=20" | jq .
```

The audit stream includes decision, reason, timestamp, and whether it was served from cache.

## 7) Run simulation payloads from `examples/`

From the repo root:

```bash
curl -sS -X POST http://127.0.0.1:19090/simulate \
  -H "Content-Type: application/json" \
  -d @examples/simulate/allow-safe-exec.json | jq .

curl -sS -X POST http://127.0.0.1:19090/simulate \
  -H "Content-Type: application/json" \
  -d @examples/simulate/deny-destructive-exec.json | jq .
```

See `examples/README.md` for the full list.

## 8) Connect CordClaw daemon to an existing Cordum environment

When you are not using the local Docker stack, configure daemon env vars directly:

```bash
set -a
source examples/env/cordclaw-remote.env
set +a

cordclaw-daemon
```

Required variables:

- `CORDCLAW_KERNEL_ADDR`
- `CORDCLAW_API_KEY`
- `CORDCLAW_TENANT_ID`

Optional TLS variables:

- `CORDCLAW_KERNEL_INSECURE=false`
- `CORDCLAW_KERNEL_TLS_CA=/path/to/ca.pem`

Cron-origin decision state:

- Production should use the default BoltDB backend:
  `CORDCLAW_CRON_DECISION_STORE=bolt`.
- Mount a writable state directory and keep
  `CORDCLAW_CRON_DECISION_PATH=/var/lib/cordclaw/cron-decisions.db` inside it.
- `CORDCLAW_CRON_DECISION_TTL=24h` preserves the same 24-hour retention window
  as in-memory mode. Expired or unknown cron IDs fail closed with
  `cron-origin-policy-mismatch`.
- `CORDCLAW_CRON_DECISION_STORE=memory` is for dev/test only; it forgets all
  allowed cron decisions on daemon restart.

Once running, verify:

```bash
curl -sS http://127.0.0.1:19090/status | jq .
openclaw cordclaw status
```

If `kernel` is not `connected`, check:

- network reachability to Safety Kernel gRPC
- API key and tenant ID values
- TLS CA path / certificate chain

## Related Docs

- `README.md`
- `docs/ARCHITECTURE.md`
- `docs/POLICY_GUIDE.md`
- `docs/TROUBLESHOOTING.md`
