# Examples

This folder contains runnable payloads and starter configs used by `docs/GETTING_STARTED.md`.

## Simulate Payloads

- `simulate/allow-safe-exec.json`: safe shell command
- `simulate/deny-destructive-exec.json`: destructive command (expected deny)
- `simulate/require-approval-package-install.json`: package install command (often approval or constrained allow, based on profile)

Run one:

```bash
curl -sS -X POST http://127.0.0.1:19090/simulate \
  -H "Content-Type: application/json" \
  -d @examples/simulate/deny-destructive-exec.json | jq .
```

## Policy Example

- `policies/custom-moderate.yaml`: moderate-style profile that permits package installs with constraints

Apply to local stack:

```bash
cp examples/policies/custom-moderate.yaml ~/.cordclaw/config/safety.yaml
cd ~/.cordclaw
docker compose --env-file .env restart safety-kernel
```

## Remote Cordum Env Example

- `env/cordclaw-remote.env`: template env for pointing `cordclaw-daemon` to an existing Safety Kernel.
