# CordClaw Fail-Mode Behaviour

When the cordclaw-daemon cannot reach its upstream Cordum gateway (network
partition, gateway restart, gateway down for an emergency rollback, etc.),
it falls back to a local fail-mode policy. Until task-44b6aa5e the behaviour
was uniform — every action was either allowed or denied based on a single
`CORDCLAW_FAIL_MODE` value. A uniform `closed` mode was safe but blocked
benign read-only actions during outages; a uniform `open` mode kept things
working but allowed dangerous mutations through.

The graduated mode introduced here splits the decision per action class.
Reads and web searches fail open (low blast radius); execs, writes,
schedule-creations, browser interactions, and outbound messages fail
closed.

## Configuration

### `CORDCLAW_FAIL_MODE`

| Value        | Behaviour                                                                     |
| ------------ | ----------------------------------------------------------------------------- |
| `graduated`  | (default) Per-action lookup against the table below.                          |
| `open`       | Uniform fail-open. The per-action table is **not** consulted.                 |
| `closed`     | Uniform fail-closed. The per-action table is **not** consulted.               |

`open` and `closed` remain available for back-compat with prior deployments
and for emergency overrides; `graduated` is the recommended production value.

### `CORDCLAW_FAIL_MODE_BY_ACTION` (graduated mode only)

JSON map of action-tag → `"open" | "closed"` that **adds to** the
conservative defaults. Operators cannot relax safety by omission —
absent tags fall through to `closed`.

```bash
# Open browser actions in addition to the default read fail-open;
# everything else stays fail-closed.
export CORDCLAW_FAIL_MODE_BY_ACTION='{"browser":"open"}'
```

| Tag         | Default mode | Emitted by                                     |
| ----------- | ------------ | ---------------------------------------------- |
| `read`      | **open**     | `read`, `web_search`, `web_fetch`              |
| `exec`      | closed       | `exec` (shell)                                 |
| `write`     | closed       | `write`, `exec` (which carries `write`), `browser.action`, `sessions_send`, `memory_write`, `cron.create` |
| `messaging` | closed       | `sessions_send`                                |
| `schedule`  | closed       | `cron.create`                                  |
| `browser`   | closed       | `browser.navigate`, `browser.action`           |

A request whose `RiskTags` carry **multiple** priority tags is resolved
most-restrictive-first: priority order is
`exec → write → messaging → schedule → browser → read`. Concretely, an
action tagged both `read` and `write` fails closed even if `read` is set
to `open`. This is intentional: a fail-open opt-in for one tag must
never relax a co-occurring restrictive tag.

### Validation

`LoadFromEnv` rejects malformed input at daemon startup so misconfiguration
never lands in production traffic:

| Input                                                  | Result                                            |
| ------------------------------------------------------ | ------------------------------------------------- |
| `CORDCLAW_FAIL_MODE_BY_ACTION='{not-json'`             | error — daemon refuses to start                   |
| `CORDCLAW_FAIL_MODE_BY_ACTION='{"read":"yolo"}'`       | error — value must be `"open"` or `"closed"`      |
| `CORDCLAW_FAIL_MODE_BY_ACTION='{"unknown_tag":"open"}'`| starts; emits `slog.Warn` and ignores the entry   |

The unknown-tag warn-and-ignore behaviour is deliberate: the canonical
tag set evolves alongside the mapper, and operators rolling configuration
ahead of daemon upgrades should not see hard failures over a typo or a
not-yet-emitted tag.

## Observability

When fail-mode is invoked, the daemon emits a single structured log line
per request:

```
level=INFO msg="cordclaw fail-mode decision applied"
  cordclaw.fail_mode=open
  cordclaw.cordum_reachable=false
  tags=filesystem,read
```

`cordclaw.fail_mode` is the resolved mode (`open` or `closed`).
`cordclaw.cordum_reachable=false` indicates the line is from the
fail-mode path, not the normal-decision path. Operators should alert on
sustained `cordclaw.cordum_reachable=false` as a primary outage signal,
with a secondary alert on a sudden spike of `cordclaw.fail_mode=open`
volume (which usually indicates either a gateway outage or a config
drift).

## Operator playbook

### Verifying the table without an outage

1. Set `CORDCLAW_FAIL_MODE=graduated` in the daemon env.
2. Stop the cordum-api-gateway container: `docker compose stop cordum-api-gateway-1`.
3. Send a read request:
   ```bash
   curl -X POST http://127.0.0.1:19090/check \
        -H 'content-type: application/json' \
        -d '{"tool":"read","path":"/var/log/app.log"}'
   ```
   Expect `decision=ALLOW` and a daemon log line with `cordclaw.fail_mode=open`.
4. Send an exec request:
   ```bash
   curl -X POST http://127.0.0.1:19090/check \
        -H 'content-type: application/json' \
        -d '{"tool":"exec","command":"echo hi"}'
   ```
   Expect `decision=DENY` and `cordclaw.fail_mode=closed`.
5. Restart the gateway: `docker compose start cordum-api-gateway-1`.

### Tightening the defaults further

Some teams prefer ALL-closed during outages. Set:

```bash
export CORDCLAW_FAIL_MODE=closed
```

This bypasses the per-action table entirely.

### Loosening the defaults

Adding tags to fail-open requires explicit opt-in via
`CORDCLAW_FAIL_MODE_BY_ACTION`. There is no "fail-open everything"
shortcut other than `CORDCLAW_FAIL_MODE=open`, which is intentionally
the same surface that already existed pre-task-44b6aa5e.
