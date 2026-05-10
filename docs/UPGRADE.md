# CordClaw Upgrade Guide

Operator-facing upgrade guide. Pair with `CHANGELOG.md` for the full diff. This
document is the answer to "I'm running CordClaw vN; what do I need to do to get
to vN+1?".

## Version matrix

| From  | To           | Required actions                                                                              | Optional actions                                                                                                                        |
| ----- | ------------ | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 0.1.0 | _Unreleased_ | None — defaults preserve previous behavior.                                                   | Re-run `setup/install.sh` to pick up `CORDUM_API_KEY` auto-detection. Reinstall the pack to enable the new pre-dispatch hooks.          |

When the next semver release is cut, append a row above and add a per-version
detail block below.

---

## 0.1.0 → Unreleased

### TL;DR

- No breaking changes. Existing deployments keep working with their current
  `CORDUM_API_KEY`, gateway URL, and pack.
- Recommended optional actions: pack reinstall to pick up the `before_agent_start`
  + `before_prompt_build` hooks (Security improvement); re-run `install.sh` to
  benefit from `CORDUM_API_KEY` auto-detection.

### Env var changes

No required env var changes. Existing variables (`CORDUM_API_KEY`, `CORDCLAW_API_KEY`,
gateway URL, profile selectors) keep their previous semantics.

### `setup/install.sh` behavior changes

`install.sh` now resolves `CORDUM_API_KEY` from a fixed priority chain (per epic
rail "CORDUM_API_KEY is single-source-of-truth"):

1. `CORDUM_API_KEY` exported in the operator's environment (operator knows what
   they want — wins).
2. `CORDUM_API_KEY` parsed out of a running `cordum-api-gateway*` container's
   env (adopt the live stack's key).
3. `CORDUM_API_KEY=` line in `${STACK_DIR}/.env` (load from a stopped stack).
4. Generated fresh via `openssl rand -hex 32` (no prior key found).

Operators who pre-set `CORDUM_API_KEY` see no behavior change. Operators who
relied on `install.sh` generating a key every run will instead see it adopted
from a running gateway / `.env` file when one is present — this is the desired
single-source-of-truth behavior, not a regression.

### Pack reinstall (optional, recommended)

The pack now ships policy primitives consumed by the new hooks. Reinstall via
the Cordum stack to pick them up:

```bash
cordumctl pack install cordclaw --upgrade
```

Existing policies that did not reference the new primitives keep working. Pack
rules with a top-level `description` key still need migration to YAML
comments + the `reason` field — Cordum's schema rejects `description` as a
top-level key (epic rail).

### Policy migration

Internal label rename: `count` → `denied_count` on rate-limit summary jobs
(task-578c89d2). Operators who built dashboards or alerting rules on the
old label key need to update those queries. Prometheus metric name
`cordclaw_rate_limited_total` is unchanged; only the **per-job label** on
the summary job emitted to `/api/v1/jobs` has changed.

### Phase 2 transport: gRPC → HTTP `/api/v1/jobs`

The daemon's pre-dispatch path now POSTs to the Cordum gateway's HTTP
`/api/v1/jobs` endpoint instead of opening a direct gRPC connection to the
Safety Kernel. For operators this means:

- Network: the daemon now needs HTTP egress to the gateway, not direct
  gRPC to the Safety Kernel. If you were running a tightened firewall that
  allowed only the gRPC port, open the gateway HTTP port and you can close
  the direct gRPC route.
- Auth: `CORDUM_API_KEY` is now used on every `/check` round-trip (previously
  it was used only for stack management). The single-source-of-truth chain
  above ensures the daemon and gateway agree on the key.
- Safety decisions still flow back through the gateway's existing
  `evaluateSubmitPolicy` path; existing policy bundles need no changes.

The previous direct gRPC client (`daemon/internal/client/safety.go`) is
deprecated and will be removed in a future release.

## When to upgrade

Recommended: every CordClaw deployment running in production should upgrade
when the next release is cut. The Phase 1 hook coverage adds two real
attack-class fixes (cron-bypass escalation, prompt-level PII leakage) and the
Phase 2 transport unifies the audit + tenancy path — both are Security
improvements with no operator-facing breaking changes.

## How to roll back

If a deployment needs to roll back to 0.1.0:

1. Pin the daemon image to the previous tag (e.g.
   `ghcr.io/cordum-io/cordclaw-daemon:0.1.0`) in your compose / Helm values.
2. Roll back the pack with `cordumctl pack install cordclaw --version 0.1.0`.
3. The plugin TypeScript build is forward/backward compatible at the hook
   surface; no rollback action is required for the OpenClaw gateway.
4. If you had updated label-querying dashboards to read `denied_count`,
   restore the prior `count` query (or query both during the transition
   window).

There is no schema migration to undo — the changes ship as additive policy
primitives + new hook handlers. A rollback is fully clean.
