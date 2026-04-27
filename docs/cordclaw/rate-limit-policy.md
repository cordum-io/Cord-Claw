# CordClaw rate-limit policy constraints

CordClaw enforces a daemon-local per-agent emission rate limit before it sends
an OpenClaw action to Cordum. The daemon-wide default comes from
`CORDCLAW_EMIT_RATE_LIMIT` / `config.EmitRateLimit` and falls back to `50` RPS.
Policy bundles can override that default for a named agent, but only through a
trusted Cordum safety-decision constraint.

## Constraint schema

| Field | Value |
| --- | --- |
| Constraint key | `cordclaw.emit_rate_limit_rps` |
| Type | JSON number compatible with Go `float64` (string and `json.Number` decode forms are accepted defensively) |
| Range | `1.0 <= v <= 1000.0` |
| Source | Trusted policy bundle response (`decision.constraints`) only |
| Cache scope | Per agent id, per policy snapshot |

Client-supplied OpenClaw request labels are ignored for rate-limit overrides.
This includes labels such as `cordclaw.emit_rate_limit`,
`cordclaw.emit_rate_limit_rps`, and per-agent variants. Those labels are
untrusted input and must not weaken daemon fail-closed behavior.

Invalid constraint values are ignored: missing values, non-numeric strings,
`NaN`, `Infinity`, values below `1.0`, and values above `1000.0` do not create a
cache entry.

## First-request semantics

The first request from an agent uses the daemon-wide default because the daemon
has not yet observed a trusted policy decision for that agent. When Cordum
returns a safety decision with `constraints.cordclaw.emit_rate_limit_rps`, the
daemon caches the validated override for that agent. Subsequent requests for the
same agent use the cached policy value until the safety snapshot changes.

Snapshot rotation clears the override cache in the same path that clears the
CordClaw decision cache (`updateSnapshot`). This prevents stale policy-derived
limits from surviving a policy-bundle update.

## Example pack rule

Policy rule entries must not use a top-level `description` field; Cordum's policy
schema rejects it. Use comments plus the `reason` field instead.

```yaml
# Trusted high-throughput agent class. The daemon reads only this policy
# decision constraint, never the incoming OpenClaw request labels.
- id: openclaw-tool_allow-high-throughput-rate-limit
  match:
    topics: ["job.openclaw.tool_call"]
    label_allowlist:
      agent_class:
        - high_throughput
  decision: allow_with_constraints
  constraints:
    cordclaw.emit_rate_limit_rps: 200
  reason: high-throughput agent class
```

This raises matching agents from the daemon default (for example `50` RPS) to
`200` RPS. The same key can lower an agent to a more restrictive value, such as
`5` RPS, when a trusted policy bundle wants quarantine-style throttling.

## Observability and audit

Existing CordClaw audit entries already include the hook, agent id, and risk
labels for each policy check. Whether a rate-limit override came from the cache
or the default is internal daemon state; no additional audit field is emitted for
this task. Operators can infer the active policy path from the Cordum job's
safety-decision constraints and from rate-limited decisions with reason
`rate_limited`.
