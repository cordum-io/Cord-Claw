# CordClaw shadow-event rate limit

Status: accepted 2026-04-27  
Task: task-e3f68f1c

## Why this exists

Shadow mode lets operators stage stricter `enforce:false` rules without changing
the real safety decision. That visibility is valuable, but it also creates a
flood risk: a broad shadow rule on a daemon processing 1000 OpenClaw actions per
second could emit 1000 Cordum shadow jobs per second.

CordClaw caps shadow-event emission per rule id before the callback/job path.
The default cap is `5` emitted shadow events per second per rule. Extra matches
are not lost silently: they are coalesced into one summary job per rule per
rate-limited second.

## How it works

The real policy decision is computed before shadow-event throttling. On cache
misses, the daemon evaluates shadow rules and then calls `dispatchShadowEvent`
for each matching shadow rule.

`dispatchShadowEvent` performs these operations in order:

1. Increment `cordclaw_shadow_events_total` unconditionally. This keeps
   aggregate visibility for every shadow match, including matches whose callback
   emission is later throttled.
2. Consult the per-rule shadow emitter. The emitter is keyed by
   `ShadowEvent.RuleID` and defaults to `5` events per second per rule.
3. If the rule is over budget, drop only the callback emission and increment the
   unlabeled `cordclaw_shadow_rate_limited_total` counter.
4. Coalesce over-budget denials into one Cordum summary job on
   `job.openclaw.shadow_rate_limit_summary` after the current second closes.
5. If the event is under budget, dispatch the existing shadow callback through
   the bounded callback semaphore.

The summary job labels include:

- `cordclaw.shadow: "true"`
- `cordclaw.shadow.rate_limited: "true"`
- `cordclaw.rule_id: <rule-id>`
- `denied_count: <count-in-window>`
- `window_start: <unix-second>`

The job envelope repeats the same values using native JSON types. The submit
path uses a two-second timeout and logs failures rather than blocking the
request path.

## Operator knobs

| Knob | Default | Range | Effect |
| --- | --- | --- | --- |
| `CORDCLAW_SHADOW_EMIT_RATE_LIMIT` | `5` | `1..1000` | Maximum emitted shadow callbacks/jobs per second per rule id. |

The limiter inherits the existing emitter's in-memory state lifecycle:

- Entries are keyed by normalized rule id; empty ids coalesce under `unknown`.
- Inactive entries are eligible for GC after one hour.
- `Handler.Close()` stops pending summary timers during daemon shutdown.

If operators need full-fidelity shadow jobs during a controlled test, set the
limit above the expected per-rule event rate for that daemon. Do not raise the
limit just to debug a flood in production; use summary jobs to identify the hot
rule first.

## Metrics

CordClaw exposes two shadow-mode counters:

| Metric | Labels | Meaning |
| --- | --- | --- |
| `cordclaw_shadow_events_total` | none | Every matching shadow rule event seen by the daemon, before emission throttling. |
| `cordclaw_shadow_rate_limited_total` | none | Shadow callback/job emissions suppressed by the per-rule limiter. |

`rule_id` is intentionally **not** a Prometheus label. Rule ids are useful for
forensics, but exposing them as labels would create avoidable cardinality risk.
Per-rule visibility comes from the durable summary jobs on
`job.openclaw.shadow_rate_limit_summary`.

Alert on the aggregate counter:

```promql
rate(cordclaw_shadow_rate_limited_total[5m])
```

Then inspect Cordum jobs filtered to
`job.openclaw.shadow_rate_limit_summary` and group by
`labels.cordclaw.rule_id`.

## Real enforcement is unaffected

Shadow throttling sits after `policy.EvaluateWithShadow` has separated enforced
rules from shadow-only rules and after the daemon has already obtained the real
decision for the OpenClaw action. The throttle gates only the
`onShadowEvent` callback path.

Regression test
`TestEvaluateShadowRules_EnforcementUnaffected` proves that an enforced
`REQUIRE_APPROVAL` decision stays unchanged even when the matching shadow rule's
event emission is rate-limited. This preserves the task rail: real enforcement
decisions must not be changed by shadow-rate limiting.

## Cross-references

- Aggregate rate-limit metric decision:
  [`docs/cordclaw/rate-limit-metrics.md`](rate-limit-metrics.md).
- Trusted per-agent rate-limit override schema:
  [`docs/cordclaw/rate-limit-policy.md`](rate-limit-policy.md).
- OpenClaw policy bundle with shadow rules:
  [`pack/policies/openclaw-safety.yaml`](../../pack/policies/openclaw-safety.yaml).
- Shadow event dispatch implementation:
  [`daemon/internal/server/server.go`](../../daemon/internal/server/server.go).
- Shadow evaluator implementation:
  [`daemon/internal/policy/shadow.go`](../../daemon/internal/policy/shadow.go).
