# CordClaw Shadow-Mode Policy Rules

Shadow mode lets operators preview a stricter CordClaw policy rule against live OpenClaw traffic without changing the actual enforcement decision returned to the plugin.

## Enable a shadow rule

Add `enforce: false` to a rule in `pack/policies/openclaw-safety.yaml`:

```yaml
rules:
  - id: openclaw-shadow-strict-web-fetch
    enforce: false
    match:
      topics: ["job.openclaw.tool_call"]
      risk_tags: ["network", "read"]
    decision: deny
    reason: Future stricter web_fetch policy would block network read tool calls.
```

Omitting `enforce` defaults to `true` for backwards compatibility.

## What happens at runtime

1. The daemon sends the action to Cordum Gateway as usual.
2. The real response from Cordum remains authoritative; shadow rules do not change ALLOW/DENY/approval behavior.
3. On cache misses, matching shadow rules emit a `policy.ShadowEvent` through the injectable `onShadowEvent` callback.
4. The current default callback logs a structured `cordclaw shadow event` line and increments `cordclaw_shadow_events_total`.

## Reviewing results

Current implementation:

- Daemon structured logs: search for `cordclaw shadow event`.
- Prometheus: scrape `cordclaw_shadow_events_total`.

After follow-up `task-fc766e2a`, the callback will submit real Cordum jobs. Then operators can review shadow decisions on `/govern/jobs` with:

```text
labels.cordclaw.shadow=true
```

Shadow jobs will include these labels:

- `cordclaw.shadow=true`
- `cordclaw.rule_id=<rule id>`
- `cordclaw.would_decision=<ALLOW|DENY|REQUIRE_APPROVAL|...>`
- `cordclaw.would_reason=<rule reason>`
- `cordclaw.hook_name=<OpenClaw hook>`

## Limitations and safety rules

- Shadow evaluation is sampled at cache-miss rate. Cache hits return the cached real decision and do not re-run shadow rules until the cache entry expires.
- Shadow rules never enqueue approvals. If `enforce: false` is paired with `decision: require_approval`, the event is logged as would-require-approval but the real decision still controls the approval workflow.
- Shadow events contain rule metadata only; prompt/tool payload text is not passed into the callback.
- The v1 Prometheus counter is unlabeled to avoid unbounded rule-id cardinality. Per-rule metrics are tracked separately in follow-up `cordclaw shadow metric cardinality decision`.
- Full Jobs page visibility is intentionally deferred to `task-fc766e2a`; until then, use daemon logs and metrics.

## Smoke-test evidence

The automated smoke test `TestShadowPolicySmokeTenCacheMisses` loads a policy file with `openclaw-shadow-strict-web-fetch`, sends 10 unique `web_fetch` requests, and verifies:

- every real response remains uncached `ALLOW`,
- 10 shadow events are emitted with `would_decision=DENY`, and
- `cordclaw_shadow_events_total` reaches 10.
