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
4. Production handlers backed by `CordumJobsClient` auto-wire that callback to submit a Cordum job on the matching `job.openclaw.*` topic with `cordclaw.shadow=true` labels. Offline/test handlers that do not implement the Cordum jobs submitter fall back to a structured `cordclaw shadow event` log line. Both paths increment `cordclaw_shadow_events_total`.

## Reviewing results

Production implementation:

- Jobs page: filter `/govern/jobs` with:

```text
labels.cordclaw.shadow=true
```

- Prometheus: scrape `cordclaw_shadow_events_total`.
- Offline/test fallback logs: search for `cordclaw shadow event`.

Shadow jobs include these labels:

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
- Cordum job emission uses the same `/api/v1/jobs` submit path as policy checks; if that submitter is unavailable, the daemon degrades to logs/metrics rather than changing enforcement.

## Smoke-test evidence

The automated smoke test `TestShadowPolicySmokeTenCacheMisses` loads a policy file with `openclaw-shadow-strict-web-fetch`, sends 10 unique `web_fetch` requests, and verifies:

- every real response remains uncached `ALLOW`,
- 10 shadow events are emitted with `would_decision=DENY`, and
- `cordclaw_shadow_events_total` reaches 10.

The gateway integration test `TestCheckEmitsShadowEventViaCordumGateway` spins
up a fake Cordum Gateway, sends a matching `web_fetch` check, and verifies:

- the real `/check` response remains `ALLOW`,
- exactly one shadow job is POSTed to `/api/v1/jobs`,
- the job topic is `job.openclaw.tool_call`, and
- labels include `cordclaw.shadow=true`,
  `cordclaw.would_decision=DENY`, and
  `cordclaw.rule_id=openclaw-shadow-strict-web-fetch`.
