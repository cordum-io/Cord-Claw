# CordClaw rate-limit metrics decision

Status: accepted 2026-04-27  
Task: task-ad5dbc61

## Decision

CordClaw keeps `cordclaw_rate_limited_total` intentionally unlabeled. Per-agent
rate-limit visibility is provided through rate-limit summary jobs and the daemon
audit trail rather than Prometheus `agent_id` labels.

This decision protects operators from unbounded metric cardinality while keeping
the current forensic surfaces intact. It is reversible if the revisit criteria
near the end of this document become true.

## Existing per-agent telemetry surfaces

CordClaw currently exposes rate-limit activity through three complementary
surfaces. Only the first two are per-agent; the Prometheus counter is the
low-cardinality aggregate signal for alerting.

| Surface | Where it lives | Carries | Primary consumer | Retention / latency |
| --- | --- | --- | --- | --- |
| Rate-limit summary jobs | Cordum jobs on `job.openclaw.rate_limit_summary` | `agent_id`, `denied_count`, `window_start`, `cordclaw.rate_limited=true` | Operators using Cordum's `/govern/jobs` page or job APIs | Durable in Cordum's job store; emitted about one second after the denial window closes |
| Daemon audit log | CordClaw daemon `/audit` endpoint | `agent_id`, copied `risk_tags`, and `rate_limit:true` on rate-limited DENYs | Local incident response and short-window debugging | In-process FIFO ring of 1000 entries; millisecond latency; per daemon instance |
| Aggregate Prometheus counter | CordClaw daemon `/metrics` as `cordclaw_rate_limited_total` | Total rate-limited denials for the daemon | Alerting and SLO dashboards | In-memory Prometheus scrape target; millisecond latency; per daemon instance |

### Summary jobs

The summary-job path is the canonical per-agent operations surface. The daemon
batches denial counts inside the per-agent limiter and emits one best-effort
job per agent per second. That job has topic `job.openclaw.rate_limit_summary`,
so Cordum's existing job search and dashboard filtering can show hot agents
without adding a new CordClaw dashboard.

The current implementation is in
[`daemon/internal/server/server.go`](../../daemon/internal/server/server.go#L350-L387).
The labels map includes:

- `cordclaw.rate_limited: "true"`
- `agent_id: <agent-id>`
- `denied_count: <count-in-window>`
- `window_start: <unix-second>`

The job envelope repeats the same values using native JSON types. The submit
path uses a two-second timeout and logs failures rather than blocking the
request path.

### Audit log

The audit log is the short-window forensic surface. When the emitter denies a
request, the daemon appends an audit entry with the mapped tool, DENY decision,
`reason=rate_limited`, and a details map containing:

- `hook`
- `agent_id`
- `risk_tags`
- `rate_limit: true`

The current implementation is in
[`daemon/internal/server/server.go`](../../daemon/internal/server/server.go#L529-L542).
The audit ring itself is capped by `appendAudit` in
[`daemon/internal/server/server.go`](../../daemon/internal/server/server.go#L968-L974),
which keeps only the newest `auditSize` entries. At the time of this decision,
`auditSize` is 1000 entries per daemon.

### Aggregate counter

The aggregate counter remains the Prometheus-facing signal. It is declared in
[`daemon/internal/ratelimit/emitter.go`](../../daemon/internal/ratelimit/emitter.go#L53-L58)
as `cordclaw_rate_limited_total` with no labels. It increments on every denied
emission.

The counter answers the alerting question: "Is this daemon rate-limiting
OpenClaw actions?" Operators should use summary jobs and audit entries to answer
"which agent caused the rate limiting?"

## Why not bounded per-agent labels

Per-agent Prometheus labels are attractive because they make a real-time panel
such as `sum by (agent_id) (rate(cordclaw_rate_limited_total[5m]))` easy to
build. CordClaw is deliberately not shipping that surface now because even a
bounded design adds operational complexity and new failure modes that the
existing job and audit surfaces avoid.

A safe per-agent metric design would need at least:

1. A hard label-cardinality cap.
2. A configured cap name and default, for example
   `CORDCLAW_PROM_PER_AGENT_LABEL_CAP`.
3. A top-K or LRU data structure keyed by normalized agent id.
4. Eviction aligned with the limiter's current `agentEntryTTL` of one hour.
5. Tests proving inactive agents are removed from both limiter state and metric
   cardinality state.
6. Operator documentation explaining cap behavior, dropped/evicted agents, and
   dashboard interpretation.
7. Cross-tenant review for deployments that share a daemon across tenant-like
   agent namespaces.

Those costs are not justified while summary jobs already provide durable
per-agent counts and the audit log already provides low-latency local context.
Keeping Prometheus unlabeled also prevents accidental cardinality explosions
from attacker-controlled, generated, or misconfigured `agent_id` values.

## Rejected alternatives

### Unbounded `agent_id` labels

Rejected. Unbounded labels are the simplest implementation but the worst
operational outcome. Any deployment with many ephemeral agents, generated agent
ids, or malicious agent-id churn could create an unbounded number of Prometheus
time series. The task rail explicitly forbids this unless there is an eviction
or cardinality cap.

### Bounded LRU label cap

Rejected for now. A bounded LRU cap could be safe if engineered carefully, but
it adds a second state machine next to the existing rate limiter. The daemon
would need to evict metric series when agent limiter entries expire, define
what happens when the cap is full, and explain how dashboards should interpret
missing agents. This is a larger feature than the current operator need.

### Heavy-hitter or sketch-based top-K metric

Rejected for now. A heavy-hitter sketch avoids per-agent unbounded labels, but
it is approximate and harder for operators to reason about during incident
response. It would also still need a labeled export surface for the current
heavy hitters, including cap, churn, and eviction documentation. Summary jobs
are exact and already flow through Cordum's job store.

### Per-tenant or hashed labels

Rejected for now. Hashing agent ids reduces direct leakage but does not remove
cardinality risk. Per-tenant labels can be safe only when tenant cardinality is
bounded by deployment contract, which CordClaw does not enforce at the daemon
metric boundary. Neither option answers the operator's per-agent forensic
question as clearly as summary jobs.

## Revisit criteria

Reopen this decision if one or more of the following becomes true:

1. Operators require a formal per-agent rate-limit SLI in Prometheus rather
   than Cordum jobs.
2. A dashboard requirement needs real-time per-agent data and the one-second
   summary-job latency is not acceptable.
3. Multi-tenant deployments make the daemon audit FIFO too short for common
   investigations, even with summary jobs present in the Cordum job store.
4. Cordum introduces a shared, bounded-cardinality metric helper that can evict
   labels safely and consistently across services.
5. The rate-limit summary job path becomes unavailable in a deployment mode
   where Prometheus remains available.

If this decision is revisited, the new implementation must keep the existing
unlabeled aggregate counter and must prove inactive agents are removed from any
new metric/cardinality state.

## Cross-references

- Override-side schema and trust boundary:
  [`docs/cordclaw/rate-limit-policy.md`](rate-limit-policy.md).
- Unlabeled counter declaration:
  [`daemon/internal/ratelimit/emitter.go`](../../daemon/internal/ratelimit/emitter.go#L53-L58).
- Summary-job callback:
  [`daemon/internal/server/server.go`](../../daemon/internal/server/server.go#L350-L387).
- Rate-limited DENY audit append:
  [`daemon/internal/server/server.go`](../../daemon/internal/server/server.go#L529-L542).
- Audit FIFO cap:
  [`daemon/internal/server/server.go`](../../daemon/internal/server/server.go#L968-L974).
- Upgrade note for `denied_count` label and stable Prometheus metric name:
  [`docs/UPGRADE.md`](../UPGRADE.md#internal-label-rename-count--denied_count-on-rate-limit-summary-jobs).

## Operator guidance

Use Prometheus for aggregate alerting:

```promql
rate(cordclaw_rate_limited_total[5m])
```

Use Cordum jobs to find the affected agent:

1. Filter the jobs page or API to topic `job.openclaw.rate_limit_summary`.
2. Group by `labels.agent_id`.
3. Sort by numeric `labels.denied_count` or by job timestamp.
4. Use `labels.window_start` to align the count with the Prometheus spike.

Use the daemon audit log for local, low-latency debugging while the incident is
active. The audit log is a bounded FIFO; export or query summary jobs for
longer-lived investigations.
