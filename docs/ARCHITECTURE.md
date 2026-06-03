# CordClaw Architecture

CordClaw is a two-process sidecar model:

- A lightweight OpenClaw plugin intercepts pre-dispatch tool calls.
- A local Go daemon performs deterministic policy checks.
- The daemon calls Cordum Safety Kernel over gRPC and enforces outcomes.

## Control Flow

```text
OpenClaw Gateway
  -> CordClaw Plugin (before_tool_execution hook)
  -> HTTP POST localhost:19090/check
  -> cordclaw-daemon (cache + circuit breaker + mapper)
  -> gRPC PolicyCheckRequest
  -> Cordum Safety Kernel
  -> Decision: ALLOW | DENY | THROTTLE | REQUIRE_HUMAN | CONSTRAIN
  -> Plugin enforcement outcome
```

## Key Components

- `daemon/internal/server`: localhost API (`/check`, `/simulate`, `/health`, `/status`, `/audit`)
- `daemon/internal/cache`: in-memory LRU for repeated decisions
- `daemon/internal/circuit`: graduated fail-closed behavior during kernel outages
- `daemon/internal/mapper`: OpenClaw action metadata -> CAP policy request
- `daemon/internal/policy`: cron-origin decision log; production uses BoltDB at
  `/var/lib/cordclaw/cron-decisions.db` with 24h retention so allowed cron jobs
  survive daemon restarts without storing prompt or description text.
- `plugin/src/index.ts`: gateway plugin registration and hook wiring
- `plugin/src/shim.ts`: daemon HTTP client wrapper
- `plugin/src/enforcer.ts`: decision-to-action enforcement

## Design Principles

- Deterministic enforcement before execution
- Structured metadata over prompt text for policy evaluation
- Local-first latency with cache and warm kernel connection
- Explicit degraded mode when backend governance is unavailable

## Related

- [README.md](../README.md)
- [POLICY_GUIDE.md](./POLICY_GUIDE.md)
- [THREAT_MODEL.md](./THREAT_MODEL.md)
