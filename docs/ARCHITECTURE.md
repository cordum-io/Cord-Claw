# CordClaw Architecture

CordClaw is a two-process sidecar for OpenClaw governance. A lightweight
OpenClaw plugin runs in-process with the gateway, converts hook context into a
structured envelope, and calls the local `cordclaw-daemon` over localhost HTTP.
The daemon performs deterministic mapping, caching, policy evaluation, and audit
recording before the plugin applies the decision back to the OpenClaw runtime.

> Last verified: 2026-04-26 against Cord-Claw HEAD `865bb86`.

## Current status badges

| Badge | Meaning |
|-------|---------|
| **LIVE** | Code is present at this HEAD and is enforced or emitted in the running hook path. |
| **IN-PROGRESS** | Code or architecture is partially present, but the authoritative behavior is not shipped yet. |
| **ROADMAP** | Planned by the productization epic but not claimed as live in this document. |

## Interception hooks

CordClaw documents hook names in OpenClaw terms and, where OpenClaw exposes a
runtime compatibility name, includes the exact runtime hook registered by
`plugin/src/index.ts`.

| OpenClaw hook | Runtime hook | Status | Envelope shape | Decision authority |
|---------------|--------------|--------|----------------|--------------------|
| `before_agent_start` | `before_agent_start` | **LIVE** | `tool=agent_start`, `turnOrigin`, `agent`, `session`, optional `parentSession` and `cronJobId`. | Fail-closed. The plugin calls `shim.checkFailClosed`; DENY/THROTTLE/REQUIRE_HUMAN throws `cordclaw.agent_start.blocked` before the turn starts. |
| `before_prompt_build` | `before_prompt_build` | **LIVE** | `tool=prompt_build`, `prompt_text`, agent/session/model metadata. | Fail-closed. The daemon can return a prompt-redaction CONSTRAIN decision; DENY/THROTTLE/REQUIRE_HUMAN blocks prompt construction. |
| `before_tool_call` | `before_tool_execution` | **LIVE** | `tool`, command/path/url/channel metadata, agent/session/model metadata. | Authoritative pre-dispatch decision. ALLOW continues; DENY/THROTTLE/REQUIRE_HUMAN returns a blocked context; CONSTRAIN applies sandbox/read-only/timeout/prompt changes supported by the plugin. |
| `after_tool_call` | `after_tool_execution` | **IN-PROGRESS** | Raw post-tool context forwarded to daemon audit. | Audit-only at this HEAD: the hook calls `shim.audit(ctx)` and does not rewrite or block tool results. Result-gating is tracked by task-97da56e5. |
| `before_message_write` | `before_message_write` | **LIVE** | `tool=message_write`, `channel_provider`, `channel_id`, canonical `action`, `message_preview`, agent/session/model metadata. | Fail-closed. Invalid envelopes throw `cordclaw.message_write.blocked`; policy decisions are enforced by `enforceMessageWrite`. |

## Control flow at this HEAD

```text
OpenClaw Gateway
  -> CordClaw Plugin (registered hook fires)
  -> Build structured envelope for that hook
  -> HTTP POST http://127.0.0.1:19090/check
  -> cordclaw-daemon
       - normalize/canonicalize hook metadata
       - map to topic/capability/risk tags/labels
       - consult local decision cache and circuit breaker
       - call Cordum Safety Kernel over gRPC
       - record audit details
  -> Decision: ALLOW | DENY | THROTTLE | REQUIRE_HUMAN | CONSTRAIN
  -> Plugin enforcer applies the decision to OpenClaw runtime
```

The daemon also exposes `/simulate`, `/health`, `/status`, and `/audit` on the
same localhost API surface. It binds to `127.0.0.1` by default; the documented
operator port is `19090`.

## Phase 2 Cordum jobs flow

**Status: IN-PROGRESS, architectural decision pending (task-db841006).**

The productization target is that every OpenClaw action is emitted as a real
Cordum job on a `job.openclaw.*` topic, submitted through the Cordum gateway
`/api/v1/jobs` endpoint, and evaluated by the existing `evaluateSubmitPolicy`
path. In that target flow, the same `safety_decision` used by other Cordum jobs
would flow back through the gateway and become the plugin's enforcement result.

```text
OpenClaw hook
  -> CordClaw plugin envelope
  -> cordclaw-daemon /check
  -> Phase 2 target: Cordum Gateway /api/v1/jobs
  -> evaluateSubmitPolicy
  -> safety_decision
  -> cordclaw-daemon response
  -> plugin enforcer
  -> OpenClaw runtime
```

That target is not claimed as live here. At this HEAD, the daemon still uses the
Safety Kernel gRPC client as the authoritative decision source. Downstream docs
and runbooks should keep the Phase 2 flow marked **IN-PROGRESS** until
task-db841006 lands or is re-planned.

## Key components

- `plugin/src/index.ts`: plugin registration, hook wiring, and CLI commands.
- `plugin/src/lib/envelope.ts`: converts OpenClaw hook context into stable
  CordClaw envelopes.
- `plugin/src/enforcer.ts`: converts policy responses into runtime behavior.
- `daemon/internal/server`: localhost API (`/check`, `/simulate`, `/health`,
  `/status`, `/audit`) and audit recording.
- `daemon/internal/mapper`: maps hook/tool envelopes to topics, capabilities,
  risk tags, labels, and canonicalized fields.
- `daemon/internal/canonicalize`: command and message-write normalization before
  risk tagging.
- `daemon/internal/redact`: prompt-level DLP policy loading and redaction.
- `daemon/internal/cache`: in-memory LRU for repeated decisions.
- `daemon/internal/circuit`: degraded-mode behavior during governance outages.
- `daemon/internal/client/safety.go`: current Safety Kernel gRPC client.
- `pack/policies/openclaw-safety.yaml`: OpenClaw-specific policy fragment for
  prompt DLP, channel-action, cron-origin, and label-allow rules.

## Design principles

- Deterministic enforcement before execution whenever a hook can still prevent
  the action.
- Structured metadata and bounded previews instead of prompt-sized free text for
  policy evaluation.
- Fail closed for hooks that can leak secrets or start autonomous turns.
- Local-first latency with cache and warm kernel connection.
- Explicit degraded mode when backend governance is unavailable.
- Honest status separation between shipped gRPC-backed enforcement and the
  in-progress Phase 2 Cordum jobs migration.

## Related

- [README.md](../README.md)
- [POLICY_GUIDE.md](./POLICY_GUIDE.md)
- [THREAT_MODEL.md](./THREAT_MODEL.md)
