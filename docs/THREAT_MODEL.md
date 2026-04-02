# Cord-Claw Threat Model

## Scope

Cord-Claw governs OpenClaw agent actions at the pre-dispatch layer. This document describes what Cord-Claw protects against, what it does not, and the assumptions underlying each boundary.

## Trust Boundaries

```text
+---------------------------+      +---------------------------+
|  OpenClaw Agent Context   |      |  cordclaw-daemon          |
|  (untrusted runtime)      | ---> |  (trusted sidecar)        |
|                           | HTTP |                           |
|  Plugin runs in-process   |      |  LRU cache + gRPC client  |
+---------------------------+      +-------------+-------------+
                                                 |
                                           gRPC (mTLS)
                                                 |
                                   +-------------v-------------+
                                   |  Cordum Safety Kernel     |
                                   |  (trusted policy engine)  |
                                   +---------------------------+
```

1. **Agent -> Plugin**: The plugin runs inside the OpenClaw gateway process. It intercepts `before_tool_execution` hooks and extracts structured metadata (tool name, arguments, risk tags). The agent cannot bypass the plugin without modifying the gateway itself.

2. **Plugin -> Daemon**: Communication over localhost HTTP (port 19090). The daemon only binds to `127.0.0.1` by default. Network-level isolation prevents remote callers.

3. **Daemon -> Safety Kernel**: gRPC with optional mTLS. The daemon authenticates to the kernel using a tenant API key. The kernel is the authoritative policy engine.

## What Cord-Claw Protects Against

| Threat | Protection | Confidence |
|--------|-----------|------------|
| Accidental destructive commands (`rm -rf /`, `DROP TABLE`) | Regex risk-tag inference + DENY policy | High |
| Unauthorized file access to secrets (`.env`, `.pem`, `.key`) | Path-pattern risk tags + DENY policy | High |
| Unreviewed external messaging | REQUIRE_HUMAN policy on `sessions_send` | High |
| Uncontrolled cron/schedule creation | REQUIRE_HUMAN policy on `cron.create` | High |
| Unsanctioned package installs | Risk-tag detection + REQUIRE_APPROVAL | Medium |
| Non-HTTPS external requests | URL pattern detection + risk tagging | Medium |

## What Cord-Claw Does NOT Protect Against

| Threat | Why | Mitigation |
|--------|-----|------------|
| Prompt injection causing tool misuse | Cord-Claw evaluates structured metadata, not prompt content. A compromised agent can still craft valid-looking tool calls. | Combine with output scanning, sandboxing, and human review for high-risk operations. |
| Obfuscated commands (`$(echo cm0gLXJm | base64 -d)`) | Regex risk-tag inference operates on raw argument strings. Encoded or obfuscated payloads bypass pattern matching. | Layer with runtime sandboxing (NemoClaw) for defense in depth. |
| Daemon binary compromise | If an attacker replaces the daemon binary, all policy decisions are controlled by the attacker. | Verify binary checksums. Use signed releases. Run daemon as a separate user with restricted permissions. |
| Safety Kernel unavailability | Circuit breaker degrades to cached decisions. Novel actions (no cache hit) are blocked (fail-closed). | Monitor kernel health. Deploy kernel with HA. Tune cache TTLs for your risk profile. |
| Data exfiltration via allowed tools | If a tool call is ALLOW'd, the agent can use it to exfiltrate data through permitted channels. | Restrict allowed domains/IPs in policy. Use CONSTRAIN decisions to limit scope. |

## Assumptions

1. The OpenClaw gateway is not itself compromised. If the gateway process is under attacker control, the in-process plugin can be bypassed entirely.
2. The daemon binary is authentic and has not been tampered with.
3. Localhost networking provides adequate isolation for plugin-to-daemon communication.
4. Risk-tag inference is best-effort. It catches common dangerous patterns but is not a substitute for sandboxing.

## Defense in Depth

Cord-Claw is one layer in a defense stack:

- **Pre-dispatch** (Cord-Claw): Block or require approval before actions execute
- **Runtime sandboxing** (NemoClaw or containers): Limit what executed actions can access
- **Post-execution scanning** (Cordum output filters): Detect sensitive data in results
- **Human review** (Cordum approval workflows): Require operator sign-off for high-risk operations
- **Audit trail** (Cordum audit log): Immutable record of every decision for forensic review

No single layer is sufficient. Cord-Claw provides the first gate in a layered approach.
