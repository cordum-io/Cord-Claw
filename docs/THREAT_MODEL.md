# Cord-Claw Threat Model

> Last verified: 2026-04-26 against Cord-Claw HEAD `865bb86`.

## Scope

Cord-Claw governs OpenClaw agent actions at the hook boundary before, during, or
after high-risk runtime events. It does not make the model trustworthy; it makes
selected runtime actions policy-checkable through structured envelopes, local
daemon evaluation, and Cordum policy decisions. This document describes what
Cord-Claw protects against, what it does not protect against, and the assumptions
behind each boundary.

Status badges in this document:

- **LIVE**: grep-verifiable at this HEAD and enforced or emitted in the runtime path.
- **IN-PROGRESS**: partially present or planned, but not authoritative for blocking yet.
- **ROADMAP**: not claimed as shipped at this HEAD.

## Trust boundaries

```text
+---------------------------+      +---------------------------+
|  OpenClaw Agent Context   |      |  cordclaw-daemon          |
|  (untrusted runtime)      | ---> |  (trusted sidecar)        |
|                           | HTTP |                           |
|  Plugin runs in-process   |      |  LRU cache + mapper +     |
|  and registers hooks      |      |  current gRPC client      |
+---------------------------+      +-------------+-------------+
                                                 |
                                           gRPC (mTLS-capable)
                                                 |
                                   +-------------v-------------+
                                   |  Cordum Safety Kernel     |
                                   |  (trusted policy engine)  |
                                   +---------------------------+
```

1. **Agent -> Plugin**: The plugin runs inside the OpenClaw gateway process. It
   registers `before_tool_execution`, `before_agent_start`,
   `before_prompt_build`, `before_message_write`, and audit-only
   `after_tool_execution` hooks. A compromised gateway process can bypass the
   plugin entirely; Cord-Claw assumes the gateway is not malicious.
2. **Plugin -> Daemon**: Communication is localhost HTTP on port `19090`. The
   daemon binds to `127.0.0.1` by default and receives structured envelopes
   rather than unbounded prompt transcripts where possible.
3. **Daemon -> Safety Kernel**: At this HEAD the daemon's authoritative path is
   Safety Kernel gRPC. The Phase 2 `/api/v1/jobs` path is **IN-PROGRESS** under
   task-db841006 and is not treated as live in this threat model.
4. **Policy -> Runtime**: The plugin translates ALLOW, DENY, THROTTLE,
   REQUIRE_HUMAN, and CONSTRAIN into OpenClaw runtime effects. Hooks that can
   still prevent an action fail closed for unsafe or invalid envelopes.

## Attack classes

### 1. Cron-bypass escalation — **LIVE**

**Scenario.** A user approves a benign scheduled action, but a later cron-fired
turn attempts to execute a different tool or capability. Without origin
correlation, the later autonomous turn could reuse the trust of the original
approval and escalate from a schedule into arbitrary execution.

**Attack steps.** The attacker creates or modifies a cron task, waits for the
cron-triggered agent turn, and uses that autonomous turn to call tools that were
not part of the approved intent. If the policy engine sees only a generic tool
call, it cannot tell whether this call originated from a user turn or a cron
turn.

**Cord-Claw controls.** The plugin registers `before_agent_start` and sends
`turnOrigin`, `cronJobId`, `session`, and agent metadata before the turn starts.
The daemon records approved cron decisions and rejects unknown, evicted, or drifted
cron-origin turns with `cron-origin-policy-mismatch`. The v2 cron-origin work
also preserves allowlisted tool/capability metadata for subsequent cron-origin
checks.

**Catching hooks/primitives.** `before_agent_start`; `cron_origin_check` rules in
`pack/policies/openclaw-safety.yaml`; daemon cron decision log.

### 2. Prompt-level PII leakage — **LIVE**

**Scenario.** A prompt builder includes provider credentials, Slack tokens, AWS
keys, or sensitive internal identifiers in the prompt sent to the model. If the
model sees that material, a later policy check cannot reliably make the model
unsee it.

**Attack steps.** The agent gathers context from files, environment-like text, or
previous tool results, then composes a prompt containing secrets. The provider
call is made before traditional tool-call governance observes the leak.

**Cord-Claw controls.** The plugin registers `before_prompt_build`, extracts the
candidate prompt text, and calls the daemon fail-closed. The daemon loads the
`prompt_pii_redact` policy, scans for configured patterns, and can return a
CONSTRAIN response with a redacted prompt. If prompt text is unavailable or the
daemon is unreachable, the plugin blocks instead of letting a potentially secret
prompt through.

**Catching hooks/primitives.** `before_prompt_build`; `prompt_pii_redact` policy
and daemon redaction module.

### 3. Exfiltration via tool result — **IN-PROGRESS**

**Scenario.** A permitted tool reads a large or sensitive result, and the agent
then forwards that result into chat, a file, or an external channel. Pre-dispatch
policy may have allowed the tool call because the request looked safe; the leak
appears in the post-tool result.

**Attack steps.** The agent requests an allowed read/search/fetch, receives a
result containing secrets or bulk data, and uses subsequent actions to exfiltrate
that output. A pre-dispatch-only guard cannot inspect the final result bytes.

**Cord-Claw controls today.** The plugin registers `after_tool_execution`, but at
this HEAD it is audit-only: it forwards context with `shim.audit(ctx)` and does
not rewrite or block the result. The pack contains a `result_gating` policy shape,
but without a modifying post-tool hook it is not authoritative enforcement.
Result gating is tracked by task-97da56e5 and remains **IN-PROGRESS**.

**Catching hooks/primitives.** `after_tool_execution` audit today;
modifying result gating is not live yet.

### 4. Channel-action granularity — **LIVE**

**Scenario.** A policy allows Slack sends but should not allow deletes, uploads,
or other channel actions on the same provider and channel. A provider-only policy
would treat `slack.send`, `slack.delete`, and `slack.upload_file` as equivalent.

**Attack steps.** The agent requests a message operation on an approved provider,
then switches the action from send to delete or upload. If policy is keyed only
on provider or channel id, the action-specific risk is invisible.

**Cord-Claw controls.** The plugin registers `before_message_write` and builds an
envelope with `channel_provider`, `channel_id`, canonical `action`, and a bounded
`message_preview`. The daemon canonicalizes the provider/action pair, emits
labels such as `channel_action=slack.delete`, and the pack's
`channel_action_allow` rules allow or deny exact pairs. Unknown providers or
actions fail closed.

**Catching hooks/primitives.** `before_message_write`; `channel_action_allow`;
message-write canonicalization.

### 5. Obfuscation bypass — **LIVE**

**Scenario.** A dangerous command is hidden behind base64 decoding, command-local
environment substitution, or symlink indirection so raw regex checks do not see
`rm -rf`, `--drop`, or similar markers.

**Attack steps.** The agent asks for an apparently harmless shell command that
expands into a destructive command only after shell evaluation. Naive pattern
matching on the original string misses the dangerous payload.

**Cord-Claw controls.** For `exec` tool calls, the daemon runs command
canonicalization before regex risk tagging. It decodes supported base64 pipelines,
expands command-local environment assignments without reading process
credentials, surfaces static substitutions, and records canonical operations in
audit details while preserving the original command field.

**Catching hooks/primitives.** `before_tool_execution` for `exec`; command
canonicalization in `daemon/internal/canonicalize`; command-family/risk-tag policy
rules.

## Other protections currently shipped

| Threat | Protection | Status |
|--------|------------|--------|
| Accidental destructive commands (`rm -rf /`, `DROP TABLE`) | Canonicalized command risk tags + DENY policy | **LIVE** |
| Unauthorized file access to secrets (`.env`, `.pem`, `.key`) | Path-pattern risk tags + DENY policy | **LIVE** |
| Unreviewed external messaging | REQUIRE_HUMAN / channel-action policies depending on topic | **LIVE** |
| Uncontrolled cron/schedule creation | REQUIRE_HUMAN policy for cron creation + cron-origin checks for autonomous turns | **LIVE** |
| Unsanctioned package installs | Command risk-tag detection + REQUIRE_APPROVAL | **LIVE** |
| Non-HTTPS external requests | URL parsing tags non-HTTPS transports for stricter policy | **LIVE** |

## What Cord-Claw does NOT protect against

| Threat | Why | Mitigation |
|--------|-----|------------|
| Kernel-level or container escape exploits | Cord-Claw decides whether an action should run; it is not a kernel sandbox and cannot contain a process after execution starts. | Pair with OS sandboxing, containers, seccomp/AppArmor, or NemoClaw-style runtime isolation. |
| Network-level attacks on hosts or service mesh | The localhost daemon boundary does not inspect all network packets and cannot replace firewall or egress controls. | Use network policy, egress allowlists, TLS, and service-level authentication. |
| Supply-chain attacks on OpenClaw or CordClaw binaries | If the gateway, plugin, daemon, or dependencies are replaced, the enforcement point can be bypassed or falsified. | Verify signed releases, checksums, dependency provenance, and deployment attestation. |
| Compromised OpenClaw gateway process | The plugin runs in-process. A malicious gateway can skip hooks or mutate context before Cord-Claw sees it. | Harden gateway deployment, restrict admin access, and monitor binary/process integrity. |
| Runaway autonomy if every hook fails open | Cord-Claw relies on fail-closed behavior for high-risk hooks, but operator misconfiguration or future fail-open changes could remove that layer. | Keep high-risk hooks fail-closed; use per-action fail mode from task-44b6aa5e when available; alert on degraded governance. |
| Secrets already present in model memory/context | Prompt DLP can redact future prompt builds; it cannot remove secrets the model already saw before the hook was installed or before a pattern existed. | Rotate exposed credentials and keep secret scanning close to data ingress. |
| Race between policy snapshot and execution | A decision is made against the policy snapshot loaded at check time; a policy update immediately after the decision does not retroactively cancel already-returned ALLOW responses. | Use short cache TTLs for high-risk environments and require approval for irreversible operations. |
| Cordum gateway or Safety Kernel compromise | If the trusted policy service is compromised, decisions can be malicious. | Treat Cordum control-plane hardening, audit review, and SIEM alerting as part of the security boundary. |
| Full prevention of data exfiltration after an allowed result | Result-gating is audit-only / in-progress at this HEAD. | Keep sensitive reads constrained, review audit, and land task-97da56e5 before claiming post-tool-result blocking. |

## Assumptions

1. The OpenClaw gateway is not itself compromised. If the gateway process is
   under attacker control, the in-process plugin can be bypassed entirely.
2. The daemon binary is authentic and has not been tampered with.
3. Localhost networking provides adequate isolation for plugin-to-daemon
   communication.
4. Risk-tag inference and canonicalization catch common dangerous patterns but do
   not prove a command is safe.
5. Policy fragments are installed without top-level `description` keys in rule
   entries, matching the Cordum schema.
6. The current authoritative policy path is Safety Kernel gRPC until the Phase 2
   Cordum jobs migration is completed.

## Defense in depth

Cord-Claw is one layer in a defense stack. The current shipped layers are:

- **Turn start** (`before_agent_start`): validates origin and cron correlation
  before autonomous work begins.
- **Prompt build** (`before_prompt_build`): redacts or blocks secrets before the
  model provider call.
- **Tool pre-dispatch** (`before_tool_execution`): maps structured action
  metadata, canonicalizes exec commands, and enforces policy before tool use.
- **Message write** (`before_message_write`): enforces provider/action-specific
  message policy before outbound channel writes.
- **Post-tool audit** (`after_tool_execution`): records post-tool context today;
  modifying result gating is still in progress.

Defense-in-depth means an attack should have to cross multiple hooks and policy
layers before succeeding. Per-action fail mode (task-44b6aa5e) strengthens this
model by allowing read-like actions to degrade differently from write/exec-like
actions, but high-risk hooks should remain fail-closed.

No single layer is sufficient. Cord-Claw provides deterministic hook-boundary
governance, but operators should still use runtime sandboxing, network egress
controls, human approvals, audit review, and credential rotation.
