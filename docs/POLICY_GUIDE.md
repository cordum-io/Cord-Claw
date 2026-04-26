# Cord-Claw Policy Guide

> Last verified: 2026-04-26 against Cord-Claw HEAD `865bb86`.

Cord-Claw policies are Cordum policy-bundle fragments for OpenClaw and legacy
CordClaw topics. They decide whether hook envelopes are allowed, denied,
constrained, throttled, or sent to human approval.

> **Schema rule:** policy rule entries must **not** contain a top-level
> `description` key. Cordum's safety-policy schema rejects unknown rule fields.
> Put operator-only notes in YAML comments and put agent/operator-facing rationale
> in the required `reason` field.

Wrong:

```yaml
rules:
  - id: bad-description-field
    description: Human-readable note that Cordum's schema rejects
    match:
      topics: ["job.openclaw.tool_call"]
    decision: deny
    reason: This is the reason shown to the agent/operator.
```

Right:

```yaml
rules:
  # Human-readable note for operators. Comments are safe.
  - id: good-comment-plus-reason
    match:
      topics: ["job.openclaw.tool_call"]
    decision: deny
    reason: This is the reason shown to the agent/operator.
```

Status badges in this guide:

- **LIVE**: policy/code is present at this HEAD and can be exercised by the current daemon/plugin path.
- **IN-PROGRESS**: policy shape or target architecture exists, but the authoritative enforcement path is not live yet.
- **ROADMAP**: planned shape only; not claimed as shipped.

## 0. Built-in profiles and legacy categories

Cord-Claw still ships three built-in policy profiles for the legacy
`job.cordclaw.*` topics. Each profile defines rules for 10 OpenClaw action
categories. Use a profile as-is for pilots, then add site-specific rules for
production.

| Profile | Use case | Default behavior |
|---------|----------|------------------|
| **Permissive** | Personal / developer use | Allow most operations. Block only obviously destructive commands and secrets access. |
| **Moderate** | Team / staging | Allow routine operations. Require approval for external messaging, scheduling, and package installs. Deny destructive and secrets access. |
| **Strict** | Enterprise / production | Require approval for most write operations. Deny destructive commands, secrets access, and cloud infrastructure operations. |

Set your profile during install:

```bash
CORDCLAW_PROFILE=moderate ./setup/install.sh
```

Legacy action categories remain available for existing deployments:

| Category | Tool | Risk tags | Typical policy outcome |
|----------|------|-----------|------------------------|
| Shell execution | `exec` | exec, system, write | Allow with sandbox constraints; deny destructive/cloud/remote access. |
| File read | `read` / file-read topic | filesystem, read | Allow by default; deny secret paths. |
| File write | `write` / file-write topic | filesystem, write | Allow or require approval; deny secret paths. |
| Browser navigate | `browser.navigate` | network, browser | Allow with timeout budget. |
| Browser interact | `browser.action` | network, browser, write | Allow or require approval depending on profile. |
| Web search/fetch | `web_search`, `web_fetch` | network, read | Allow routine reads; tag non-HTTPS transports. |
| Send message | message-send topic | messaging, write, external | Require approval or exact channel-action policy. |
| Memory write | memory-write topic | memory, write, persistence | Allow in permissive/moderate, require approval in strict. |
| Create cron | `cron.create` | schedule, write, autonomy | Require approval or deny. |

## New OpenClaw policy primitives

The OpenClaw-specific fragment is `pack/policies/openclaw-safety.yaml` and is
referenced from `pack/pack.yaml`. The older `pack/overlays/policy.fragment.yaml`
remains for legacy `job.cordclaw.*` topics.

### `prompt_pii_redact` — **LIVE**

**Purpose.** Redact or block provider-side credential leakage during
`before_prompt_build` before prompt text reaches the model provider.

**Decision authority.** The daemon returns CONSTRAIN with a modified prompt when
patterns are redacted. DENY/THROTTLE/REQUIRE_HUMAN block prompt construction;
unavailable prompt text fails closed.

**Attack class.** [Prompt-level PII leakage](./THREAT_MODEL.md#2-prompt-level-pii-leakage--live).

```yaml
prompt_pii_redact:
  action: CONSTRAIN
  reason: "redact provider-side credential leakage in agent prompts"
  include_email: false
  patterns:
    - name: OPENAI_KEY
      regex: '\bsk-[A-Za-z0-9_-]{10,}\b'
      placeholder: '<REDACTED-OPENAI_KEY>'

rules:
  - id: openclaw-prompt_pii_redact
    match:
      topics: ["job.openclaw.prompt_build"]
      risk_tags: ["prompt_pii"]
    decision: allow_with_constraints
    constraints:
      kind: prompt_pii_redact
      prompt_pii_redact:
        use_pack_policy: true
    reason: OpenClaw prompt builds with PII risk are constrained through prompt_pii_redact.
```

### `cron_origin_check` — **LIVE**

**Purpose.** Prevent autonomous cron-fired turns from drifting away from the
intent and tool/capability allowlists recorded when the cron was approved.

**Decision authority.** Unknown, evicted, or drifted cron-origin turns are denied
with `cron-origin-policy-mismatch`. Verified cron-origin turns continue with
`cron_origin_verified` metadata.

**Attack class.** [Cron-bypass escalation](./THREAT_MODEL.md#1-cron-bypass-escalation--live).

```yaml
rules:
  - id: openclaw-cron_origin_check-agent-start
    match:
      topics: ["job.openclaw.agent_start"]
      risk_tags: ["cron_fire"]
    decision: deny
    reason: cron-origin-policy-mismatch

  - id: openclaw-cron_fire-allow-verified
    match:
      topics: ["job.openclaw.cron_fire"]
    decision: allow
    reason: Verified OpenClaw cron-fired turns are allowed after origin correlation.
```

### `channel_action_allow` — **LIVE**

**Purpose.** Treat provider/action pairs as first-class policy inputs so a rule
can allow `slack.send` while denying `slack.delete` or `slack.upload_file`.

**Decision authority.** Exact provider/action matches can ALLOW, DENY, or require
approval. Unknown providers/actions fail closed before policy evaluation.

**Attack class.** [Channel-action granularity](./THREAT_MODEL.md#4-channel-action-granularity--live).

```yaml
rules:
  # channel_action_allow is exact-pair keyed; do not replace with provider-only allow.
  - id: openclaw-channel_action_allow-slack-send
    primitive: channel_action_allow
    match:
      topics: ["job.openclaw.message_write"]
      label_allowlist:
        channel_action:
          - slack.send
    decision: allow
    reason: channel_action_allowed provider=slack action=send

  - id: openclaw-channel_action_allow-slack-delete-deny
    primitive: channel_action_allow
    match:
      topics: ["job.openclaw.message_write"]
      label_allowlist:
        channel_action:
          - slack.delete
    decision: deny
    reason: channel_action_denied provider=slack action=delete
```

### `exec_command_allow` — **IN-PROGRESS**

**Purpose.** Allow known-safe command families after `exec` commands are
canonicalized. The policy rule is present in `pack/policies/openclaw-safety.yaml`,
but current daemon HEAD does not yet emit `command_family` labels, so the label
allowlist path is marked **IN-PROGRESS**.

**Decision authority.** Once command-family labels are emitted, matching
`command_family` labels ALLOW. Today, obfuscation defense is live through
canonicalized risk tags and deny/approval rules such as `destructive`, `cloud`,
`infrastructure`, or `remote-access`.

**Attack class.** [Obfuscation bypass](./THREAT_MODEL.md#5-obfuscation-bypass--live).

```yaml
rules:
  # Command-family labels are emitted by daemon canonicalization tasks.
  - id: openclaw-exec_command_allow-readonly
    match:
      topics: ["job.openclaw.tool_call"]
      label_allowlist:
        command_family:
          - inspect
          - read_only
          - list
    decision: allow
    reason: Read-only command families are allowed for OpenClaw tool calls.
```

### `file_path_scope` — **IN-PROGRESS**

**Purpose.** Keep file operations inside approved path scopes such as workspace
or temporary directories. The policy rule is present, but current daemon HEAD
does not yet emit `path_scope` labels, so the label allowlist path is marked
**IN-PROGRESS**.

**Decision authority.** Once path-scope labels are emitted, matching `path_scope`
labels ALLOW. Today, secret/system path risk tags can still DENY earlier in the
rule set.

**Attack class.** Supports the tool pre-dispatch layer described in
[Other protections currently shipped](./THREAT_MODEL.md#other-protections-currently-shipped).

```yaml
rules:
  - id: openclaw-file_path_scope-workspace
    match:
      topics: ["job.openclaw.tool_call"]
      label_allowlist:
        path_scope:
          - workspace
          - temp
    decision: allow
    reason: OpenClaw file operations are allowed inside approved path scopes.
```

### `url_domain_allow` — **IN-PROGRESS**

**Purpose.** Allow URL/browser actions only for known documentation and code-host
domains when URL labels are present. The policy rule is present, but current
daemon HEAD does not yet emit `url_domain` labels, so the label allowlist path is
marked **IN-PROGRESS**.

**Decision authority.** Once URL-domain labels are emitted, matching `url_domain`
labels ALLOW. Today, non-HTTPS or unknown network destinations must be handled by
adjacent risk-tag/approval rules.

**Attack class.** Supports data-exfiltration reduction, but post-tool result
blocking is also **IN-PROGRESS** until task-97da56e5 lands.

```yaml
rules:
  - id: openclaw-url_domain_allow-default
    match:
      topics: ["job.openclaw.tool_call"]
      label_allowlist:
        url_domain:
          - cordum.io
          - docs.cordum.io
          - github.com
    decision: allow
    reason: OpenClaw URL actions are allowed for approved documentation and code hosts.
```

## Custom policies

Create a bundle fragment with site-specific rules. Keep comments for operator
notes and `reason` for surfaced rationale.

```yaml
version: "1"
default_tenant: default

rules:
  # Redact prompt builds that carry provider credentials before model dispatch.
  - id: team-prompt-redact-provider-keys
    match:
      topics: ["job.openclaw.prompt_build"]
      risk_tags: ["prompt_pii"]
    decision: allow_with_constraints
    constraints:
      kind: prompt_pii_redact
      prompt_pii_redact:
        use_pack_policy: true
    reason: Prompt builds with provider credentials must be redacted before dispatch.

  # Block uploads to Slack until channel-specific review is complete.
  - id: team-channel-action-deny-slack-upload
    primitive: channel_action_allow
    match:
      topics: ["job.openclaw.message_write"]
      label_allowlist:
        channel_action:
          - slack.upload_file
    decision: deny
    reason: Slack uploads are disabled pending data-loss review.
```

Redeploy through Cordum pack installation once the fragment is included in the
CordClaw pack or your environment-specific pack overlay:

```bash
cordumctl pack install cordclaw --tenant default
```

Expected output shape:

```text
pack cordclaw installed
policy fragments applied: safety, openclaw-safety
simulations: passed
```

For local daemon-only testing, use the simulation API before rollout:

```bash
curl -X POST http://localhost:19090/simulate \
  -H "Content-Type: application/json" \
  -d @examples/payloads/deny-destructive-exec.json
```

Example response shape:

```json
{
  "decision": "DENY",
  "reason": "Destructive command detected: rm -rf",
  "riskTags": ["exec", "system", "write", "destructive"],
  "cached": false
}
```

## Related

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design and control flow
- [THREAT_MODEL.md](./THREAT_MODEL.md) - Attack classes and security limits
- [GETTING_STARTED.md](./GETTING_STARTED.md) - Hands-on tutorial
