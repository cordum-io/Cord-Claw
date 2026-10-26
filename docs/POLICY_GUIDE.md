# Cord-Claw Policy Guide

> Last verified: 2026-04-26 against Cord-Claw HEAD `865bb86`.

Cord-Claw policies are Cordum policy-bundle fragments for OpenClaw and legacy
CordClaw topics. They decide whether hook envelopes are allowed, denied,
constrained, throttled, or sent to human approval.

> **Schema rule:** policy rule entries must **not** contain a top-level
> `description` key. Cordum's safety-policy schema rejects unknown rule fields.
> Put operator-only notes in YAML comments and put agent/operator-facing rationale
> in the required `reason` field. The same goes for any key outside the schema
> (`primitive`, `constraints.kind`, a top-level `prompt_pii_redact`): the
> gateway refuses to install a pack whose fragment carries one.

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
| **Moderate** | Team / staging | Allow routine operations. Require approval for external messaging, scheduling, and package installs. Deny destructive commands, secrets access, cloud infrastructure operations, and remote access (`ssh`, `scp`, `rsync`). |
| **Strict** | Enterprise / production | Require approval for most write operations. Deny everything Moderate denies, plus autonomous scheduling. |

Set your profile during install:

```bash
CORDCLAW_PROFILE=moderate ./setup/install.sh
```

Legacy action categories remain available for existing deployments:

| Category | Tool | Risk tags | Typical policy outcome |
|----------|------|-----------|------------------------|
| Shell execution | `exec` | exec, system, write | Allow with sandbox constraints; deny destructive/cloud/remote access and secret reads (`cat ~/.ssh/id_rsa`). |
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
remains for legacy `job.cordclaw.*` topics. The prompt DLP patterns live in
`pack/policies/prompt-pii-redact.yaml`, which is daemon config, not a fragment.

### `prompt_pii_redact` — **LIVE**

**Purpose.** Redact or block provider-side credential leakage during
`before_prompt_build` before prompt text reaches the model provider.

**Decision authority.** The daemon decides prompt builds itself, without a
Safety Kernel call. It returns CONSTRAIN with a modified prompt when patterns
are redacted. DENY/THROTTLE/REQUIRE_HUMAN block prompt construction;
unavailable prompt text fails closed.

**Attack class.** [Prompt-level PII leakage](./THREAT_MODEL.md#2-prompt-level-pii-leakage--live).

The patterns sit in `pack/policies/prompt-pii-redact.yaml` because Cordum's
policy schema rejects a `prompt_pii_redact` key inside a fragment. Point
`CORDCLAW_DLP_POLICY_PATH` at that file; when the variable is unset the daemon
uses the same built-in patterns. A path to an older policy file that still
embeds the block keeps working, and a path to `openclaw-safety.yaml` falls back
to the `prompt-pii-redact.yaml` beside it.

```yaml
# pack/policies/prompt-pii-redact.yaml
prompt_pii_redact:
  action: CONSTRAIN
  reason: "redact provider-side credential leakage in agent prompts"
  include_email: false
  patterns:
    - name: OPENAI_KEY
      regex: '\bsk-[A-Za-z0-9_-]{10,}\b'
      placeholder: '<REDACTED-OPENAI_KEY>'
```

The fragment keeps a schema-valid rule that records the CONSTRAIN outcome for
Cordum-side simulation and audit:

```yaml
rules:
  - id: openclaw-prompt_pii_redact
    match:
      topics: ["job.openclaw.prompt_build"]
      risk_tags: ["prompt_pii"]
    decision: allow_with_constraints
    reason: OpenClaw prompt builds with PII risk are constrained through prompt_pii_redact.
```

### `cron_origin_check` — **LIVE**

**Purpose.** Correlate every cron-fired agent turn with a recorded cron approval
so unknown, evicted, or drifted cron-origin turns are rejected before tools run.

**Decision authority.** Cron-origin turns whose `cronJobId` is missing from the
daemon's cron decision log — or whose recorded approval has been evicted or
otherwise drifted — are denied with `cron-origin-policy-mismatch`. Verified
cron-origin turns continue with `cron_origin_verified` metadata.

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
approval. Pairs without a rule fall through to the default deny. Unknown
providers/actions fail closed before policy evaluation.

**Attack class.** [Channel-action granularity](./THREAT_MODEL.md#4-channel-action-granularity--live).

Match pairs with `labels`, which is an exact match. Do not use
`label_allowlist` here: Cordum fires a `label_allowlist` rule when the label
value is **not** in the list, which turns an allow for `slack.send` into an
allow for every other action.

```yaml
rules:
  # channel_action_allow is exact-pair keyed; do not replace with provider-only allow.
  - id: openclaw-channel_action_allow-slack-send
    match:
      topics: ["job.openclaw.message_write"]
      labels:
        channel_action: slack.send
    decision: allow
    reason: channel_action_allowed provider=slack action=send

  - id: openclaw-channel_action_allow-slack-delete-deny
    match:
      topics: ["job.openclaw.message_write"]
      labels:
        channel_action: slack.delete
    decision: deny
    reason: channel_action_denied provider=slack action=delete
```

### `exec_command_allow` — **IN-PROGRESS**

**Purpose.** Allow known-safe command families after `exec` commands are
canonicalized. The rules are present in `pack/policies/openclaw-safety.yaml`,
but current daemon HEAD does not yet emit `command_family` labels, so this path
is marked **IN-PROGRESS**.

**Decision authority.** Once command-family labels are emitted, a call whose
`command_family` is exactly `inspect`, `read_only` or `list` is ALLOWED by that
family's rule. Other families fall through to `openclaw-tool_allow-default`.
The secrets, destructive and scope denies come first, so a read-only command on
a secret path or outside the workspace is still denied. Today, obfuscation
defense is live through canonicalized risk tags and deny/approval rules such as
`destructive`, `cloud`, `infrastructure`, or `remote-access`.

**Attack class.** [Obfuscation bypass](./THREAT_MODEL.md#5-obfuscation-bypass--live).

Write one rule per family with `labels`, which is an exact match. A single
`label_allowlist` allow would fire for every family that is **not** listed.

```yaml
rules:
  - id: openclaw-exec_command_allow-read_only
    match:
      topics: ["job.openclaw.tool_call"]
      labels:
        command_family: read_only
    decision: allow
    reason: Read-only commands are allowed for OpenClaw tool calls.
```

### `file_path_scope` — **IN-PROGRESS**

**Purpose.** Keep file operations inside approved path scopes such as workspace
or temporary directories. The policy rule is present, but current daemon HEAD
does not yet emit `path_scope` labels, so this path is marked **IN-PROGRESS**.

**Decision authority.** Once path-scope labels are emitted, a call whose
`path_scope` is not `workspace` or `temp` is DENIED. Listed scopes, and calls
without a `path_scope` label, continue to the next rule. Today, secret/system
path risk tags can still DENY earlier in the rule set.

**Attack class.** Supports the tool pre-dispatch layer described in
[Other protections currently shipped](./THREAT_MODEL.md#other-protections-currently-shipped).

`label_allowlist` fires when the label value is **not** in the list, so an
"only these" scope is a `deny` placed above the allows. The `url_domain` scope
below and the `mcp_server` scope (`openclaw-mcp_server_allow-deny-unlisted`)
use the same shape.

```yaml
rules:
  - id: openclaw-file_path_scope-deny-outside
    match:
      topics: ["job.openclaw.tool_call"]
      label_allowlist:
        path_scope:
          - workspace
          - temp
    decision: deny
    reason: OpenClaw file operations outside the workspace and temp path scopes are denied.
```

### `url_domain_allow` — **IN-PROGRESS**

**Purpose.** Allow URL/browser actions only for known documentation and code-host
domains when URL labels are present. The policy rule is present, but current
daemon HEAD does not yet emit `url_domain` labels, so this path is marked
**IN-PROGRESS**.

**Decision authority.** Once URL-domain labels are emitted, a call whose
`url_domain` is not listed is DENIED. Listed domains, and calls without a
`url_domain` label, continue to the next rule. Matching is exact apart from
case, so `github.com` does not cover `api.github.com`. Today, non-HTTPS or
unknown network destinations must be handled by adjacent risk-tag/approval
rules.

**Attack class.** Supports data-exfiltration reduction, but post-tool result
blocking is also **IN-PROGRESS** until task-97da56e5 lands.

```yaml
rules:
  - id: openclaw-url_domain_allow-deny-unlisted
    match:
      topics: ["job.openclaw.tool_call"]
      label_allowlist:
        url_domain:
          - cordum.io
          - docs.cordum.io
          - github.com
    decision: deny
    reason: OpenClaw URL actions outside the approved documentation and code hosts are denied.
```

## Custom policies

Create a bundle fragment with site-specific rules. Keep comments for operator
notes and `reason` for surfaced rationale.

```yaml
version: "1"
default_tenant: default

rules:
  # Block uploads to Slack until channel-specific review is complete.
  - id: team-channel-action-deny-slack-upload
    match:
      topics: ["job.openclaw.message_write"]
      labels:
        channel_action: slack.upload_file
    decision: deny
    reason: Slack uploads are disabled pending data-loss review.
```

A policy rule cannot change what gets redacted from prompts. To add or tighten
prompt DLP patterns, edit a copy of `pack/policies/prompt-pii-redact.yaml` and
point `CORDCLAW_DLP_POLICY_PATH` at it.

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
