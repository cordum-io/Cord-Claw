# CordClaw attack classes

This page tracks OpenClaw attack classes closed by CordClaw hardening work.
The strategic roadmap is `C:\Users\yaron\.claude\plans\we-need-cordclaw-to-jiggly-forest.md`.

## Command obfuscation bypass

**Attack.** A destructive shell command can be hidden from the legacy regex
tagger by encoding or indirection, for example:

```sh
echo cm0gLXJmIC8= | base64 -d | sh
```

Before task-011f0cf1, the daemon evaluated the visible command text (`echo ...`)
and missed the decoded `rm -rf /`, so the exec request could look benign until a
shell decoded and executed it.

**Mitigation.** Exec actions now pass through
`daemon/internal/canonicalize.Normalize` immediately before command risk-tag
regexes run. The original command remains in the request/audit payload, while
the regexes inspect the canonical form. The canonicalizer:

- decodes explicit `echo|printf <blob> | base64 -d|--decode` pipelines, including
  short blobs such as the fixture above;
- scans generic base64-looking tokens only when they are at least 16 characters
  long to reduce false positives;
- expands command-local shell variables and explicit test/options environment
  maps, never the daemon process environment;
- surfaces `$(...)` and backtick command-substitution bodies as text without
  executing them;
- resolves path-like symlink tokens inside an optional path root before tagging.

**Limitations and guardrails.**

- CordClaw never executes attacker command text while canonicalizing.
- Recursive/double decoding is not performed unless explicitly implemented and
  tested in a future task.
- Generic base64 decoding intentionally has a length threshold; short blobs are
  decoded only in explicit decode-pipeline context.
- Symlink resolution skips `/proc`, `/sys`, and `/dev`, skips paths outside the
  configured path root, and records skip reasons instead of failing open.
- Cross-device/cross-root symlinks are skipped; symlink TOCTOU remains out of
  scope because CordClaw is not the command executor.

**Verification.**

- `daemon/internal/canonicalize/cmd_test.go` covers base64 pipelines, generic
  threshold behavior, command-local env expansion, static command-substitution
  surfacing, symlink skip/resolve behavior, and composition.
- `daemon/internal/mapper/openclaw_test.go` proves canonical text is what drives
  exec risk tags while the original command stays intact.
- `daemon/internal/server/server_test.go` drives the base64 and env-expansion
  attacks through `/check`, observes `destructive` risk tags, and receives a DENY
  from the configured policy path while audit retains both original and canonical
  command text.
- `daemon/internal/canonicalize/cmd_bench_test.go` keeps the no-op hot path under
  a 1ms p95 budget and records benchmark allocation counts.

## Channel-action granularity gap

**Attack.** A policy that only says "allow Slack messages" can accidentally
allow every action exposed by the same provider/channel, including destructive
or exfiltration-prone actions such as deleting a message, uploading a file, or
pinning content. Before task-11bfec30, CordClaw saw generic message-send style
traffic and could not make an exact decision on `(provider, action)` pairs.

**Mitigation.** The plugin now registers `before_message_write` and builds a
message-write envelope before OpenClaw writes to a channel. The envelope carries:

- `channel_provider` — one of the 13 mapped OpenClaw channel providers
  (`feishu`, `googlechat`, `msteams`, `mattermost`, `matrix`, `signal`,
  `slack`, `telegram`, `discord`, `imessage`, `whatsapp`,
  `nextcloud-talk`, `irc`).
- `channel_id` — the exact channel, room, conversation, or target.
- `action` — canonicalized action (`send`, `broadcast`, `delete`,
  `upload_file`, `download_file`, `react`, `pin`, `edit`, `poll`).
- `message_preview` — the first 200 characters after upstream redaction; this
  is audit context only, never a full message log.

The daemon maps the hook to `job.openclaw.message_write` with capability
`openclaw.message-write`, emits exact labels such as
`channel_action=slack.delete`, and derives risk tags from the
provider/action pair. The pack's `channel_action_allow` primitive is exact-pair
keyed: `slack.send` is allowed by default, while `slack.delete` denies with
`provider=slack action=delete` and `slack.upload_file` denies as
`exfil-risk`.

**Fail-closed behavior.**

- Unknown providers, unknown actions, and empty channel IDs return a DENY
  decision before the message write leaves OpenClaw.
- The plugin uses the fail-closed daemon path even if ordinary tool fail mode is
  configured as open/allow.
- The daemon audit trail stores provider/channel/action/risk tags and sanitized
  preview only; it does not store full message text.

**Verification.**

- `plugin/src/__tests__/channel_action_attack.test.ts` drives Slack `send`,
  `delete`, and `upload_file` through the same provider/channel and confirms
  only send is allowed.
- `daemon/internal/server/server_test.go` verifies the same-provider same-channel
  cache boundary: a cached Slack send decision is not reused for Slack delete.
- `pack/tests/verify_pack.py` rejects provider-only channel-action policy rules
  and requires exact `provider.action` simulations for Slack send/delete/upload
  and unknown fail-closed behavior.

## Prompt-level PII leakage

**Attack.** An agent reads context that includes credentials, such as a
`config.json` containing API keys, and quotes those credentials into the prompt
sent to OpenAI, Anthropic, or another model provider. Before task-341c3570,
CordClaw intercepted tool calls but not the assembled prompt, so secrets could
land in provider request logs.

**Mitigation.** The plugin now registers `before_prompt_build`, extracts the
assembled prompt text, and sends a prompt-build envelope to the daemon `/check`
endpoint before the provider call. The daemon scans the prompt with the
`prompt_pii_redact` primitive from `pack/policies/openclaw-safety.yaml` (or the
built-in fallback policy) and returns:

- `ALLOW` for prompts without matches.
- `CONSTRAIN` with `constraints.kind=prompt_redact` and a deterministic
  `modified_prompt` containing `<REDACTED-...>` placeholders.
- `DENY` for block-mode policies or oversized prompts.

The plugin fails closed for this hook: if the daemon is unreachable, OpenClaw
receives `cordclaw.prompt.dlp_block` and the prompt is not sent to the model.

**Default patterns.** The shipped primitive covers OpenAI-style keys, Slack bot
tokens, AWS access key IDs, context-guarded AWS secret values, and GitHub tokens.
Email redaction is opt-in through `include_email` so deployments can choose the
right balance between privacy and false positives.

**Operational notes.**

- Configure `CORDCLAW_DLP_POLICY_PATH` to point the daemon at the pack policy
  file when running outside the packaged deployment.
- Redaction is deterministic; identical input and policy produce byte-identical
  output, keeping prompt-build cache behavior stable.
- Logs and audit entries record hook, decision, match count, and pattern names
  only. They never include prompt text or matched literal values.

**Verification.**

- `daemon/test/integration/prompt_redaction_test.go` seeds a fake secret
  `sk-TESTKEY-DONTLEAK` and asserts no captured request body for
  `api.openai.com` or `api.anthropic.com` contains the literal.
- `daemon/internal/redact/dlp_fp_corpus_test.go` enforces a false-positive rate
  no higher than 0.5% across the benign prompt corpus.
