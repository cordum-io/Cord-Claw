# CordClaw attack classes

This page tracks OpenClaw attack classes closed by CordClaw hardening work.
The strategic roadmap is `C:\Users\yaron\.claude\plans\we-need-cordclaw-to-jiggly-forest.md`; this entry covers Phase 1 step 2.

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

## Cron-bypass tool drift

**Attack.** A cron job is approved for a narrow, harmless intent (for example a
web reminder) but the cron-fired turn later attempts a broader or more dangerous
tool such as `exec`. The v1 guard blocked unknown or evicted cron IDs at
`before_agent_start`, but a known cron ID could still drift during subsequent
tool checks if the tool request was allowed by general policy or cache.

**Mitigation.** Cron creation can now carry approved intent metadata as
`allowedTools`/`allowed_tools`/`tools` and
`allowedCapabilities`/`allowed_capabilities`/`capabilities`. The daemon
normalizes these allowlists, records them with the cron decision record, and
checks every cron-origin tool request before cache and before Safety Kernel:

- Unknown or evicted cron IDs still fail closed with
  `cron-origin-policy-mismatch`.
- Known cron IDs may start the agent turn with `cron_origin_verified`.
- Subsequent cron-origin tool checks must match either an allowed tool or an
  allowed capability. Drift is denied before Safety Kernel with
  `cron-origin-tool-drift`.
- An empty allowlist is explicit and does not mean allow all; it allows the
  agent-start correlation but denies subsequent cron-origin tool checks until a
  cron create supplies approved intent metadata.

**Operational notes.**

- Do not infer allowlists from cron prompt or description text. Those fields are
  not logged or persisted by this guard.
- The durable cron decision store persists only policy metadata (timestamps,
  topics, tags, agent, tools, capabilities); not prompt/description/body text.
- Pack policy entries continue to avoid top-level `description` keys because
  Cordum's schema rejects them.

**Verification.**

- Server tests cover harmless cron allowed, unknown cron denied with the v1
  reason, known cron with an allowed tool allowed, known cron with a disallowed
  tool denied with `cron-origin-tool-drift`, and empty allowlists failing closed
  for tool checks.
