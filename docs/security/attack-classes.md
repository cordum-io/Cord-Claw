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

**Policy regex safety lint.** Tenant/operator-supplied `prompt_pii_redact`
patterns are statically linted before use. Pack verification and daemon policy
loading reject obvious whole-prompt wildcards such as `.*`, regexes that match
the empty string, and nested-quantifier shapes that can produce catastrophic
backtracking in less constrained engines. The daemon applies the same lint when
constructing a scanner directly, so custom policy loaders cannot bypass it.
This lint is deterministic/static plus a constant empty-string match check; it
does not execute regexes over generated stress prompts and is not an LLM
classifier.

**Unicode obfuscation hardening.** Prompt DLP scans a normalized shadow
representation before applying the configured regexes. The shadow is built with
Unicode NFKC plus a small curated homoglyph fold for credential-relevant ASCII
lookalikes (for example Cyrillic `ѕ`/`к` and fullwidth `ｓｋ` prefixes), so an
obfuscated OpenAI-style token is still detected before provider submission. The
daemon never substitutes the normalized shadow back into the user prompt:
matches are mapped back to original UTF-8 byte spans and the original prompt is
redacted in place with deterministic `<REDACTED-...>` placeholders. Non-secret
Unicode text such as accents, emoji, CJK, and Cyrillic words is preserved
exactly outside matched spans.

This is deterministic preprocessing plus regex DLP, not an LLM classifier.
Base64/encoded payload decoding remains a separate hardening track.

**Operational notes.**

- Configure `CORDCLAW_DLP_POLICY_PATH` to point the daemon at the pack policy
  file when running outside the packaged deployment.
- Redaction is deterministic; identical input and policy produce byte-identical
  output, keeping prompt-build cache behavior stable. Normalized matching still
  returns original prompt byte spans for placeholder insertion.
- Invalid policy regex errors include the pattern name and lint category only.
  They do not include prompt text, matched literal values, or sample secrets.
- Logs and audit entries record hook, decision, match count, and pattern names
  only. They never include prompt text, normalized shadow text, or matched
  literal values.

**Verification.**

- `daemon/test/integration/prompt_redaction_test.go` seeds a fake secret
  `sk-TESTKEY-DONTLEAK` and asserts no captured request body for
  `api.openai.com` or `api.anthropic.com` contains the literal.
- The same integration suite covers fullwidth/homoglyph-obfuscated
  OpenAI-style keys and asserts provider request bodies contain the placeholder,
  not the original obfuscated token or normalized ASCII token.
- `daemon/internal/redact/dlp_fp_corpus_test.go` enforces a false-positive rate
  no higher than 0.5% across the benign prompt corpus.
- `pack/tests/verify_pack_regex_lint_test.py` and
  `daemon/internal/redact/pattern_lint_test.go` cover broad, empty-match, and
  nested-quantifier policy regex rejection while asserting shipped patterns
  remain valid.
