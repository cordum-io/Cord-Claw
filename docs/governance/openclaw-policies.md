# OpenClaw Pack — Topics, Pools, and Policy Primitives

This document describes how CordClaw exposes OpenClaw to Cordum's safety
kernel via a single config-only pack. No Cordum-core changes are required;
the pack ships under `Cord-Claw/pack/` and installs through the existing
`cordumctl pack install` flow.

## Two-file pack surface

| Path | Role |
| --- | --- |
| `Cord-Claw/pack/pools.d/openclaw.yaml` | Routes the six `job.openclaw.*` topics to dedicated pools with per-topic timeout + rate-limit defaults. |
| `Cord-Claw/pack/policies/openclaw-safety.yaml` | Bundle fragment carrying the OpenClaw-aware safety rules + the existing `prompt_pii_redact` config. |

Both files are declared in `pack.yaml` — `topics:` for the pool routing and
`overlays.policy:` (with `strategy: bundle_fragment`) for the policy
fragment. The `overlays.policy` mechanism is the supported policy loader
on the Cordum side; see `cordum/cmd/cordumctl/pack.go` and
`cordum/core/controlplane/gateway/packs/types.go` for the manifest schema.

## The six `job.openclaw.*` topics

OpenClaw hook events flow into Cordum as first-class jobs on six topics.
Each topic has its own pool so noisy traffic on one hook can be throttled
without touching the others.

| Topic | Maps to OpenClaw hook | Pool | Timeout | Rate limit |
| --- | --- | --- | --- | --- |
| `job.openclaw.tool_call` | `before_tool_call` / `after_tool_call` | `openclaw-tool-call` | 30s | 10 rps / 20 burst |
| `job.openclaw.prompt_build` | `before_prompt_build` | `openclaw-prompt-build` | 30s | 10 rps / 20 burst |
| `job.openclaw.agent_start` | `before_agent_start` | `openclaw-agent-lifecycle` | 60s | 10 rps / 20 burst |
| `job.openclaw.message_write` | `before_message_write` | `openclaw-message-write` | 30s | 10 rps / 20 burst |
| `job.openclaw.cron_fire` | `cron_origin_check` (synthetic, triggered by scheduler) | `openclaw-cron-fire` | 120s | 10 rps / 20 burst |
| `job.openclaw.result_gating` | `after_tool_call` (modifying mode) | `openclaw-result-gating` | 30s | 10 rps / 20 burst |

Defaults match Cordum-pool conventions; tune per-deployment by editing the
YAML and re-running `cordumctl pack install --upgrade`.

## Rule primitive families

`policies/openclaw-safety.yaml` ships nine rule primitive families covering
the five attack classes the epic targets (cron-bypass escalation, prompt-PII
leakage, exfiltration via tool result, granular channel-action gap,
obfuscation bypass).

| Primitive | Topic match | Decision shape | Tuning surface |
| --- | --- | --- | --- |
| `tool_deny` | `job.openclaw.tool_call` | DENY on `risk_tags: [secrets]` or `[destructive]` | Add tags via daemon classifier output |
| `tool_allow` | `job.openclaw.tool_call` | ALLOW default after explicit denies | Reorder denies before this baseline |
| `mcp_server_allow` | `job.openclaw.tool_call` | `match.label_allowlist.mcp_server` | Add MCP server identifiers |
| `exec_command_allow` | `job.openclaw.tool_call` | `match.label_allowlist.command_family` | Family taxonomy in daemon `mapper/openclaw.go` |
| `file_path_scope` | `job.openclaw.tool_call` | `match.label_allowlist.path_scope` | Scope strings emitted by daemon |
| `url_domain_allow` | `job.openclaw.tool_call` | `match.label_allowlist.url_domain` | Suffix-aware match |
| `channel_action_allow` | `job.openclaw.message_write` | `match.label_allowlist.channel_action` | `<provider>:<action>` pairs |
| `prompt_pii_redact` | `job.openclaw.prompt_build` | `allow_with_constraints` + `kind: prompt_pii_redact` | `redact_patterns` list |
| `cron_origin_check` | `job.openclaw.agent_start` + `job.openclaw.cron_fire` | DENY on cron-origin-policy mismatch | Match-rule label predicates |
| `result_gating` | `job.openclaw.result_gating` | `allow_with_constraints` (`max_output_bytes`, etc.) | Constraint values per tenant |

`risk_tags` matching in Cordum's `SafetyPolicy` is ANY-match — a rule that
lists `[secrets, destructive]` fires on either tag, not both. Use a single
specific tag per deny rule to keep semantics tight. Allowlists fail-open on
missing labels (the daemon SHOULD always emit them; if it doesn't, the rule
behaves as ALLOW). Document new labels in `daemon/internal/mapper/openclaw.go`
when extending these allowlists.

## Why `overlays.policy`, not a top-level `policies:` field

Earlier explorations considered a top-level `policies:` manifest section.
That field is not in Cordum's pack schema — see `packManifest` in
`cordum/cmd/cordumctl/pack.go` and `PackManifest` in
`cordum/core/controlplane/gateway/packs/types.go`. Both expose
`overlays.policy` as the only supported registration site. Using
`overlays.policy` with `strategy: bundle_fragment` fragments the safety
policy at install time so other CordClaw policy files (e.g. the existing
`overlays/policy.fragment.yaml`) compose without conflict.

## Static verification

`Cord-Claw/pack/tests/verify_pack.py` enforces the DoD-relevant invariants:
the six required topics, the policy primitive coverage, no rule-level
`description` keys, the `overlays.policy` registration, and matching
inline+file simulation names. Run it before opening any PR:

```bash
cd Cord-Claw/pack
python tests/verify_pack.py
# expected: [pack-verify] OK: pack metadata, resources, overlays, and simulations are valid
```

## Install + safety-kernel-load gates

Two install-time gates are tracked separately as task `task-e4e9489c`
(Cordum-core relaxations) and run after that task lands:

1. `cordumctl pack install` against a running stack — currently blocked
   on the topic-namespace validator that requires `job.<metadata.id>.*`.
   The relaxation adds `metadata.aliases` so a `cordclaw` pack can validate
   `job.openclaw.*` topics.
2. `docker logs cordum-safety-kernel-1` should show no
   `schema validation failed` lines for the bundle. Currently blocked on
   the safetykernel constraints schema rejecting `max_output_bytes`,
   `allowed_destinations`, and `redact_patterns` as `additionalProperties`.

When task-e4e9489c lands these two gates flip to GREEN with no further
pack edits required; the pack artifacts shipped here are forward-compatible.
