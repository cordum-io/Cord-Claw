# CordClaw output constraints hardening

Status: accepted 2026-04-27
Task: task-d8fe6dc1

CordClaw output constraints are enforced in the OpenClaw plugin at runtime and
validated by the daemon when it loads the policy bundle. The two gates are
deliberately redundant: bad runtime constraints fail closed in the plugin, and
bad pack policies fail loud before operators depend on them.

## allowed_destinations enum

`allowed_destinations` is a destination allow-list for constrained tool output.
The canonical values are:

- `file`
- `workspace`
- `channel`
- `network`

Any non-empty `allowed_destinations` list containing a value outside that enum
is rejected. The plugin returns a blocked result with an operator-visible reason
containing `canonical enum is {file,workspace,channel,network}`. The daemon's
`LoadRulesFile` applies the same enum at policy-load time and wraps the error
with the offending rule id.

An empty list still means "allow all destinations" for backwards
compatibility. This preserves the existing v1 contract used by policies that
set `allowed_destinations: []` as a no-op placeholder.

Runtime source of truth:
[`plugin/src/enforcer.ts`](../../plugin/src/enforcer.ts).
Policy-load source of truth:
[`daemon/internal/policy/shadow.go`](../../daemon/internal/policy/shadow.go).

## redact_patterns ReDoS gate

`redact_patterns` are operator-authored regular expressions applied to output
before truncation. They are powerful enough to protect secrets, but unsafe
regexes can also cause catastrophic backtracking in JavaScript runtimes. CordClaw
therefore rejects patterns that exceed a conservative complexity heuristic
before calling `new RegExp`.

The plugin and daemon use the same constants:

| Check | Limit | Example rejected reason |
| --- | --- | --- |
| Pattern length | `<= 200` characters | `length=250` |
| Quantifier count | `<= 5` of `*`, `+`, `?`, or `{...}` | `quantifier-count=6` |
| Nested quantifier shape | none | `nested-quantifier` for `(a+)+` or `(((a)+)+)+` |
| Alternation segments | `<= 10` | `alternation=11` |

The nested-quantifier check uses a single-pass group stack / parenthesis-depth
tracker so obfuscated forms such as `(((a)+)+)+` are rejected, not just the
literal `(a+)+` substring.

If a legitimate redaction rule trips the heuristic, split the pattern into
multiple smaller, more-specific patterns. The canonical pack patterns
`\\b\\d{16}\\b` and `\\bAKIA[0-9A-Z]{16}\\b` are part of the regression suite
and remain accepted.

## Defense in depth

CordClaw validates constraints in two places:

1. **Plugin runtime gate** — `applyOutputConstraints` checks
   `allowed_destinations` and `redact_patterns` before applying constraints to a
   tool result. Invalid values return `blocked=true` and an operator-visible
   reason.
2. **Daemon load-time gate** — `LoadRulesFile` validates `Rule.Constraints`
   after YAML parsing. Bad pack policies fail at daemon load with the rule id in
   the error, for example `shadow policy: rule openclaw-...: ...`.

This means a malformed policy can be caught during deployment, and an unexpected
runtime constraint from any source still fails closed at enforcement time.

## Adding a new destination

Adding a new output destination is a coordinated change. Update both source
files in the same PR:

- [`plugin/src/enforcer.ts`](../../plugin/src/enforcer.ts) — runtime enum.
- [`daemon/internal/policy/shadow.go`](../../daemon/internal/policy/shadow.go) —
  policy-load enum.

Also update tests in
[`plugin/src/__tests__/enforcer-output-constraints.test.ts`](../../plugin/src/__tests__/enforcer-output-constraints.test.ts)
and [`daemon/internal/policy/shadow_test.go`](../../daemon/internal/policy/shadow_test.go).
The enum and heuristic comments in the two implementation files are intentional;
do not remove them unless a shared generated source replaces both constants.

## Cross-references

- Canonical pass corpus:
  [`pack/policies/openclaw-safety.yaml`](../../pack/policies/openclaw-safety.yaml).
- Runtime implementation:
  [`plugin/src/enforcer.ts`](../../plugin/src/enforcer.ts).
- Policy-load implementation:
  [`daemon/internal/policy/shadow.go`](../../daemon/internal/policy/shadow.go).
- Task reference: task-d8fe6dc1.
