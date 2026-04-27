# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

<!--
Authoring rule (per task-b4e775e4 rail): future feature PRs MUST append their
CHANGELOG entry in the same PR as the feature itself — never split into a
separate "docs follow-up" commit. This avoids drift between shipped behavior
and what operators are told changed.

Order entries within each section newest-first. Cite the originating Moe task
ID where one exists; cite the commit hash when an entry covers multiple
follow-ups against the same feature.

For upgrade guidance keyed to these entries, see `docs/UPGRADE.md`.
-->

## [Unreleased]

### Added

- `before_agent_start` hook + cron-origin policy check — gates agent boot for cron-launched OpenClaw runs and closes the cron-bypass escalation attack class (task-b25365c4, commit `aadc49b`).
- `before_prompt_build` hook + DLP module — redacts or blocks API keys and secrets in agent prompts before the LLM provider call (task-341c3570).
- docs(cordclaw): record per-agent rate-limit metrics decision (stay unlabeled; per-agent visibility via summary jobs + audit log) (task-ad5dbc61).
- Per-agent emission rate limit — caps `/check` evaluations per agent per second to bound the daemon's outbound load on the Cordum gateway (commit `bc4059d`). Rate-limited drops are summarized in a single `cordclaw_rate_limited_total` counter increment plus a periodic summary job; per-agent override knob is configurable via pack policy.
- Rate-limit summary jobs + per-agent overrides — completes the rate-limit emitter with summary-job emission via the gateway and operator-controllable thresholds (commit `03d6821`).

### Changed

- Per-agent rate-limit overrides are now sourced from trusted policy decision constraints; client-supplied labels are ignored (task-8e9c59a5).
- Mapper now emits canonical `job.openclaw.<hook>` topics and the CordumJobsClient honors `req.Topic` when set, so `/govern/jobs` can filter tool calls via `job.openclaw.tool_call` while preserving pack_id=`cordclaw` (task-a6c15d06).
- Pre-dispatch safety checks now route through Cordum's gateway HTTP `/api/v1/jobs` endpoint instead of the prior direct gRPC connection to the Safety Kernel (commit `9a61957`). Decisions still flow back through the gateway's existing `evaluateSubmitPolicy` path so existing policy bundles work unchanged. The architectural diagram in `README.md` will catch up in a docs refresh; behavior for operators is unchanged when `CORDUM_API_KEY` and the gateway URL resolve correctly.
- Fail-closed when a `/api/v1/jobs` response is missing a `safety_decision` block — previously a missing decision was treated as ALLOW; now the daemon refuses to dispatch the action and surfaces a graduated fail-closed status. Tightens the trust boundary against partial/invalid gateway responses (commit `f298721`).
- Prompt-DLP path forces fail-closed on daemon outage so a crash cannot become a silent allow on prompt-level secret scans (task-341c3570, commit `3d79707`).
- Renamed rate-limit summary label/envelope key from `count` to `denied_count` to align with the Phase-2 job-label contract (task-578c89d2). Pack rules and dashboards that read this label must update; the Prometheus metric name `cordclaw_rate_limited_total` is unchanged.

### Security

- **OpenClaw governance hook coverage expanded from 2 of 12 to 4 of 12.** Newly wired hooks: `before_agent_start` (closes cron-bypass escalation), `before_prompt_build` (closes prompt-level PII/secret leakage). Together with the existing `before_tool_call` + `after_tool_call` audit hooks, this closes two of the five exploitable attack classes catalogued in the epic plan; remaining hooks (`before_message_write`, modifying `after_tool_execution`, etc.) are tracked under the same epic.
- Pre-dispatch safety checks now traverse Cordum's existing audit + tenant-scoping path on every action instead of a direct gRPC bypass — every CordClaw decision is now visible in the same `/govern/jobs` page as any other Cordum job, with the same audit chain integrity guarantees.
- Daemon fails closed on missing or malformed safety decisions in the gateway response — a partial response can no longer become an inadvertent ALLOW.

### Deprecated

- Direct gRPC client to the Safety Kernel (`daemon/internal/client/safety.go`) is preserved in-tree for one release as a fallback, but the production code path has moved to the HTTP `/api/v1/jobs` flow. Remove in a future release once telemetry confirms zero gRPC client usage in the field.

## [0.1.0] - 2026-03-30

### Added

- **cordclaw-daemon**: Go sidecar binary with localhost HTTP API (`/check`, `/simulate`, `/health`, `/status`, `/audit`)
- **OpenClaw gateway plugin**: TypeScript shim intercepting `before_tool_execution` hooks
- **Cordum Pack**: Policy templates covering 10 OpenClaw action categories (exec, file read/write, browser, web, messaging, memory, cron)
- **Three policy profiles**: Strict (enterprise), Moderate (team), Permissive (personal)
- **Five decision types**: ALLOW, DENY, THROTTLE, REQUIRE_HUMAN, CONSTRAIN
- **LRU decision cache**: Sub-5ms cached lookups for repeated actions
- **Circuit breaker**: Graduated fail-closed logic when Safety Kernel is unavailable
- **Risk tag inference**: Regex-based detection of destructive commands, secrets patterns, non-HTTPS URLs
- **One-command installer**: `setup/install.sh` with profile selection and optional Cordum stack upgrade
- **Docker Compose stack**: Local development environment with Safety Kernel, Redis, NATS
- **Policy simulation tests**: 8 simulation test cases validating deny/allow/approval decisions
- **CI/CD**: GitHub Actions workflows for daemon (Go) and plugin (Node.js) testing
- **Community files**: CODE_OF_CONDUCT.md, SECURITY.md, CONTRIBUTING.md, issue/PR templates
- **Documentation**: Architecture guide, getting started tutorial, comparison matrix, adoption funnel
- **Examples**: Simulation payloads, custom policy YAML, environment templates
