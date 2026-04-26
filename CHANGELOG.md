# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Add adversarial DLP bypass test suite (30+ techniques), senior-engineer security review of `redact/dlp.go`, and `docs/DLP_RED_TEAM.md` threat model (task-6f85494c).
- Serialize CordClaw installer stack preparation with a portable lock and
  atomic mode-600 `.env` replacement so concurrent first installs cannot
  generate divergent `CORDUM_API_KEY` values (task-8b7e4824).
- Add CordClaw installer API-key precedence tests and setup docs for keeping
  `CORDUM_API_KEY` aligned with the running Cordum gateway without logging raw
  secrets (task-d1cff69c).
- Refresh ARCHITECTURE, THREAT_MODEL, and POLICY_GUIDE for the CordClaw security-first push: 5 hooks documented, 5 attack classes covered, and 6 policy primitives described with live/in-progress status badges (task-6beb04df).
- Demo refresh: `terminal-demo.sh` now exercises 4-of-5 attack classes end-to-end against the live daemon (cron-bypass, prompt-PII, channel-action, obfuscation); result-exfil scenario stubs in place pending task-97da56e5; visibility punchline reads `/audit` today and notes `/govern/jobs?pack_id=cordclaw` as Phase-2 future state (task-a71d76be).
- Add `before_message_write` channel-action enforcement — exact `channel_action_allow` policy pairs distinguish Slack send from delete/upload and fail closed on unknown provider/action inputs (task-11bfec30).
- Add `before_prompt_build` hook + DLP module — redacts or blocks API keys and secrets in agent prompts before the LLM provider call (task-341c3570).
- Persist cron-origin allow decisions in the daemon with a BoltDB-backed
  `cron_decisions_v1` store, 24h retention, Docker state volume, and
  fail-closed handling for unknown/evicted cron IDs (task-752e64d1).
- Add cron-origin allowlist correlation v2: cron.create records approved
  tool/capability intent metadata and cron-origin tool drift is denied before
  cache/safety with `cron-origin-tool-drift` (task-362041af).
- Harden prompt DLP with deterministic Unicode normalization + curated homoglyph folding before regex matching, while redacting original prompt byte spans and preserving non-secret Unicode text (task-4c48bc3a).
- Decode base64-encoded secrets before prompt DLP scanning, using a bounded stdlib-only budget of max 100 candidates × 2 KiB while keeping the benign-corpus false-positive rate at 0/1000 (task-ff10cb69).
- Lint `prompt_pii_redact` regexes at pack verification and daemon policy load time, rejecting broad wildcards, empty-match patterns, and nested quantifiers before they can deny/redact every prompt or create regex-risky policy packs (task-2eff8a3c).
- Add exec command canonicalization before regex tagging — base64 decode pipelines, command-local env expansion, static substitution surfacing, and guarded symlink resolution close command-obfuscation bypasses while preserving original command audit fields (task-011f0cf1).
- Add per-action fail-mode (`CORDCLAW_FAIL_MODE=graduated` + `CORDCLAW_FAIL_MODE_BY_ACTION` JSON override). Default table opens fail-mode for `read` only; `exec`/`write`/`messaging`/`schedule`/`browser` stay fail-closed. Most-restrictive-tag-wins ensures co-occurring tags can never relax safety. Outage decisions emit `cordclaw.fail_mode` + `cordclaw.cordum_reachable=false` structured log fields (task-44b6aa5e). See [docs/fail-mode.md](docs/fail-mode.md).

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
