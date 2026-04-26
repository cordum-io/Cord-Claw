# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Add `before_prompt_build` hook + DLP module — redacts or blocks API keys and secrets in agent prompts before the LLM provider call (task-341c3570).
- Persist cron-origin allow decisions in the daemon with a BoltDB-backed
  `cron_decisions_v1` store, 24h retention, Docker state volume, and
  fail-closed handling for unknown/evicted cron IDs (task-752e64d1).
- Add cron-origin allowlist correlation v2: cron.create records approved
  tool/capability intent metadata and cron-origin tool drift is denied before
  cache/safety with `cron-origin-tool-drift` (task-362041af).

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
