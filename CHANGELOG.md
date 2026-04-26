# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Add `before_prompt_build` hook + DLP module — redacts or blocks API keys and secrets in agent prompts before the LLM provider call (task-341c3570).
- Harden prompt DLP with deterministic Unicode normalization + curated homoglyph folding before regex matching, while redacting original prompt byte spans and preserving non-secret Unicode text (task-4c48bc3a).
- Decode base64-encoded secrets before prompt DLP scanning, using a bounded stdlib-only budget of max 100 candidates × 2 KiB while keeping the benign-corpus false-positive rate at 0/1000 (task-ff10cb69).

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
