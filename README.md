# CordClaw

[![npm](https://img.shields.io/npm/v/%40cordum%2Fcordclaw?label=npm)](https://www.npmjs.com/package/@cordum/cordclaw)
[![CI](https://github.com/cordum-io/Cord-Claw/actions/workflows/ci.yml/badge.svg)](https://github.com/cordum-io/Cord-Claw/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/cordum-io/Cord-Claw?label=release)](https://github.com/cordum-io/Cord-Claw/releases)
[![Docker](https://img.shields.io/badge/ghcr-cordclaw--daemon-blue)](https://github.com/orgs/cordum-io/packages)
[![Homebrew](https://img.shields.io/badge/homebrew-cordclaw--daemon-orange)](https://github.com/cordum-io/homebrew-tap)
[![Powered by Cordum Safety Kernel](https://img.shields.io/badge/Powered%20by-Cordum%20Safety%20Kernel-0b7285)](docs/ARCHITECTURE.md)

Pre-dispatch governance for OpenClaw.

CordClaw inserts a deterministic policy decision before every OpenClaw tool
execution. It combines a local Go daemon, an OpenClaw gateway plugin, and
Cordum Safety Kernel policies to enforce `ALLOW`, `DENY`, `THROTTLE`,
`REQUIRE_HUMAN`, and `CONSTRAIN`.

## Why CordClaw

- Deterministic pre-dispatch control before actions run
- Prompt-injection-resistant enforcement on structured action metadata
- Human-in-the-loop and audit-ready decision outcomes
- Fast local path: cache hits target sub-5ms checks

## CordClaw to Cordum Journey

1. Start with free CordClaw and enforce deterministic local pre-dispatch policy.
2. Prove value quickly with deny/throttle/require-human policy outcomes in daily workflows.
3. Upgrade to full Cordum stack when you need dashboard visibility, multi-tenant controls, and centralized audit operations.
4. Roll out team-wide governance with policy packs, simulation, and approval workflows.

See [docs/ADOPTION_FUNNEL.md](docs/ADOPTION_FUNNEL.md) for the full funnel map.

## Architecture

```text
                          OpenClaw Gateway
                               |
                    [Agent wants to act]
                               |
                               v
                   +------------------------+
                   |   CordClaw Plugin      |
                   |   (TypeScript, in-proc)|
                   |                        |
                   |  1. Extract action     |
                   |     metadata           |
                   |  2. HTTP POST to       |
                   |     localhost:19090    |
                   |  3. Enforce decision   |
                   +----------+-------------+
                              |
                    HTTP (localhost only)
                              |
                              v
                   +------------------------+
                   |   cordclaw-daemon      |
                   |   (Go binary, sidecar) |
                   |                        |
                   |  - Client-side LRU     |
                   |    decision cache      |
                   |  - Warm gRPC conn to   |
                   |    Safety Kernel       |
                   |  - Circuit breaker     |
                   |  - Graduated fail-     |
                   |    closed logic        |
                   +----------+-------------+
                              |
                    gRPC (local or remote)
                              |
                              v
                   +------------------------+
                   |   Cordum Safety Kernel |
                   |                        |
                   |  - Input policy rules  |
                   |  - MCP filters         |
                   |  - Tenant isolation    |
                   |  - Server-side cache   |
                   |  - Audit trail         |
                   +------------------------+
                              |
                              v
                   ALLOW | DENY | THROTTLE |
                   REQUIRE_HUMAN | CONSTRAIN
                              |
                              v
                    [Action executes or not]
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design notes.

## Quickstart

### Daemon (Go)

```bash
cd daemon
make tidy
make test
make build
```

### Plugin (TypeScript)

```bash
cd plugin
npm install
npm test
npm run build
```

### One-command setup (Phase 3 target)

```bash
cd setup
OPENCLAW_SKIP=true ./install.sh
```

By default, the installer asks whether to enable the full Cordum stack.

Standalone CordClaw:

```bash
cd setup
CORDUM_UPGRADE=false OPENCLAW_SKIP=true ./install.sh
```

CordClaw + Cordum stack upgrade:

```bash
cd setup
CORDUM_UPGRADE=true OPENCLAW_SKIP=true ./install.sh
```

Use `CORDCLAW_PROFILE=strict|moderate|permissive` to choose baseline policy.

## Demo

Run the repeatable terminal demo script:

```bash
chmod +x demo/terminal-demo.sh
./demo/terminal-demo.sh
```

Recording assets and scene plan:

- `demo/DEMO_STORYBOARD.md`
- `demo/DEMO_TRANSCRIPT.md`

## Comparison

| Capability | CordClaw | NemoClaw | SecureClaw | Native OpenClaw |
|-----------|----------|----------|------------|-----------------|
| **Enforcement type** | Pre-dispatch, deterministic | Runtime sandbox | In-context rules | Tool allow/deny lists |
| **Prompt injection resistant** | Yes - structured envelope (see threat model for limits) | Yes (kernel-level) | No (in context window) | No (config-level) |
| **Policy language** | Declarative YAML | YAML (sandbox rules) | Natural language | JSON config |
| **Decision types** | 5 (allow/deny/throttle/require_human/constrain) | 2 (allow/deny) | 2 (allow/deny) | 2 (allow/deny) |
| **Human-in-the-loop** | Native (approval workflows) | No | No | Basic (exec approvals) |
| **Audit trail** | Full (every decision logged) | Partial | No | No |
| **Multi-tenant** | Yes | No | No | No |
| **Policy simulation** | Yes (test before deploy) | No | No | No |
| **Dashboard** | Yes (Cordum dashboard) | No | CLI only | No |
| **Hardware dependency** | None | NVIDIA preferred | None | None |
| **Fail mode** | Graduated (cached + blocked + degraded status) | Deny | N/A | N/A |
| **Latency overhead** | <5ms cached / <50ms warm / <200ms cold | Variable | None (in-process) | None (in-process) |
| **Open source** | Apache 2.0 | Open source | Open source | MIT |

| Deployment mode | Standalone CordClaw | CordClaw + Cordum |
|-----------------|---------------------|-------------------|
| Primary value | Local deterministic gateway control | Full governance platform (control + operations) |
| Recommended stage | Individual/pilot rollout | Team/production rollout |
| Dashboard + reporting | No | Yes |
| Multi-tenant policy operations | No | Yes |
| Upgrade path | `CORDUM_UPGRADE=true ./setup/install.sh` | Already enabled |

See [docs/COMPARISON.md](docs/COMPARISON.md) for details.

## Repository Layout

```text
cordclaw/
  daemon/   # Go governance daemon
  plugin/   # OpenClaw gateway plugin
  pack/     # Cordum policy pack
  setup/    # installer and local stack config
  docs/     # architecture, policy, threat-model, troubleshooting
```

## Learn More

- [Best Practices for Deploying AI Agents in Production](https://cordum.io/blog/deploy-ai-agents-production) — architecture, rollout, and governance checklist
- [What Is Pre-Dispatch Governance for AI Agents?](https://cordum.io/blog/pre-dispatch-governance-ai-agents) — why enforcement before execution matters
- [How to Secure OpenClaw Agents in Production](https://cordum.io/blog/how-to-secure-openclaw-agents-in-production) — complete governance guide

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and open an issue from the
templates in `.github/ISSUE_TEMPLATE/`.

## Community

- Discussions: https://github.com/cordum-io/Cord-Claw/discussions
- Community guide: [docs/COMMUNITY.md](docs/COMMUNITY.md)
- Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Security policy: [SECURITY.md](SECURITY.md)

## Publishing

Release and distribution workflow is documented in
[docs/PUBLISHING.md](docs/PUBLISHING.md).

## License

Apache-2.0
