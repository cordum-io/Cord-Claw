# CordClaw

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

`setup/install.sh` is scaffolded and will be expanded into the full under
5-minute installation flow from the PRD in Phase 3.

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

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md) and open an issue from the
templates in `.github/ISSUE_TEMPLATE/`.

## License

Apache-2.0
