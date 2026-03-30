# CordClaw Comparison

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

## Positioning Summary

CordClaw focuses on deterministic pre-dispatch governance for agent actions,
with explicit support for approval workflows, policy simulation, and full audit
visibility. It is designed as a governance control plane extension rather than
just a runtime sandbox or static allowlist.

## Deployment Comparison: Standalone vs Upgrade

| Capability | Standalone CordClaw | CordClaw + Cordum |
|-----------|----------------------|-------------------|
| Core enforcement | Yes (plugin + daemon) | Yes (plugin + daemon + Safety Kernel stack) |
| Setup path | `CORDUM_UPGRADE=false ./setup/install.sh` | `CORDUM_UPGRADE=true ./setup/install.sh` |
| Dashboard and incident triage | No | Yes |
| Centralized tenant operations | No | Yes |
| Policy pack lifecycle and simulation at scale | Limited/local | Full |
| Best fit | Solo dev, local pilot, PoC | Team rollout, regulated workloads, production governance |

See [docs/ADOPTION_FUNNEL.md](ADOPTION_FUNNEL.md) for the staged migration path.
