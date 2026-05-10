# Cordum Edge / CordClaw Adoption Funnel

CordClaw is the Cordum Edge OpenClaw adapter and is free/open source (Apache
2.0). The funnel is designed to deliver immediate Edge governance value first,
then unlock full Cordum platform operations when teams are ready.

## Funnel Stages

| Stage | User intent | User action | Product signal | Next CTA |
|-------|-------------|-------------|----------------|----------|
| 1. Discover | "I need safer agent actions now" | Read README and run local install | Repo star, install script start | Try local Edge adapter setup |
| 2. Activate | "Show me deterministic control" | Enforce deny/throttle/require-human policies | First blocked or constrained risky tool call | Save and share policy profile |
| 3. Validate | "Will this work with my team?" | Run demo script and compare against alternatives | Demo completion + policy simulation run | Start pilot with shared policies |
| 4. Upgrade | "I need visibility and operations" | Enable full Cordum stack in installer | Dashboard login + audit trail usage | Move pilot to team rollout |
| 5. Expand | "I need organization-wide governance" | Adopt policy pack lifecycle and approval workflows | Multi-tenant usage and recurring policy updates | Standardize on Cordum platform |

## Journey Narrative

1. Land with the local Cordum Edge / CordClaw adapter to remove the "unsafe by default" gap.
2. Prove governance outcomes quickly with real blocked risky commands.
3. Introduce Cordum dashboard and tenant operations as the natural scale step.
4. Convert successful pilots into team-wide governance standards.

## Messaging Anchors

- Free entry point: "Cordum Edge / CordClaw is free Apache 2.0 and production-ready for local governance."
- Technical proof: "Deterministic pre-dispatch decisions on structured action metadata."
- Upgrade trigger: "When you need centralized operations, enable Cordum stack in one command."

## Upgrade Trigger in Installer

- Local Edge adapter mode: `CORDUM_UPGRADE=false ./setup/install.sh`
- Full Cordum Edge platform mode: `CORDUM_UPGRADE=true ./setup/install.sh`
- Default mode: installer prompt asks whether to enable the Cordum stack
