# Security Policy

## Supported Versions

CordClaw is early-stage and moving quickly. We prioritize security fixes on the
latest `main` branch and the latest tagged release.

## Reporting a Vulnerability

Please do not open public issues for security vulnerabilities.

Report vulnerabilities privately to:

- security@cordum.io

When reporting, include:

- A clear description of the issue and affected component (daemon, plugin,
  setup, pack)
- Reproduction steps or proof-of-concept details
- Impact assessment (confidentiality/integrity/availability)
- Any mitigations or temporary workarounds you identified

## Disclosure Process

1. We acknowledge receipt within 3 business days.
2. We triage and reproduce the issue.
3. We coordinate a fix and release timeline with the reporter when possible.
4. We publish remediation details after a fix is available.

## Safe Harbor

If you act in good faith, avoid privacy violations, data destruction, or
service disruption, we will not pursue legal action for your research.

## Hardening Log

Security-improving changes are recorded here in addition to `CHANGELOG.md`.
Each entry names the originating Moe task and the attack class it closes.

### Unreleased

- **`before_agent_start` hook closes the cron-bypass escalation attack class.**
  Cron-launched OpenClaw runs are now subject to the same pre-dispatch policy
  evaluation as interactive sessions, so an attacker who can write a cron
  entry can no longer skip the gate. (task-b25365c4)
- **`before_prompt_build` hook + DLP module closes prompt-level PII and
  secret leakage.** API keys, tokens, and well-known secret patterns are
  redacted or blocked before they reach the LLM provider; daemon outage
  forces fail-closed so a crash cannot turn into a silent allow.
  (task-341c3570)
- **Pre-dispatch safety checks fail closed on missing safety decisions.**
  A `/api/v1/jobs` response that lacks a `safety_decision` block is now
  treated as a refusal; previously a partial response could become an
  inadvertent ALLOW. (commit `f298721`)
- **Per-agent emission rate limit caps daemon outbound load.** Bounds the
  surface available to a runaway or compromised agent that floods `/check`
  with evaluations; rate-limited events are summarized as a single Cordum
  job with a stable `denied_count` label.
