# Demo Transcript

This narrator script aligns with `demo/DEMO_STORYBOARD.md` and the live
`demo/terminal-demo.sh` flow. Keep each scene concise so the recording stays
under five minutes.

## Opening

"CordClaw adds deterministic governance for OpenClaw-powered Autonomous AI
Agents. It works at the Agent Control Plane boundary: before a tool runs, before
prompt text reaches the model, and before high-risk agent lifecycle events turn
into real-world actions."

## Scene 0 — Status

"First, we check the local daemon. Even in a degraded local demo without the full
Safety Kernel, CordClaw still executes hook-local protections like cron-origin
validation and prompt DLP. The important part is that each scenario below is a
real `/check` round-trip, not a mocked output."

## Scene 1 — Cron-bypass escalation

"This cron-fired turn has no matching recorded approval. CordClaw blocks it with
`cron-origin-policy-mismatch`, so an agent cannot quietly convert a scheduled
background task into unrestricted autonomous execution. That closes the
cron-bypass escalation path before any tool is called."

## Scene 2 — Prompt-level PII leakage

"Here the prompt carries a demo API-key-shaped string. CordClaw evaluates the
prompt before model context is built, returns `CONSTRAIN`, and provides a
redacted prompt. Governance happens before sensitive text can become LLM input."

## Scene 3 — Channel-action gap

"Outbound messaging is not one generic permission. The envelope keeps provider,
channel, and action together, so Slack send, upload, and delete can have
different policy outcomes. This scene attempts a destructive channel action and
shows the live decision plus its audit entry."

## Scene 4 — Obfuscation bypass

"The command looks harmless if policy only scans raw text: base64 is decoded and
piped to a shell. CordClaw canonicalizes the command first, reveals `rm -rf /`,
and evaluates the dangerous operation instead of the disguise."

## Scene 5 — Result exfiltration

"Result exfiltration is the remaining attack class. The script probes for the
modifying result gate. If task-97da56e5 has not landed, we say so and skip the
scene rather than faking it. When it lands, this same slot becomes the live
result-gating demo."

## Audit visibility punchline

"Now we read `/audit`. The decisions are recorded chronologically with hook,
tool, and policy context. Today that is the local visibility proof. In Phase 2,
these CordClaw events also become Cordum jobs visible at `/govern/jobs` filtered
by `pack_id=cordclaw`."

## Closing

"CordClaw starts as a local control point and grows into full Cordum governance.
Use the setup script for a pilot, tune the policy guide for your team, then roll
out governed Autonomous AI Agents through the Agent Control Plane."
