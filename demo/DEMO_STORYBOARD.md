# CordClaw Demo Storyboard

Goal: produce one sub-5-minute terminal walkthrough that proves CordClaw protects
OpenClaw-powered Autonomous AI Agents at the Agent Control Plane boundary.

Export targets after the final all-5-scenarios re-render:

- `demo/cordclaw-demo.gif` for README and docs pages
- `demo/cordclaw-demo.mp4` for blog/social clips

## Runtime Budget

| Segment | Target |
| --- | ---: |
| Intro | 20s |
| 5 attack-class scenes | 5 x 45s = 225s |
| Audit visibility punchline | 25s |
| Closing CTA | 30s |
| **Total ceiling** | **300s** |

Each scene shows the same proof pattern: attack attempted -> live CordClaw
`/check` decision -> `/audit` visibility. The demo uses `/check` rather than
`/simulate` so prompt DLP and hook-specific checks run through the same path used
by the OpenClaw gateway plugin.

## Scene Plan

### 0. Intro: deterministic governance at the Agent Control Plane (20s)

- **On screen:** repo root, daemon URL, status endpoint.
- **Narrator:** CordClaw sits between OpenClaw and tool execution, enforcing
  deterministic governance before actions leave the agent process.
- **Command:** `GET /status`.
- **Expected decision:** status payload; degraded kernel is acceptable for local
  demo mode, because hook-local checks still execute.

### 1. Cron-bypass escalation (<=45s)

- **Attack attempted:** a cron-fired agent turn tries to start without a prior
  approved cron decision.
- **Live envelope:**

```json
{"hookType":"before_agent_start","tool":"agent_start","agent":"demo-agent","session":"cron:unallowlisted-job-id","turn_origin":"cron","cron_job_id":"unallowlisted-job-id"}
```

- **Expected decision:** `DENY`, reason includes
  `cron-origin-policy-mismatch`.
- **Security point:** closes attack class 1 by rejecting autonomous cron-origin
  turns that cannot be correlated to a recorded approval.

### 2. Prompt-level PII leakage (<=45s)

- **Attack attempted:** prompt text carries a demo API-key-shaped secret toward
  the LLM provider.
- **Live envelope:**

```json
{"hookType":"before_prompt_build","hook":"before_prompt_build","tool":"prompt_build","agent":"demo-agent","model":"demo-model","prompt_text":"Summarize this demo credential sk-DEMO-EXAMPLE-NOT-REAL-1234567890ABCDEFGH for the incident report"}
```

- **Expected decision:** `CONSTRAIN` with a redacted `modified_prompt`.
- **Security point:** closes attack class 2 by applying prompt DLP before model
  context is built. The fixture is explicitly marked `DEMO` and is not a real
  credential.

### 3. Channel-action gap (<=45s)

- **Attack attempted:** the agent asks to delete content from a Slack channel,
  not just send a benign message.
- **Live envelope:**

```json
{"hookType":"before_message_write","tool":"message_write","channel_provider":"slack","channel_id":"C123DEMO","action":"delete","message_preview":"delete the release approval thread","agent":"demo-agent","session":"session-channel-action"}
```

- **Expected decision:** `DENY` in local demo mode. With the policy backend
  connected, the policy reason should identify the denied channel/action pair.
- **Security point:** closes attack class 4 by preserving provider + channel +
  action metadata instead of treating all outbound messages as the same risk.

### 4. Obfuscation bypass (<=45s)

- **Attack attempted:** a destructive shell command is hidden behind a base64
  pipeline.
- **Live envelope:**

```json
{"tool":"exec","command":"echo cm0gLXJmIC8= | base64 -d | sh","agent":"demo-agent","session":"session-obfuscation"}
```

- **Expected decision:** `DENY`; audit details include the original command and
  a canonical command revealing `rm -rf /`.
- **Security point:** closes attack class 5 by canonicalizing command text before
  risk tagging and policy evaluation.

### 5. Result exfiltration via tool output (<=45s)

- **Attack attempted:** malicious tool output tries to smuggle sensitive content
  back into the model turn.
- **Status:** skipped at runtime until task-97da56e5 ships the modifying
  `after_tool_call`/`after_tool_execution` result gate.
- **Runtime behavior:** `terminal-demo.sh` probes the hook. If the daemon returns
  unknown-hook, the scene prints an explicit `SKIP` and continues. If the hook is
  present, it sends the real result-exfil envelope through `/check`.
- **Security point:** this is the fifth attack class and the script is ready, but
  the live demo does not fake unshipped result gating.

### 6. Audit visibility punchline (25s)

- **On screen:** `GET /audit?limit=10` pretty-printed.
- **Narrator:** every decision above produced a chronological audit entry with
  hook/tool context. This is the visibility proof today.
- **Forward-looking line:** once Phase 2 ships, every CordClaw decision also
  surfaces at `/govern/jobs?pack_id=cordclaw` on the Cordum dashboard.

### 7. Closing CTA (30s)

- **On screen:** install command and policy guide links.
- **Narrator:** start locally with the daemon demo, then connect CordClaw to the
  full Cordum governance plane for team rollout.

## Recording Command

```bash
chmod +x demo/terminal-demo.sh
./demo/terminal-demo.sh
```

## Export Checklist

- Keep terminal width near 110 columns.
- Use large readable font and high contrast.
- Do not include real secrets, tokens, or operator shell history.
- Keep each attack scene under 45 seconds.
- Re-render `demo/cordclaw-demo.gif` and `demo/cordclaw-demo.mp4` after
  task-97da56e5 lands so the final asset shows all five scenarios wired live.
