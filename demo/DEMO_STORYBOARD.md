# CordClaw Demo Storyboard

Goal: produce one 5-minute terminal walkthrough and export:

- `demo/cordclaw-demo.gif` for README
- `demo/cordclaw-demo.mp4` for blog/social

## Scene Plan

1. Intro (10-15s)
- Show repo root and one-line value proposition.

2. Governance status (20s)
- Run daemon status endpoint.
- Explain connected/degraded signal.

3. Dangerous action blocked (45s)
- Simulate `rm -rf /`.
- Highlight `DENY` decision and reason.

4. Safe action allowed/constrained (45s)
- Simulate `npm test`.
- Highlight decision + constraints.

5. Human-in-the-loop example (45s)
- Simulate outbound messaging action.
- Explain `REQUIRE_APPROVAL` behavior when available.

6. Audit trail (30s)
- Show recent entries from `/audit`.

7. OpenClaw integration (45s)
- `openclaw cordclaw status`
- `openclaw cordclaw simulate --tool exec --command "rm -rf /"`

8. Wrap-up CTA (15s)
- Repo URL + quickstart mention.

## Recording Command

```bash
chmod +x demo/terminal-demo.sh
./demo/terminal-demo.sh
```

## Export Checklist

- Keep terminal width ~110 cols.
- Use large readable font and high contrast.
- Do not include secrets/tokens in terminal history.
- Trim dead time between scenes.
- Final assets:
  - `demo/cordclaw-demo.gif`
  - `demo/cordclaw-demo.mp4`
