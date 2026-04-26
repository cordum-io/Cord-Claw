# CordClaw Demo Recording Procedure

Use this guide to re-render `cordclaw-demo.gif` and `cordclaw-demo.mp4` from
the live terminal demo.

## Prerequisites

- CordClaw daemon running on `127.0.0.1:19090` or `DAEMON_URL` pointing at the
  target daemon.
- `curl` plus either `jq` or `python` for JSON formatting.
- A terminal recorder: Terminalizer or asciinema.
- `ffmpeg` for MP4 export.
- Terminal width near 110 columns and a large, readable font.

## Smoke-test before recording

```bash
bash -n demo/terminal-demo.sh
./demo/terminal-demo.sh
```

The script should print at least four `decision=` lines. Until task-97da56e5
lands, the result-exfiltration scene must print an explicit `SKIP` instead of a
fabricated result.

## Terminalizer flow

```bash
terminalizer record demo/cordclaw-demo --command 'bash demo/terminal-demo.sh'
terminalizer render demo/cordclaw-demo -o demo/cordclaw-demo.gif
ffmpeg -i demo/cordclaw-demo.gif -movflags faststart -pix_fmt yuv420p demo/cordclaw-demo.mp4
```

## asciinema flow

```bash
asciinema rec demo/cordclaw-demo.cast --command 'bash demo/terminal-demo.sh'
agg demo/cordclaw-demo.cast demo/cordclaw-demo.gif
ffmpeg -i demo/cordclaw-demo.gif -movflags faststart -pix_fmt yuv420p demo/cordclaw-demo.mp4
```

## Re-render gate

Do not replace the checked-in GIF/MP4 with a final all-green recording until
result-exfiltration result gating lands in task-97da56e5. Before that task ships,
recorded assets may show 4 wired scenarios plus the explicit result-exfil SKIP;
that is acceptable for interim internal review, but the release asset should be
re-rendered after all five scenarios are live.

## Safety checklist

- Never record real credentials, tenant secrets, or operator shell history.
- Keep the demo fixture `sk-DEMO-EXAMPLE-NOT-REAL-...` visibly marked as demo
  data.
- Re-run `./demo/terminal-demo.sh` immediately before rendering the final asset.
- Preserve the forward-looking dashboard line: `/govern/jobs?pack_id=cordclaw`
  is a Phase 2 visibility destination, not a live claim for this demo branch.
