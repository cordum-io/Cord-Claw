# Cord-Claw Policy Guide

## Overview

Cord-Claw ships three built-in policy profiles. Each profile defines rules for 10 OpenClaw action categories. You can use a profile as-is or customize individual rules.

## Profiles

| Profile | Use Case | Default Behavior |
|---------|----------|-----------------|
| **Permissive** | Personal / developer use | Allow most operations. Block only obviously destructive commands and secrets access. |
| **Moderate** | Team / staging | Allow routine operations. Require approval for external messaging, scheduling, and package installs. Deny destructive and secrets access. |
| **Strict** | Enterprise / production | Require approval for most write operations. Deny destructive commands, secrets access, and cloud infrastructure operations. |

Set your profile during install:

```bash
CORDCLAW_PROFILE=moderate ./setup/install.sh
```

## Action Categories

| Category | Tool | Risk Tags | Permissive | Moderate | Strict |
|----------|------|-----------|------------|----------|--------|
| Shell execution | `exec` | exec, system, write | Allow (deny destructive) | Allow (deny destructive) | Require approval |
| File read | `file_read` | filesystem, read | Allow | Allow | Allow |
| File write | `file_write` | filesystem, write | Allow (deny secrets) | Allow (deny secrets) | Require approval (deny secrets) |
| Browser navigate | `browser_navigate` | network, browser | Allow | Allow | Allow |
| Browser interact | `browser_interact` | network, browser, write | Allow | Allow | Require approval |
| Web search | `web_search` | network, read | Allow | Allow | Allow |
| Web fetch | `web_fetch` | network, read | Allow | Allow | Allow (deny non-HTTPS) |
| Send message | `sessions_send` | messaging, write, external | Allow | Require approval | Require approval |
| Memory write | `memory_write` | memory, write, persistence | Allow | Allow | Require approval |
| Create cron | `cron.create` | schedule, write, autonomy | Allow | Require approval | Deny |

## Risk Tags

Risk tags are inferred from action metadata using regex patterns. They augment the base category to trigger stricter rules.

| Tag | Trigger | Effect |
|-----|---------|--------|
| `destructive` | `rm -rf`, `DROP`, `DELETE FROM`, `mkfs`, `dd if=` | Escalates to DENY in all profiles |
| `secrets` | Paths matching `.env`, `.pem`, `.key`, `credentials`, `tokens` | Escalates to DENY in all profiles |
| `cloud` | `aws`, `gcloud`, `az`, `terraform`, `kubectl` commands | Escalates to DENY in strict |
| `package-install` | `npm install`, `pip install`, `apt install` | Escalates to REQUIRE_APPROVAL in moderate/strict |
| `non-https` | URLs without `https://` prefix | Adds warning tag; DENY in strict |

## Custom Policies

Create a YAML file with your overrides:

```yaml
# custom-policy.yaml
rules:
  - topic: job.cordclaw.exec
    capability: cordclaw.shell-execute
    match:
      riskTags:
        contains: ["package-install"]
    decision: ALLOW
    reason: "Team policy: allow package installs without approval"

  - topic: job.cordclaw.message-send
    capability: cordclaw.message-send
    decision: DENY
    reason: "No external messaging allowed in this environment"
```

Apply it:

```bash
cordclaw-daemon --policy-override ./custom-policy.yaml
```

Custom rules are evaluated before profile defaults. First matching rule wins.

## Simulation

Test policy decisions without executing actions:

```bash
curl -X POST http://localhost:19090/simulate \
  -H "Content-Type: application/json" \
  -d @examples/payloads/deny-destructive-exec.json
```

Response:

```json
{
  "decision": "DENY",
  "reason": "Destructive command detected: rm -rf",
  "riskTags": ["exec", "system", "write", "destructive"],
  "cached": false
}
```

See `examples/payloads/` for sample simulation inputs.

## Related

- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design and control flow
- [THREAT_MODEL.md](./THREAT_MODEL.md) - What policies protect against and their limits
- [GETTING_STARTED.md](./GETTING_STARTED.md) - Hands-on tutorial
