# OpenClaw channel-action matrix

Task: `task-11bfec30` — before_message_write channel-action granularity.

## Discovery provenance

- OpenClaw package inspected: `openclaw@2026.4.24` (`OpenClaw 2026.4.24 (cbcfdf6)`).
- Hook name evidence: packaged `CHANGELOG.md` explicitly references `before_message_write` for mirrored transcript writes and persistence regression coverage. The live `openclaw docs before_message_write` search returned no public docs result, so implementation must keep context extraction defensive rather than rely on a narrow documented payload shape.
- Provider capabilities were discovered with `openclaw channels capabilities --channel <provider> --json` for 12/13 required providers. On this Windows host the WhatsApp CLI path fails with `ERR_UNSUPPORTED_ESM_URL_SCHEME`; WhatsApp rows use the packaged plugin source (`dist/extensions/whatsapp/shared-DFK7it_n.js` and `channel-Q9B_RJru.js`) which exposes direct/group chat, media, polls, reactions, and react/poll channel actions.
- The `actions` array in the CLI output currently exposes `send` and `broadcast` for all providers that load. Capability flags (`media`, `reactions`, `polls`, `edit`) are mapped to explicit canonical actions so policy can distinguish file exfiltration, reactions, polls, and edits when a hook payload supplies those actions. Destructive/admin actions (`delete`, `pin`) are accepted as canonical hook payload actions even when not advertised by this OpenClaw capability surface, so the daemon/policy can deny them with exact `provider.action` reasons instead of collapsing them into generic sends.

## Provider capability summary

| Provider | Source | Reported actions | Capability flags used |
| --- | --- | --- | --- |
| `feishu` | openclaw channels capabilities | `send, broadcast` | `media, reactions, edit, threads` |
| `googlechat` | openclaw channels capabilities | `send, broadcast` | `media, reactions, threads, blockStreaming` |
| `msteams` | openclaw channels capabilities | `send, broadcast` | `media, polls, threads` |
| `mattermost` | openclaw channels capabilities | `send, broadcast` | `media, reactions, threads, nativeCommands` |
| `matrix` | openclaw channels capabilities | `send, broadcast` | `media, reactions, polls, threads` |
| `signal` | openclaw channels capabilities | `send, broadcast` | `media, reactions` |
| `slack` | openclaw channels capabilities | `send, broadcast` | `media, reactions, threads, nativeCommands` |
| `telegram` | openclaw channels capabilities | `send, broadcast` | `media, reactions, polls, threads, nativeCommands, blockStreaming` |
| `discord` | openclaw channels capabilities | `send, broadcast` | `media, reactions, polls, threads, nativeCommands` |
| `imessage` | openclaw channels capabilities | `send, broadcast` | `media` |
| `whatsapp` | packaged-plugin-source | `send, broadcast` | `media, reactions, polls` |
| `nextcloud-talk` | openclaw channels capabilities | `send, broadcast` | `media, reactions, blockStreaming` |
| `irc` | openclaw channels capabilities | `send, broadcast` | `media, blockStreaming` |

## Canonical action mapping

| Provider | Raw source action/capability | Canonical action | Risk tags | Source |
| --- | --- | --- | --- | --- |
| `feishu` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `feishu` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `feishu` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `feishu` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `feishu` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `feishu` | `support.edit=true` | `edit` | `messaging, write, external, destructive` | capability flag |
| `googlechat` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `googlechat` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `googlechat` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `googlechat` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `googlechat` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `msteams` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `msteams` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `msteams` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `msteams` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `msteams` | `support.polls=true` | `poll` | `messaging, write, external, poll` | capability flag |
| `mattermost` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `mattermost` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `mattermost` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `mattermost` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `mattermost` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `matrix` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `matrix` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `matrix` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `matrix` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `matrix` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `matrix` | `support.polls=true` | `poll` | `messaging, write, external, poll` | capability flag |
| `signal` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `signal` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `signal` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `signal` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `signal` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `slack` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `slack` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `slack` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `slack` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `slack` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `telegram` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `telegram` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `telegram` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `telegram` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `telegram` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `telegram` | `support.polls=true` | `poll` | `messaging, write, external, poll` | capability flag |
| `discord` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `discord` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `discord` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `discord` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `discord` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `discord` | `support.polls=true` | `poll` | `messaging, write, external, poll` | capability flag |
| `imessage` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `imessage` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `imessage` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `imessage` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `whatsapp` | `actions:send` | `send` | `messaging, write, external` | generic WhatsApp send |
| `whatsapp` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | generic WhatsApp broadcast |
| `whatsapp` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `whatsapp` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `whatsapp` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `whatsapp` | `support.polls=true` | `poll` | `messaging, write, external, poll` | capability flag |
| `nextcloud-talk` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `nextcloud-talk` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `nextcloud-talk` | `support.reactions=true` | `react` | `messaging, write, external, reaction` | capability flag |
| `nextcloud-talk` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `nextcloud-talk` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |
| `irc` | `actions:send` | `send` | `messaging, write, external` | CLI actions |
| `irc` | `actions:broadcast` | `broadcast` | `messaging, write, external, broadcast` | CLI actions |
| `irc` | `support.media=true` | `upload_file` | `messaging, write, external, exfil-risk` | capability flag |
| `irc` | `support.media=true` | `download_file` | `messaging, read, external, exfil-risk` | capability flag |

## Fail-closed notes

- Provider values outside the 13-provider set, empty channel IDs, and action values outside the canonical action enum must be treated as invalid and DENY for `before_message_write`.
- `delete` and `pin` are intentionally absent from the current discovered OpenClaw capability surface but are part of the canonical action enum for fail-closed policy. A payload with `provider=slack, action=delete` must reach the daemon as `channel_action=slack.delete` and DENY with `action=delete` in the reason instead of being treated as a generic Slack send. `pin` follows the same rule and should remain denied unless an operator adds an explicit exact-pair allow/approval rule.
- `media=true` maps to both `upload_file` and `download_file` because both are exfiltration-relevant policy surfaces. If a future OpenClaw release splits these into explicit raw actions, update this matrix and the table-driven tests together.
- Message previews must be redacted before the 200-character cap; this matrix only governs provider/action classification, not preview content handling.
