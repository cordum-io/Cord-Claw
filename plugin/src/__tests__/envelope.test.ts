import { describe, expect, it } from "vitest";

import { buildAgentStartEnvelope, buildMessageWriteEnvelope } from "../lib/envelope.js";
import { assertEnvelope } from "../types.js";

describe("agent-start envelope extraction", () => {
  it("handles supported turn origins and derives cron/webhook/pairing context", () => {
    expect(buildAgentStartEnvelope({ agent: "agent-1", session: "session-1", turnOrigin: "user" })).toEqual(
      expect.objectContaining({ turnOrigin: "user", session: "session-1" })
    );
    expect(buildAgentStartEnvelope({ agent: "agent-1", sessionKey: "cron:cron-7" })).toEqual(
      expect.objectContaining({ turnOrigin: "cron", session: "cron:cron-7", cronJobId: "cron-7" })
    );
    expect(buildAgentStartEnvelope({ agent: "agent-1", sessionKey: "hook:webhook-1" })).toEqual(
      expect.objectContaining({ turnOrigin: "webhook", session: "hook:webhook-1" })
    );
    expect(buildAgentStartEnvelope({ agent: "agent-1", session: "session-1", pairingId: "pair-1" })).toEqual(
      expect.objectContaining({ turnOrigin: "pairing", session: "session-1" })
    );
  });

  it("rejects unknown origins and cron origins without a cron job id", () => {
    expect(() => buildAgentStartEnvelope({ agent: "agent-1", session: "session-1", turnOrigin: "sideways" })).toThrow(
      "invalid turn_origin: sideways"
    );

    const missingCronID = buildAgentStartEnvelope({ agent: "agent-1", session: "session-1", turnOrigin: "cron" });
    expect(() => assertEnvelope(missingCronID)).toThrow("before_agent_start cron envelope missing cronJobId");
  });
});

describe("message-write envelope extraction", () => {
  it("normalizes channel provider/action fields into the daemon wire shape", () => {
    const envelope = buildMessageWriteEnvelope({
      channelProvider: "Slack",
      channelId: " C123 ",
      action: "send",
      message: "deploy complete",
      agentId: "agent-1",
      sessionKey: "sess-1"
    });

    expect(envelope).toEqual(
      expect.objectContaining({
        hookType: "before_message_write",
        hook_type: "before_message_write",
        hook: "before_message_write",
        tool: "message_write",
        channel_provider: "slack",
        channel_id: "C123",
        action: "send",
        message_preview: "deploy complete",
        agent: "agent-1",
        agent_id: "agent-1",
        session: "sess-1"
      })
    );
    expect(() => assertEnvelope(envelope)).not.toThrow();
  });

  it("rejects unsupported providers, unsupported actions, and empty channel IDs", () => {
    expect(() =>
      buildMessageWriteEnvelope({ channelProvider: "unknown", channelId: "C123", action: "send", message: "hello" })
    ).toThrow("unsupported channel provider: unknown");

    expect(() =>
      buildMessageWriteEnvelope({ channelProvider: "slack", channelId: "C123", action: "nuke", message: "hello" })
    ).toThrow("unsupported channel action: provider=slack action=nuke");

    expect(() =>
      buildMessageWriteEnvelope({ channelProvider: "slack", channelId: "   ", action: "send", message: "hello" })
    ).toThrow("before_message_write envelope missing channel_id");
  });

  it("redacts secret-like text before truncating message_preview to 200 characters", () => {
    const secret = "xoxb-123456789012345678901234 sk-TESTKEY-DONTLEAK";
    const longTail = "A".repeat(260);
    const envelope = buildMessageWriteEnvelope({
      channel_provider: "slack",
      channel_id: "C123",
      action: "send",
      text: `${secret} ${longTail}`
    });

    expect(envelope.message_preview).toContain("<REDACTED-SLACK_BOT>");
    expect(envelope.message_preview).toContain("<REDACTED-OPENAI_KEY>");
    expect(envelope.message_preview).not.toContain("xoxb-123456789012345678901234");
    expect(envelope.message_preview).not.toContain("sk-TESTKEY-DONTLEAK");
    expect(envelope.message_preview.length).toBeLessThanOrEqual(200);
  });
});
