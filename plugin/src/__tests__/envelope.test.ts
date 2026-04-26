import { describe, expect, it } from "vitest";

import { buildAgentStartEnvelope, buildToolExecutionEnvelope } from "../lib/envelope.js";
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

describe("tool execution approved intent metadata", () => {
  it("forwards cron.create allowlists without prompt or description text", () => {
    const envelope = buildToolExecutionEnvelope({
      tool: "cron.create",
      agent: "agent-1",
      session: "session-parent",
      prompt: "do not forward this prompt",
      description: "do not forward this description",
      allowedTools: ["web_fetch", "browser.navigate"],
      allowed_capabilities: "cordclaw.web-fetch, cordclaw.browser-navigate"
    });

    expect(envelope).toEqual(
      expect.objectContaining({
        tool: "cron.create",
        allowedTools: ["web_fetch", "browser.navigate"],
        allowed_tools: ["web_fetch", "browser.navigate"],
        allowedCapabilities: ["cordclaw.web-fetch", "cordclaw.browser-navigate"],
        allowed_capabilities: ["cordclaw.web-fetch", "cordclaw.browser-navigate"]
      })
    );
    expect(envelope).not.toHaveProperty("prompt_text");
    expect(JSON.stringify(envelope)).not.toContain("do not forward this prompt");
    expect(JSON.stringify(envelope)).not.toContain("do not forward this description");
  });

  it("forwards cron-origin tool-check allowlists from aliases", () => {
    const envelope = buildToolExecutionEnvelope({
      tool: "web_fetch",
      cronJobId: "cron-7",
      session: "cron:cron-7",
      tools: "web_fetch, browser.navigate",
      capabilities: ["cordclaw.web-fetch"]
    });

    expect(envelope).toEqual(
      expect.objectContaining({
        tool: "web_fetch",
        cronJobId: "cron-7",
        cron_job_id: "cron-7",
        allowedTools: ["web_fetch", "browser.navigate"],
        allowed_tools: ["web_fetch", "browser.navigate"],
        allowedCapabilities: ["cordclaw.web-fetch"],
        allowed_capabilities: ["cordclaw.web-fetch"]
      })
    );
  });
});
