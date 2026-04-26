import { describe, expect, it } from "vitest";

import { buildAgentStartEnvelope } from "../lib/envelope.js";
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
