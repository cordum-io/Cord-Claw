import { beforeEach, describe, expect, it, vi } from "vitest";

import { CordClawShim } from "../src/shim.js";

describe("CordClawShim", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns daemon response for check", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        json: async () => ({ decision: "ALLOW", reason: "ok", governanceStatus: "connected" })
      }))
    );

    const shim = new CordClawShim("http://127.0.0.1:19090", 500, "deny");
    const result = await shim.check({ hookType: "before_tool_execution", tool: "exec", command: "echo hi" });

    expect(result.decision).toBe("ALLOW");
  });

  it("falls back to failMode on network errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("offline");
      })
    );

    const shim = new CordClawShim("http://127.0.0.1:19090", 500, "deny");
    const result = await shim.check({ hookType: "before_tool_execution", tool: "exec" });

    expect(result.decision).toBe("DENY");
    expect(result.governanceStatus).toBe("offline");
  });
});
