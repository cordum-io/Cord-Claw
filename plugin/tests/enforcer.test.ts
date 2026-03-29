import { describe, expect, it, vi } from "vitest";

import { enforce } from "../src/enforcer.js";

describe("enforce", () => {
  const logger = {
    warn: vi.fn(),
    info: vi.fn()
  };

  it("allows ALLOW decisions", () => {
    const input = { tool: "exec" };
    const output = enforce({ decision: "ALLOW", reason: "ok", governanceStatus: "connected" }, input, logger);
    expect(output).toEqual(input);
  });

  it("blocks DENY decisions", () => {
    const output = enforce(
      { decision: "DENY", reason: "blocked", governanceStatus: "connected" },
      { tool: "exec" },
      logger
    );

    expect(output.blocked).toBe(true);
    expect(String(output.userMessage)).toContain("blocked");
  });

  it("requires approval for REQUIRE_HUMAN decisions", () => {
    const output = enforce(
      {
        decision: "REQUIRE_HUMAN",
        reason: "approval needed",
        approvalRef: "apr-1",
        governanceStatus: "connected"
      },
      { tool: "exec" },
      logger
    );

    expect(output.blocked).toBe(true);
    expect(String(output.userMessage)).toContain("apr-1");
  });

  it("applies constraints", () => {
    const output = enforce(
      {
        decision: "CONSTRAIN",
        reason: "sandbox",
        governanceStatus: "connected",
        constraints: { sandbox: true, timeout: 25, readOnly: true }
      },
      { tool: "exec" },
      logger
    );

    expect(output.sandbox).toBe(true);
    expect(output.readOnly).toBe(true);
    expect(output.timeout).toBe(25);
  });
});