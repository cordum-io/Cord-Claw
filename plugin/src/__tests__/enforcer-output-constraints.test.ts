import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import { applyOutputConstraints, enforce } from "../enforcer.js";

const marker = (original: number, limit: number) => `[truncated: original=${original}, limit=${limit}]`;

describe("output constraint enforcement", () => {
  it("truncates string output by byte budget and appends a marker", () => {
    const output = "a".repeat(2048);

    const result = applyOutputConstraints({ output }, { max_output_bytes: 1024 });

    expect(result.blocked).toBe(false);
    expect(result.output).toBe(`${"a".repeat(1024)}${marker(2048, 1024)}`);
  });

  it("enforces byte budgets on Buffer and multibyte string outputs", () => {
    const binary = Buffer.alloc(4096, 0xab);

    const binaryResult = applyOutputConstraints({ output: binary }, { max_output_bytes: 1024 });

    expect(binaryResult.blocked).toBe(false);
    expect(Buffer.isBuffer(binaryResult.output)).toBe(true);
    const binaryOutput = binaryResult.output as Buffer;
    expect(binaryOutput.subarray(0, 1024)).toEqual(binary.subarray(0, 1024));
    expect(binaryOutput.subarray(1024).toString("utf8")).toBe(marker(4096, 1024));

    const emoji = "🚀".repeat(3);
    const emojiResult = applyOutputConstraints({ output: emoji }, { max_output_bytes: 8 });

    expect(emoji.length).toBe(6);
    expect(Buffer.byteLength(emoji, "utf8")).toBe(12);
    expect(emojiResult.output).toBe(`${"🚀".repeat(2)}${marker(12, 8)}`);
  });

  it("blocks output to destinations not listed in allowed_destinations", () => {
    const result = applyOutputConstraints(
      { output: "build log", destination: "channel" },
      { allowed_destinations: ["file", "workspace"] }
    );

    expect(result.blocked).toBe(true);
    expect(result.reason).toContain("channel");
  });

  it("allows output to listed destinations", () => {
    const result = applyOutputConstraints(
      { output: "build log", destination: "file" },
      { allowed_destinations: ["file", "workspace"] }
    );

    expect(result.blocked).toBe(false);
    expect(result.output).toBe("build log");
  });

  it("applies redact_patterns to string output", () => {
    const result = applyOutputConstraints(
      { output: "card 4111111111111111 token sk-test-abc123" },
      { redact_patterns: ["\\b\\d{16}\\b", "sk-test-[A-Za-z0-9]+"] }
    );

    expect(result.blocked).toBe(false);
    expect(result.output).toBe("card [REDACTED] token [REDACTED]");
  });

  it("applies redact_patterns to serialized object output", () => {
    const result = applyOutputConstraints(
      { output: { body: "token sk-test-object123", status: 200 } },
      { redact_patterns: ["sk-test-[A-Za-z0-9]+"] }
    );

    expect(result.blocked).toBe(false);
    expect(result.output).toBe('{"body":"token [REDACTED]","status":200}');
  });

  it("fails closed instead of throwing on invalid redact_patterns regex", () => {
    const result = applyOutputConstraints({ output: "safe output" }, { redact_patterns: ["[unclosed"] });

    expect(result.blocked).toBe(true);
    expect(result.reason).toContain("invalid redact_patterns regex");
  });

  it("treats an empty allowed_destinations list as allow-all", () => {
    const result = applyOutputConstraints(
      { output: "deploy note", destination: "network" },
      { allowed_destinations: [] }
    );

    expect(result.blocked).toBe(false);
    expect(result.output).toBe("deploy note");
  });

  it("redacts before truncating when multiple constraints are present", () => {
    const result = applyOutputConstraints(
      { output: `secret sk-test-abc123 ${"x".repeat(80)}` },
      { redact_patterns: ["sk-test-[A-Za-z0-9]+"], max_output_bytes: 32 }
    );

    expect(result.blocked).toBe(false);
    expect(String(result.output)).not.toContain("sk-test-abc123");
    expect(String(result.output)).toContain("[REDACTED]");
    expect(String(result.output)).toContain(marker(98, 32));
  });

  it("applies output constraints through the CONSTRAIN enforcer path", () => {
    const logger = { info: () => undefined, warn: () => undefined };
    const result = enforce(
      {
        decision: "CONSTRAIN",
        reason: "output constrained",
        governanceStatus: "connected",
        constraints: {
          max_output_bytes: 4,
          redact_patterns: ["sk-test-[A-Za-z0-9]+"],
          allowed_destinations: ["file", "workspace"]
        }
      },
      { output: "sk-test-secret123 ok", destination: "file" },
      logger
    );

    expect(result.blocked).toBeUndefined();
    expect(result.output).toBe(`[RED${marker(13, 4)}`);
  });

  it("blocks through the CONSTRAIN enforcer path without leaking malformed destination content", () => {
    const logger = { info: () => undefined, warn: () => undefined };
    const result = enforce(
      {
        decision: "CONSTRAIN",
        reason: "destination constrained",
        governanceStatus: "connected",
        constraints: {
          allowed_destinations: ["file", "workspace"]
        }
      },
      { output: "payload", destination: "channel\nsecret" },
      logger
    );

    expect(result.blocked).toBe(true);
    expect(result.userMessage).toContain("destination invalid not allowed");
    expect(result.userMessage).not.toContain("secret");
  });
});
