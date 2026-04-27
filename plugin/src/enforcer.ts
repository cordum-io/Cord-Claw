import { Buffer } from "node:buffer";

import type { PolicyResponse } from "./types.js";

type Logger = { warn: (m: string) => void; info: (m: string) => void };
type ConstraintSet = NonNullable<PolicyResponse["constraints"]>;
type OutputConstraintInput = Record<string, unknown> & {
  output?: unknown;
  result?: unknown;
  destination?: unknown;
};

export type OutputConstraintResult = {
  output: unknown;
  blocked: boolean;
  reason?: string;
};

export function agentStartBlocked(
  reason: string,
  decision = "DENY"
): Error & { code: string; reason: string; decision: string } {
  const err = new Error(`[CordClaw] Agent turn blocked: ${reason}`) as Error & {
    code: string;
    reason: string;
    decision: string;
  };
  err.code = "cordclaw.agent_start.blocked";
  err.reason = reason;
  err.decision = decision;
  return err;
}

export function enforce(response: PolicyResponse, ctx: Record<string, unknown>, logger: Logger): Record<string, unknown> {
  if (response.governanceStatus !== "connected") {
    logger.warn(`[CordClaw] Governance ${response.governanceStatus} - operating on cached policies`);
  }

  const isAgentStart = ctx.hookType === "before_agent_start" || ctx.hook === "before_agent_start";

  switch (response.decision) {
    case "ALLOW":
      return ctx;

    case "DENY":
      if (isAgentStart) {
        throw agentStartBlocked(response.reason, response.decision);
      }
      return {
        ...ctx,
        blocked: true,
        userMessage: `[CordClaw] Action blocked: ${response.reason}`
      };

    case "THROTTLE":
      if (isAgentStart) {
        throw agentStartBlocked("Action rate-limited. Try again shortly.", response.decision);
      }
      return {
        ...ctx,
        blocked: true,
        userMessage: "[CordClaw] Action rate-limited. Try again shortly."
      };

    case "REQUIRE_HUMAN":
      if (isAgentStart) {
        throw agentStartBlocked(response.reason, response.decision);
      }
      return {
        ...ctx,
        blocked: true,
        userMessage: [
          "[CordClaw] This action requires human approval.",
          `Action: ${String(ctx.tool ?? "unknown")}`,
          `Reason: ${response.reason}`,
          `Approval ref: ${response.approvalRef ?? "n/a"}`,
          `Approve via Cordum dashboard or: openclaw cordclaw approve ${response.approvalRef ?? "<ref>"}`
        ].join("\n")
      };

    case "CONSTRAIN": {
      const modified = { ...ctx };
      if (response.constraints?.sandbox) {
        modified.sandbox = true;
      }
      if (response.constraints?.readOnly) {
        modified.readOnly = true;
      }
      if (typeof response.constraints?.timeout === "number") {
        modified.timeout = response.constraints.timeout;
      }
      if (response.constraints?.kind === "prompt_redact" && typeof response.constraints.modified_prompt === "string") {
        modified.prompt = response.constraints.modified_prompt;
      }
      // TODO(task-97da56e5): when the after_tool_execution result-gating hook
      // becomes modifying, call this same helper from that hook as well. Until
      // then, this preserves output constraints for CONSTRAIN callers that pass
      // `output`/`result` through the existing enforcer surface.
      if (hasOutputConstraints(response.constraints) && ("output" in modified || "result" in modified)) {
        const constrained = applyOutputConstraints(modified, response.constraints);
        if (constrained.blocked) {
          return {
            ...modified,
            blocked: true,
            userMessage: `[CordClaw] Action blocked: ${constrained.reason ?? response.reason}`
          };
        }
        if ("output" in modified) {
          modified.output = constrained.output;
        } else {
          modified.result = constrained.output;
        }
      }

      logger.info(`[CordClaw] Action allowed with constraints: ${response.reason}`);
      return modified;
    }
  }
}

export function applyOutputConstraints(result: OutputConstraintInput, constraints: ConstraintSet = {}): OutputConstraintResult {
  let output = extractOutput(result);

  if (Array.isArray(constraints.redact_patterns) && constraints.redact_patterns.length > 0) {
    const redacted = redactOutput(output, constraints.redact_patterns);
    if (redacted.blocked) {
      return redacted;
    }
    output = redacted.output;
  }

  if (typeof constraints.max_output_bytes === "number") {
    if (!Number.isFinite(constraints.max_output_bytes) || !Number.isInteger(constraints.max_output_bytes) || constraints.max_output_bytes < 0) {
      return { output, blocked: true, reason: "cordclaw: invalid max_output_bytes constraint" };
    }
    const limited = truncateOutput(output, constraints.max_output_bytes);
    output = limited.output;
  }

  if (Array.isArray(constraints.allowed_destinations) && constraints.allowed_destinations.length > 0) {
    const destination = extractDestination(result);
    if (!constraints.allowed_destinations.includes(destination)) {
      return {
        output,
        blocked: true,
        reason: `cordclaw: destination ${displayDestination(destination)} not allowed by allowed_destinations`
      };
    }
  }

  return { output, blocked: false };
}

function hasOutputConstraints(constraints: ConstraintSet | undefined): constraints is ConstraintSet {
  return Boolean(
    constraints &&
      (typeof constraints.max_output_bytes === "number" ||
        (Array.isArray(constraints.allowed_destinations) && constraints.allowed_destinations.length > 0) ||
        (Array.isArray(constraints.redact_patterns) && constraints.redact_patterns.length > 0))
  );
}

function extractOutput(result: OutputConstraintInput): unknown {
  if (Object.prototype.hasOwnProperty.call(result, "output")) {
    return result.output;
  }
  if (Object.prototype.hasOwnProperty.call(result, "result")) {
    return result.result;
  }
  return result;
}

function extractDestination(result: OutputConstraintInput): string {
  if (typeof result.destination === "string" && result.destination !== "") {
    return result.destination;
  }
  const output = extractOutput(result);
  if (isRecord(output) && typeof output.destination === "string" && output.destination !== "") {
    return output.destination;
  }
  return "unknown";
}

function displayDestination(destination: string): string {
  return /^[A-Za-z0-9_.:-]{1,64}$/.test(destination) ? destination : "invalid";
}

function redactOutput(output: unknown, patterns: string[]): OutputConstraintResult {
  if (Buffer.isBuffer(output) || output instanceof Uint8Array) {
    return { output, blocked: false };
  }
  let redacted = typeof output === "string" ? output : serializeOutput(output);
  for (const pattern of patterns) {
    if (typeof pattern !== "string" || pattern === "") {
      return { output, blocked: true, reason: "cordclaw: invalid redact_patterns regex" };
    }
    let regex: RegExp;
    try {
      regex = new RegExp(pattern, "g");
    } catch {
      return { output, blocked: true, reason: "cordclaw: invalid redact_patterns regex" };
    }
    redacted = redacted.replace(regex, "[REDACTED]");
  }
  return { output: redacted, blocked: false };
}

function truncateOutput(output: unknown, limit: number): OutputConstraintResult {
  const byteLength = outputByteLength(output);
  if (byteLength <= limit) {
    return { output, blocked: false };
  }
  const marker = `[truncated: original=${byteLength}, limit=${limit}]`;
  if (Buffer.isBuffer(output)) {
    return { output: Buffer.concat([output.subarray(0, limit), Buffer.from(marker, "utf8")]), blocked: false };
  }
  if (output instanceof Uint8Array) {
    return {
      output: Buffer.concat([Buffer.from(output.subarray(0, limit)), Buffer.from(marker, "utf8")]),
      blocked: false
    };
  }
  const serialized = typeof output === "string" ? output : serializeOutput(output);
  return { output: `${truncateStringToUtf8Bytes(serialized, limit)}${marker}`, blocked: false };
}

function outputByteLength(output: unknown): number {
  if (Buffer.isBuffer(output) || output instanceof Uint8Array) {
    return output.length;
  }
  const serialized = typeof output === "string" ? output : serializeOutput(output);
  return Buffer.byteLength(serialized, "utf8");
}

function serializeOutput(output: unknown): string {
  if (typeof output === "string") {
    return output;
  }
  try {
    const encoded = JSON.stringify(output);
    return encoded === undefined ? String(output) : encoded;
  } catch {
    return String(output);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function truncateStringToUtf8Bytes(value: string, limit: number): string {
  let bytes = 0;
  let out = "";
  for (const char of value) {
    const size = Buffer.byteLength(char, "utf8");
    if (bytes + size > limit) {
      break;
    }
    out += char;
    bytes += size;
  }
  return out;
}

export function enforcePrompt(response: PolicyResponse, prompt: string, logger: Logger): { prompt: string; blocked: boolean; reason?: string } {
  if (response.governanceStatus !== "connected") {
    logger.warn(`[CordClaw] Governance ${response.governanceStatus} - operating on cached policies`);
  }

  switch (response.decision) {
    case "ALLOW":
      return { prompt, blocked: false };
    case "CONSTRAIN":
      if (response.constraints?.kind === "prompt_redact" && typeof response.constraints.modified_prompt === "string") {
        logger.info(`[CordClaw] Prompt allowed with constraints: ${response.reason}`);
        return { prompt: response.constraints.modified_prompt, blocked: false };
      }
      return { prompt, blocked: false };
    case "DENY":
    case "THROTTLE":
    case "REQUIRE_HUMAN":
      return { prompt, blocked: true, reason: response.reason };
  }
}
