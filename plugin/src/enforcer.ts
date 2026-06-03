import type { PolicyResponse } from "./types.js";

type Logger = { warn: (m: string) => void; info: (m: string) => void };

export function enforce(response: PolicyResponse, ctx: Record<string, unknown>, logger: Logger): Record<string, unknown> {
  if (response.governanceStatus !== "connected") {
    logger.warn(`[CordClaw] Governance ${response.governanceStatus} - operating on cached policies`);
  }

  switch (response.decision) {
    case "ALLOW":
      return ctx;

    case "DENY":
      return {
        ...ctx,
        blocked: true,
        userMessage: `[CordClaw] Action blocked: ${response.reason}`
      };

    case "THROTTLE":
      return {
        ...ctx,
        blocked: true,
        userMessage: "[CordClaw] Action rate-limited. Try again shortly."
      };

    case "REQUIRE_HUMAN":
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

      logger.info(`[CordClaw] Action allowed with constraints: ${response.reason}`);
      return modified;
    }
  }
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
