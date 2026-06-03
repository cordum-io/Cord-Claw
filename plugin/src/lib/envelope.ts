import type { PromptBuildEnvelope } from "../types.js";

export function promptTextFromContext(ctx: Record<string, unknown>): string {
  if (typeof ctx.prompt === "string") {
    return ctx.prompt;
  }
  if (typeof ctx.prompt_text === "string") {
    return ctx.prompt_text;
  }
  if (typeof ctx.text === "string") {
    return ctx.text;
  }
  if (typeof ctx.input === "string") {
    return ctx.input;
  }
  return "";
}

export function buildPromptBuildEnvelope(ctx: Record<string, unknown>, prompt: string): PromptBuildEnvelope {
  const agent = String(ctx.agent ?? ctx.agent_id ?? "");
  const session = String(ctx.session ?? "");
  const provider = String(ctx.provider ?? "");
  const model = String(ctx.model ?? "");

  return {
    tool: "prompt_build",
    hook: "before_prompt_build",
    prompt_text: prompt,
    agent,
    agent_id: agent,
    session,
    provider,
    model
  };
}
