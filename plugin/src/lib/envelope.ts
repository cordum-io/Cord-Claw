import type { BeforeAgentStartEnvelope, BeforeToolExecutionEnvelope, PromptBuildEnvelope, TurnOrigin } from "../types.js";

const turnOrigins = new Set<string>(["user", "cron", "webhook", "pairing"]);

function firstString(ctx: Record<string, unknown>, keys: string[]): string {
  for (const key of keys) {
    const value = ctx[key];
    if (typeof value === "string" && value.trim() !== "") {
      return value.trim();
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
  }
  return "";
}

function firstStringList(ctx: Record<string, unknown>, keys: string[]): { values: string[]; found: boolean } {
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(ctx, key)) {
      continue;
    }
    const value = ctx[key];
    if (Array.isArray(value)) {
      return {
        values: value
          .map((item) => (typeof item === "string" || typeof item === "number" || typeof item === "boolean" ? String(item).trim() : ""))
          .filter((item) => item !== ""),
        found: true
      };
    }
    if (typeof value === "string") {
      return {
        values: value
          .split(",")
          .map((item) => item.trim())
          .filter((item) => item !== ""),
        found: true
      };
    }
  }
  return { values: [], found: false };
}

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
  const agent = firstString(ctx, ["agent", "agent_id", "agentId"]);
  const session = firstString(ctx, ["session", "session_id", "sessionId", "sessionKey"]);
  const provider = firstString(ctx, ["provider"]);
  const model = firstString(ctx, ["model"]);

  return {
    hookType: "before_prompt_build",
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

export function buildToolExecutionEnvelope(ctx: Record<string, unknown>): BeforeToolExecutionEnvelope {
  const agent = firstString(ctx, ["agent", "agent_id", "agentId"]);
  const allowedTools = firstStringList(ctx, ["allowedTools", "allowed_tools", "tools"]);
  const allowedCapabilities = firstStringList(ctx, [
    "allowedCapabilities",
    "allowed_capabilities",
    "capabilities"
  ]);

  const envelope: BeforeToolExecutionEnvelope = {
    hookType: "before_tool_execution",
    hook: "before_tool_execution",
    tool: firstString(ctx, ["tool"]),
    command: firstString(ctx, ["command"]),
    path: firstString(ctx, ["path"]),
    url: firstString(ctx, ["url"]),
    channel: firstString(ctx, ["channel"]),
    agent,
    agent_id: agent,
    session: firstString(ctx, ["session", "session_id", "sessionId", "sessionKey"]),
    model: firstString(ctx, ["model"]),
    provider: firstString(ctx, ["provider"]),
    cronJobId: firstString(ctx, ["cron_job_id", "cronJobId", "job_id", "jobId"]),
    cron_job_id: firstString(ctx, ["cron_job_id", "cronJobId", "job_id", "jobId"])
  };
  if (allowedTools.found) {
    envelope.allowedTools = allowedTools.values;
    envelope.allowed_tools = allowedTools.values;
  }
  if (allowedCapabilities.found) {
    envelope.allowedCapabilities = allowedCapabilities.values;
    envelope.allowed_capabilities = allowedCapabilities.values;
  }
  return envelope;
}

export function buildAgentStartEnvelope(ctx: Record<string, unknown>): BeforeAgentStartEnvelope {
  const session = firstString(ctx, ["session", "session_id", "sessionId", "sessionKey"]);
  const agent = firstString(ctx, ["agent", "agent_id", "agentId"]);
  const turnOrigin = extractTurnOrigin(ctx, session);
  const parentSession = firstString(ctx, ["parent_session", "parentSession", "parent_session_id", "parentSessionId"]);
  const cronJobId = firstString(ctx, ["cron_job_id", "cronJobId", "job_id", "jobId"]) || cronJobIDFromSession(session);

  const envelope: BeforeAgentStartEnvelope = {
    hookType: "before_agent_start",
    tool: "agent_start",
    hook: "before_agent_start",
    agent,
    agent_id: agent,
    session,
    turnOrigin,
    turn_origin: turnOrigin,
    model: firstString(ctx, ["model"]),
    provider: firstString(ctx, ["provider"])
  };
  if (parentSession !== "") {
    envelope.parentSession = parentSession;
    envelope.parent_session_id = parentSession;
  }
  if (cronJobId !== "") {
    envelope.cronJobId = cronJobId;
    envelope.cron_job_id = cronJobId;
  }
  return envelope;
}

export function extractTurnOrigin(ctx: Record<string, unknown>, session = firstString(ctx, ["session", "session_id", "sessionId", "sessionKey"])): TurnOrigin {
  const explicit = firstString(ctx, ["turn_origin", "turnOrigin", "origin"]);
  if (explicit !== "") {
    if (turnOrigins.has(explicit)) {
      return explicit as TurnOrigin;
    }
    throw new Error(`invalid turn_origin: ${explicit}`);
  }

  if (firstString(ctx, ["cron_job_id", "cronJobId", "job_id", "jobId"]) !== "" || session.startsWith("cron:")) {
    return "cron";
  }
  if (firstString(ctx, ["webhook_id", "webhookId", "hook_id", "hookId"]) !== "" || session.startsWith("hook:")) {
    return "webhook";
  }
  if (firstString(ctx, ["pairing_id", "pairingId"]) !== "") {
    return "pairing";
  }
  return "user";
}

function cronJobIDFromSession(session: string): string {
  const prefix = "cron:";
  if (!session.startsWith(prefix)) {
    return "";
  }
  return session.slice(prefix.length).trim();
}
