import {
  channelActions,
  channelProviders,
  type BeforeAgentStartEnvelope,
  type BeforeMessageWriteEnvelope,
  type BeforeToolExecutionEnvelope,
  type ChannelAction,
  type ChannelProvider,
  type PromptBuildEnvelope,
  type TurnOrigin
} from "../types.js";

const turnOrigins = new Set<string>(["user", "cron", "webhook", "pairing"]);
const validChannelProviders = new Set<string>(channelProviders);
const validChannelActions = new Set<string>(channelActions);
const slackBotTokenPattern = /\bxoxb-[A-Za-z0-9-]{20,}\b/g;
const openAIKeyPattern = /\bsk-[A-Za-z0-9_-]{10,}\b/g;

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

  return {
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

export function buildMessageWriteEnvelope(ctx: Record<string, unknown>): BeforeMessageWriteEnvelope {
  const channelProvider = normalizeChannelProvider(firstString(ctx, ["channel_provider", "channelProvider", "channelType", "provider"]));
  if (!validChannelProviders.has(channelProvider)) {
    throw new Error(`unsupported channel provider: ${channelProvider}`);
  }

  const channelID = firstString(ctx, [
    "channel_id",
    "channelId",
    "target",
    "target_id",
    "targetId",
    "room_id",
    "roomId",
    "conversation_id",
    "conversationId",
    "channel"
  ]);
  if (channelID === "") {
    throw new Error("before_message_write envelope missing channel_id");
  }

  const action = normalizeChannelAction(firstString(ctx, ["action", "channel_action", "channelAction", "operation", "verb"]));
  if (!validChannelActions.has(action)) {
    throw new Error(`unsupported channel action: provider=${channelProvider} action=${action}`);
  }

  const agent = firstString(ctx, ["agent", "agent_id", "agentId"]);
  const preview = previewFromContext(ctx);

  return {
    hookType: "before_message_write",
    hook_type: "before_message_write",
    hook: "before_message_write",
    tool: "message_write",
    channel_provider: channelProvider as ChannelProvider,
    channel_id: channelID,
    action: action as ChannelAction,
    message_preview: preview,
    agent,
    agent_id: agent,
    session: firstString(ctx, ["session", "session_id", "sessionId", "sessionKey"]),
    model: firstString(ctx, ["model"]),
    provider: firstString(ctx, ["provider"])
  };
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

function normalizeChannelProvider(provider: string): string {
  const normalized = provider.toLowerCase().trim().replace(/[_\s]+/g, "-");
  switch (normalized) {
    case "google-chat":
      return "googlechat";
    case "ms-teams":
    case "teams":
      return "msteams";
    case "i-message":
      return "imessage";
    case "whats-app":
      return "whatsapp";
    case "nextcloudtalk":
    case "nextcloud-talk":
      return "nextcloud-talk";
    default:
      return normalized;
  }
}

function normalizeChannelAction(action: string): string {
  const normalized = action.toLowerCase().trim().replace(/[\s-]+/g, "_");
  switch (normalized) {
    case "send_message":
    case "message":
    case "reply":
      return "send";
    case "broadcast_message":
      return "broadcast";
    case "upload":
    case "file_upload":
    case "attach":
    case "attachment":
      return "upload_file";
    case "download":
    case "file_download":
      return "download_file";
    case "reaction":
      return "react";
    case "delete_message":
    case "remove":
    case "destroy":
      return "delete";
    case "edit_message":
      return "edit";
    case "create_poll":
    case "poll_create":
      return "poll";
    default:
      return normalized;
  }
}

function previewFromContext(ctx: Record<string, unknown>): string {
  const message = firstString(ctx, ["message", "text", "content", "body", "preview"]);
  return truncatePreview(redactPreview(message), 200);
}

function redactPreview(preview: string): string {
  return preview.replace(slackBotTokenPattern, "<REDACTED-SLACK_BOT>").replace(openAIKeyPattern, "<REDACTED-OPENAI_KEY>");
}

function truncatePreview(preview: string, limit: number): string {
  if (preview.length <= limit) {
    return preview;
  }
  return preview.slice(0, limit);
}

function cronJobIDFromSession(session: string): string {
  const prefix = "cron:";
  if (!session.startsWith(prefix)) {
    return "";
  }
  return session.slice(prefix.length).trim();
}
