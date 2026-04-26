export type Decision = "ALLOW" | "DENY" | "THROTTLE" | "REQUIRE_HUMAN" | "CONSTRAIN";
export type TurnOrigin = "user" | "cron" | "webhook" | "pairing";
export const channelProviders = [
  "feishu",
  "googlechat",
  "msteams",
  "mattermost",
  "matrix",
  "signal",
  "slack",
  "telegram",
  "discord",
  "imessage",
  "whatsapp",
  "nextcloud-talk",
  "irc"
] as const;
export type ChannelProvider = (typeof channelProviders)[number];

export const channelActions = [
  "send",
  "broadcast",
  "delete",
  "upload_file",
  "download_file",
  "react",
  "pin",
  "edit",
  "poll"
] as const;
export type ChannelAction = (typeof channelActions)[number];

const validTurnOrigins = new Set<TurnOrigin>(["user", "cron", "webhook", "pairing"]);
const validChannelProviders = new Set<ChannelProvider>(channelProviders);
const validChannelActions = new Set<ChannelAction>(channelActions);

export interface BeforeToolExecutionEnvelope {
  hookType: "before_tool_execution";
  tool: string;
  hook?: "before_tool_execution";
  command?: string;
  path?: string;
  url?: string;
  channel?: string;
  agent?: string;
  agent_id?: string;
  session?: string;
  model?: string;
  provider?: string;
  prompt_text?: string;
  cronJobId?: string;
  cron_job_id?: string;
}

export interface PromptBuildEnvelope {
  hookType: "before_prompt_build";
  tool: "prompt_build";
  hook: "before_prompt_build";
  prompt_text: string;
  agent?: string;
  agent_id?: string;
  session?: string;
  model?: string;
  provider?: string;
}

export interface BeforeAgentStartEnvelope {
  hookType: "before_agent_start";
  tool: "agent_start";
  hook: "before_agent_start";
  agent: string;
  agent_id?: string;
  session: string;
  turnOrigin: TurnOrigin;
  turn_origin?: TurnOrigin;
  parentSession?: string;
  parent_session_id?: string;
  cronJobId?: string;
  cron_job_id?: string;
  model?: string;
  provider?: string;
}

export interface BeforeMessageWriteEnvelope {
  hookType: "before_message_write";
  hook_type: "before_message_write";
  tool: "message_write";
  hook: "before_message_write";
  channel_provider: ChannelProvider;
  channel_id: string;
  action: ChannelAction;
  message_preview: string;
  agent?: string;
  agent_id?: string;
  session?: string;
  model?: string;
  provider?: string;
}

export type CheckRequest = BeforeToolExecutionEnvelope | PromptBuildEnvelope | BeforeAgentStartEnvelope | BeforeMessageWriteEnvelope;

export function assertEnvelope(req: unknown): asserts req is CheckRequest {
  if (typeof req !== "object" || req === null) {
    throw new Error("CordClaw envelope must be an object");
  }

  const envelope = req as Record<string, unknown>;
  const hookType = envelope.hookType;
  if (typeof hookType !== "string" || hookType === "") {
    throw new Error("CordClaw envelope missing hookType");
  }

  switch (hookType) {
    case "before_tool_execution":
      if (typeof envelope.tool !== "string" || envelope.tool === "") {
        throw new Error("before_tool_execution envelope missing tool");
      }
      return;

    case "before_prompt_build":
      if (envelope.tool !== "prompt_build") {
        throw new Error("before_prompt_build envelope must use tool=prompt_build");
      }
      if (typeof envelope.prompt_text !== "string" || envelope.prompt_text === "") {
        throw new Error("before_prompt_build envelope missing prompt_text");
      }
      return;

    case "before_agent_start": {
      const origin = envelope.turnOrigin;
      if (typeof origin !== "string" || !validTurnOrigins.has(origin as TurnOrigin)) {
        throw new Error("before_agent_start envelope has invalid turnOrigin");
      }
      if (typeof envelope.agent !== "string" || envelope.agent === "") {
        throw new Error("before_agent_start envelope missing agent");
      }
      if (typeof envelope.session !== "string" || envelope.session === "") {
        throw new Error("before_agent_start envelope missing session");
      }
      if (origin === "cron" && typeof envelope.cronJobId !== "string") {
        throw new Error("before_agent_start cron envelope missing cronJobId");
      }
      return;
    }

    case "before_message_write": {
      if (envelope.hook_type !== "before_message_write") {
        throw new Error("before_message_write envelope missing hook_type");
      }
      if (envelope.tool !== "message_write") {
        throw new Error("before_message_write envelope must use tool=message_write");
      }
      if (
        typeof envelope.channel_provider !== "string" ||
        !validChannelProviders.has(envelope.channel_provider as ChannelProvider)
      ) {
        throw new Error(`unsupported channel provider: ${String(envelope.channel_provider ?? "")}`);
      }
      if (typeof envelope.channel_id !== "string" || envelope.channel_id.trim() === "") {
        throw new Error("before_message_write envelope missing channel_id");
      }
      if (typeof envelope.action !== "string" || !validChannelActions.has(envelope.action as ChannelAction)) {
        throw new Error(
          `unsupported channel action: provider=${String(envelope.channel_provider ?? "")} action=${String(envelope.action ?? "")}`
        );
      }
      if (typeof envelope.message_preview !== "string" || envelope.message_preview.length > 200) {
        throw new Error("before_message_write envelope invalid message_preview");
      }
      return;
    }

    default:
      throw new Error(`CordClaw envelope has unsupported hookType: ${hookType}`);
  }
}

export interface PolicyResponse {
  decision: Decision;
  reason: string;
  governanceStatus: "connected" | "degraded" | "offline";
  constraints?: {
    maxTokens?: number;
    timeout?: number;
    sandbox?: boolean;
    allowedPaths?: string[];
    deniedPaths?: string[];
    readOnly?: boolean;
    kind?: string;
    modified_prompt?: string;
  };
  approvalRef?: string;
  cached?: boolean;
  latencyMs?: number;
}

export interface CordClawConfig {
  daemonUrl?: string;
  timeoutMs?: number;
  failMode?: "deny" | "allow";
  logDecisions?: boolean;
  bypassTools?: string[];
}
