export type Decision = "ALLOW" | "DENY" | "THROTTLE" | "REQUIRE_HUMAN" | "CONSTRAIN";
export type TurnOrigin = "user" | "cron" | "webhook" | "pairing";

const validTurnOrigins = new Set<TurnOrigin>(["user", "cron", "webhook", "pairing"]);

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

export type CheckRequest = BeforeToolExecutionEnvelope | PromptBuildEnvelope | BeforeAgentStartEnvelope;

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
    max_output_bytes?: number;
    allowed_destinations?: string[];
    redact_patterns?: string[];
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
