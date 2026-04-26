export type Decision = "ALLOW" | "DENY" | "THROTTLE" | "REQUIRE_HUMAN" | "CONSTRAIN";

export interface CheckRequest {
  tool: string;
  hook?: string;
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
}

export interface PromptBuildEnvelope extends CheckRequest {
  tool: "prompt_build";
  hook: "before_prompt_build";
  prompt_text: string;
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
