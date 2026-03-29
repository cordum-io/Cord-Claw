export type Decision = "ALLOW" | "DENY" | "THROTTLE" | "REQUIRE_HUMAN" | "CONSTRAIN";

export interface CheckRequest {
  tool: string;
  command?: string;
  path?: string;
  url?: string;
  channel?: string;
  agent?: string;
  session?: string;
  model?: string;
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