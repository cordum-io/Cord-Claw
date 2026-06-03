import { assertEnvelope, type CheckRequest, type PolicyResponse } from "./types.js";

export class CordClawShim {
  constructor(
    private readonly daemonUrl: string,
    private readonly timeoutMs: number,
    private readonly failMode: "deny" | "allow"
  ) {}

  async check(ctx: CheckRequest): Promise<PolicyResponse> {
    return this.checkWithFailMode(ctx, this.failMode);
  }

  async checkFailClosed(ctx: CheckRequest): Promise<PolicyResponse> {
    return this.checkWithFailMode(ctx, "deny");
  }

  private async checkWithFailMode(ctx: CheckRequest, failMode: "deny" | "allow"): Promise<PolicyResponse> {
    try {
      assertEnvelope(ctx);
      const payload: Record<string, unknown> = {
        hookType: ctx.hookType,
        tool: ctx.tool,
        hook: ctx.hook ?? ctx.hookType
      };
      if ("command" in ctx) payload.command = ctx.command;
      if ("path" in ctx) payload.path = ctx.path;
      if ("url" in ctx) payload.url = ctx.url;
      if ("channel" in ctx) payload.channel = ctx.channel;
      if ("agent" in ctx) payload.agent = ctx.agent;
      if ("agent_id" in ctx) payload.agent_id = ctx.agent_id;
      if ("session" in ctx) payload.session = ctx.session;
      if ("model" in ctx) payload.model = ctx.model;
      if ("provider" in ctx) payload.provider = ctx.provider;
      if ("prompt_text" in ctx) payload.prompt_text = ctx.prompt_text;
      if ("hook_type" in ctx) payload.hook_type = ctx.hook_type;
      if ("channel_provider" in ctx) payload.channel_provider = ctx.channel_provider;
      if ("channel_id" in ctx) payload.channel_id = ctx.channel_id;
      if ("action" in ctx) payload.action = ctx.action;
      if ("message_preview" in ctx) payload.message_preview = ctx.message_preview;
      if ("turnOrigin" in ctx) {
        payload.turnOrigin = ctx.turnOrigin;
        payload.turn_origin = ctx.turn_origin ?? ctx.turnOrigin;
      }
      if ("parentSession" in ctx) {
        payload.parentSession = ctx.parentSession;
        payload.parent_session_id = ctx.parent_session_id ?? ctx.parentSession;
      }
      if ("cronJobId" in ctx) {
        payload.cronJobId = ctx.cronJobId;
        payload.cron_job_id = ctx.cron_job_id ?? ctx.cronJobId;
      }

      const response = await fetch(`${this.daemonUrl}/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.timeoutMs)
      });

      return (await response.json()) as PolicyResponse;
    } catch {
      return {
        decision: failMode === "deny" ? "DENY" : "ALLOW",
        reason: "CordClaw daemon unreachable",
        governanceStatus: "offline"
      };
    }
  }

  async status(): Promise<Record<string, unknown>> {
    const response = await fetch(`${this.daemonUrl}/status`);
    return (await response.json()) as Record<string, unknown>;
  }

  async simulate(opts: Record<string, unknown>): Promise<PolicyResponse> {
    const response = await fetch(`${this.daemonUrl}/simulate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(opts)
    });
    return (await response.json()) as PolicyResponse;
  }

  async audit(ctx: Record<string, unknown>): Promise<void> {
    await fetch(`${this.daemonUrl}/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ctx),
      signal: AbortSignal.timeout(this.timeoutMs)
    });
  }

  async auditList(limit: number): Promise<Array<Record<string, unknown>>> {
    const response = await fetch(`${this.daemonUrl}/audit?limit=${limit}`);
    const data = (await response.json()) as { decisions?: Array<Record<string, unknown>> };
    return data.decisions ?? [];
  }
}
