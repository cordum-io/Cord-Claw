import type { CheckRequest, PolicyResponse } from "./types.js";

export class CordClawShim {
  constructor(
    private readonly daemonUrl: string,
    private readonly timeoutMs: number,
    private readonly failMode: "deny" | "allow"
  ) {}

  async check(ctx: CheckRequest): Promise<PolicyResponse> {
    try {
      const response = await fetch(`${this.daemonUrl}/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tool: ctx.tool,
          command: ctx.command,
          path: ctx.path,
          url: ctx.url,
          channel: ctx.channel,
          agent: ctx.agent,
          session: ctx.session,
          model: ctx.model
        }),
        signal: AbortSignal.timeout(this.timeoutMs)
      });

      return (await response.json()) as PolicyResponse;
    } catch {
      return {
        decision: this.failMode === "deny" ? "DENY" : "ALLOW",
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