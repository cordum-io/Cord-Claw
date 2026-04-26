import { beforeEach, describe, expect, it, vi } from "vitest";

import cordclawPlugin from "../index.js";

type HookRegistration = {
  name: string;
  handler: (ctx: Record<string, unknown>) => Promise<unknown>;
  options: Record<string, unknown>;
};

function registerPlugin(fetchImpl: typeof fetch) {
  const hooks: HookRegistration[] = [];
  const logger = { info: vi.fn(), warn: vi.fn() };
  vi.stubGlobal("fetch", fetchImpl);
  cordclawPlugin.register({
    config: { plugins: { entries: { cordclaw: { config: { daemonUrl: "http://daemon", timeoutMs: 250, failMode: "deny" } } } } },
    logger,
    registerHook(name: string, handler: HookRegistration["handler"], options: Record<string, unknown>) {
      hooks.push({ name, handler, options });
    },
    registerCli: vi.fn()
  });

  return {
    beforeAgentStart: hooks.find((entry) => entry.name === "before_agent_start"),
    beforeToolExecution: hooks.find((entry) => entry.name === "before_tool_execution"),
    logger
  };
}

describe("cron bypass escalation attack", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("blocks unknown cron-origin turns before any disallowed tool can run", async () => {
    const allowedCronIDs = new Set<string>();
    const daemonLogs: string[] = [];
    const toolCalls: string[] = [];
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, string>;
      if (body.hookType === "before_tool_execution") {
        toolCalls.push(String(body.tool));
      }
      if (body.tool === "cron.create") {
        allowedCronIDs.add(String(body.cronJobId));
        return {
          json: async () => ({ decision: "ALLOW", reason: "cron create allowed", governanceStatus: "connected" })
        };
      }
      if (body.hookType === "before_agent_start" && body.turnOrigin === "cron" && !allowedCronIDs.has(String(body.cronJobId))) {
        daemonLogs.push("action=agent_start decision=DENY reason=cron-origin-policy-mismatch");
        return {
          json: async () => ({
            decision: "DENY",
            reason: "cron-origin-policy-mismatch",
            governanceStatus: "connected"
          })
        };
      }
      return {
        json: async () => ({ decision: "ALLOW", reason: "ok", governanceStatus: "connected" })
      };
    }) as unknown as typeof fetch;

    const { beforeAgentStart, beforeToolExecution } = registerPlugin(fetchMock);
    expect(beforeAgentStart).toBeDefined();
    expect(beforeToolExecution).toBeDefined();

    await beforeToolExecution!.handler({
      tool: "cron.create",
      jobId: "cron-allowed",
      agent: "agent-1",
      session: "session-parent"
    });
    await expect(
      beforeAgentStart!.handler({
        agent: "agent-1",
        session: "cron:cron-allowed",
        turnOrigin: "cron",
        cronJobId: "cron-allowed"
      })
    ).resolves.toEqual(expect.objectContaining({ turnOrigin: "cron", cronJobId: "cron-allowed" }));

    let blocked = false;
    try {
      await beforeAgentStart!.handler({
        agent: "agent-1",
        session: "cron:unknown-fake",
        turnOrigin: "cron",
        cronJobId: "unknown-fake"
      });
    } catch (err) {
      blocked = true;
      expect(err).toMatchObject({
        code: "cordclaw.agent_start.blocked",
        reason: "cron-origin-policy-mismatch"
      });
    }
    if (!blocked) {
      await beforeToolExecution!.handler({ tool: "exec", command: "curl http://attacker.invalid", agent: "agent-1" });
    }

    expect(daemonLogs).toContain("action=agent_start decision=DENY reason=cron-origin-policy-mismatch");
    expect(toolCalls).toEqual(["cron.create"]);
  });
});
