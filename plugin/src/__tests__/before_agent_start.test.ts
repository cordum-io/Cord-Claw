import { beforeEach, describe, expect, it, vi } from "vitest";

import cordclawPlugin from "../index.js";

type HookRegistration = {
  name: string;
  handler: (ctx: Record<string, unknown>) => Promise<unknown>;
  options: Record<string, unknown>;
};

function registerPlugin(
  fetchImpl: typeof fetch = vi.fn() as unknown as typeof fetch,
  config: Record<string, unknown> = { daemonUrl: "http://daemon", timeoutMs: 250, failMode: "deny" }
) {
  const hooks: HookRegistration[] = [];
  const logger = { info: vi.fn(), warn: vi.fn() };
  vi.stubGlobal("fetch", fetchImpl);
  cordclawPlugin.register({
    config: { plugins: { entries: { cordclaw: { config } } } },
    logger,
    registerHook(name: string, handler: HookRegistration["handler"], options: Record<string, unknown>) {
      hooks.push({ name, handler, options });
    },
    registerCli: vi.fn()
  });
  const hook = hooks.find((entry) => entry.name === "before_agent_start");
  return { hooks, hook, logger, fetchMock: fetchImpl as unknown as ReturnType<typeof vi.fn> };
}

describe("before_agent_start hook", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("registers before_agent_start and sends cron origin context to the daemon", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({ decision: "ALLOW", reason: "ok", governanceStatus: "connected" })
    })) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    const result = await hook!.handler({
      agentId: "agent-1",
      sessionKey: "cron:cron-7",
      model: "gpt-5.4"
    });

    expect(result).toEqual(
      expect.objectContaining({
        hookType: "before_agent_start",
        hook: "before_agent_start",
        tool: "agent_start",
        agent: "agent-1",
        session: "cron:cron-7",
        turnOrigin: "cron",
        cronJobId: "cron-7"
      })
    );
    expect(fetchMock).toHaveBeenCalledWith(
      "http://daemon/check",
      expect.objectContaining({
        method: "POST",
        body: expect.any(String)
      })
    );
    const body = JSON.parse(String((fetchMock as unknown as ReturnType<typeof vi.fn>).mock.calls[0][1].body));
    expect(body).toEqual(
      expect.objectContaining({
        hookType: "before_agent_start",
        hook: "before_agent_start",
        tool: "agent_start",
        agent: "agent-1",
        session: "cron:cron-7",
        turnOrigin: "cron",
        turn_origin: "cron",
        cronJobId: "cron-7",
        cron_job_id: "cron-7"
      })
    );
  });

  it("throws a stable block error when daemon denies agent start", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({
        decision: "DENY",
        reason: "cron-origin-policy-mismatch",
        governanceStatus: "connected"
      })
    })) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    await expect(hook!.handler({ agent: "agent-1", session: "cron:unknown-fake" })).rejects.toMatchObject({
      code: "cordclaw.agent_start.blocked",
      reason: "cron-origin-policy-mismatch",
      decision: "DENY"
    });
  });

  it("fails closed before daemon call on unknown turn origin", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({ decision: "ALLOW", reason: "ok", governanceStatus: "connected" })
    })) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    await expect(hook!.handler({ agent: "agent-1", session: "sess-1", turnOrigin: "sideways" })).rejects.toMatchObject({
      code: "cordclaw.agent_start.blocked",
      reason: "invalid turn_origin: sideways"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("fails closed on daemon timeout even when ordinary tool failMode is allow", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock, { daemonUrl: "http://daemon", timeoutMs: 250, failMode: "allow" });
    expect(hook).toBeDefined();

    await expect(hook!.handler({ agent: "agent-1", session: "session-1", turnOrigin: "user" })).rejects.toMatchObject({
      code: "cordclaw.agent_start.blocked",
      reason: "CordClaw daemon unreachable"
    });
  });
});
