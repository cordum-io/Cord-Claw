import { beforeEach, describe, expect, it, vi } from "vitest";

import cordclawPlugin from "../index.js";

type HookRegistration = {
  name: string;
  handler: (ctx: Record<string, unknown>) => Promise<unknown>;
  options: Record<string, unknown>;
};

function registerPlugin(
  fetchImpl: typeof fetch = vi.fn() as unknown as typeof fetch,
  config: Record<string, unknown> = { daemonUrl: "http://daemon", timeoutMs: 250, failMode: "allow" }
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
  const hook = hooks.find((entry) => entry.name === "before_message_write");
  return { hooks, hook, logger, fetchMock: fetchImpl as unknown as ReturnType<typeof vi.fn> };
}

describe("before_message_write hook", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("registers before_message_write and sends sanitized channel action context to the daemon", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({ decision: "ALLOW", reason: "ok", governanceStatus: "connected" })
    })) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    const result = await hook!.handler({
      channelProvider: "slack",
      channelId: "C123",
      action: "send",
      message: "deployment done",
      agentId: "agent-1",
      sessionKey: "sess-1"
    });

    expect(result).toEqual(
      expect.objectContaining({
        hookType: "before_message_write",
        hook_type: "before_message_write",
        channel_provider: "slack",
        channel_id: "C123",
        action: "send",
        message_preview: "deployment done"
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
        hookType: "before_message_write",
        hook_type: "before_message_write",
        hook: "before_message_write",
        tool: "message_write",
        channel_provider: "slack",
        channel_id: "C123",
        action: "send",
        message_preview: "deployment done"
      })
    );
  });

  it("fails closed before message write when daemon denies or is unreachable", async () => {
    const denyFetch = vi.fn(async () => ({
      json: async () => ({ decision: "DENY", reason: "channel_action_denied provider=slack action=delete", governanceStatus: "connected" })
    })) as unknown as typeof fetch;
    const denied = registerPlugin(denyFetch);
    expect(denied.hook).toBeDefined();

    await expect(
      denied.hook!.handler({ channelProvider: "slack", channelId: "C123", action: "delete", message: "hello" })
    ).rejects.toMatchObject({
      code: "cordclaw.message_write.blocked",
      reason: "channel_action_denied provider=slack action=delete",
      decision: "DENY"
    });

    const offlineFetch = vi.fn(async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    const offline = registerPlugin(offlineFetch, { daemonUrl: "http://daemon", timeoutMs: 250, failMode: "allow" });
    expect(offline.hook).toBeDefined();

    await expect(
      offline.hook!.handler({ channelProvider: "slack", channelId: "C123", action: "send", message: "hello" })
    ).rejects.toMatchObject({
      code: "cordclaw.message_write.blocked",
      reason: "CordClaw daemon unreachable"
    });
  });
});
