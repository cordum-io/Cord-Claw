import { beforeEach, describe, expect, it, vi } from "vitest";

import cordclawPlugin from "../index.js";

type HookRegistration = {
  name: string;
  handler: (ctx: Record<string, unknown>) => Promise<unknown>;
  options: Record<string, unknown>;
};

function registerPlugin(fetchImpl: typeof fetch) {
  const hooks: HookRegistration[] = [];
  vi.stubGlobal("fetch", fetchImpl);
  cordclawPlugin.register({
    config: {
      plugins: {
        entries: {
          cordclaw: {
            config: { daemonUrl: "http://daemon", timeoutMs: 250, failMode: "allow" }
          }
        }
      }
    },
    logger: { info: vi.fn(), warn: vi.fn() },
    registerHook(name: string, handler: HookRegistration["handler"], options: Record<string, unknown>) {
      hooks.push({ name, handler, options });
    },
    registerCli: vi.fn()
  });
  const hook = hooks.find((entry) => entry.name === "before_message_write");
  if (!hook) {
    throw new Error("before_message_write hook not registered");
  }
  return hook;
}

describe("channel-action attack closure", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("allows slack send but denies slack delete/upload on the same provider and channel", async () => {
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
      switch (body.action) {
        case "send":
          return { json: async () => ({ decision: "ALLOW", reason: "channel_action_allowed provider=slack action=send", governanceStatus: "connected" }) };
        case "delete":
          return { json: async () => ({ decision: "DENY", reason: "channel_action_denied provider=slack action=delete", governanceStatus: "connected" }) };
        case "upload_file":
          return {
            json: async () => ({
              decision: "DENY",
              reason: "channel_action_denied provider=slack action=upload_file exfil-risk",
              governanceStatus: "connected"
            })
          };
        default:
          return { json: async () => ({ decision: "DENY", reason: `unexpected action=${String(body.action)}`, governanceStatus: "connected" }) };
      }
    }) as unknown as typeof fetch;
    const hook = registerPlugin(fetchMock);

    const send = await hook.handler({
      channelProvider: "slack",
      channelId: "C123",
      action: "send",
      message: "deploy complete"
    });
    expect(send).toEqual(expect.objectContaining({ channel_provider: "slack", channel_id: "C123", action: "send" }));

    await expect(
      hook.handler({ channelProvider: "slack", channelId: "C123", action: "delete", message: "remove evidence" })
    ).rejects.toMatchObject({
      code: "cordclaw.message_write.blocked",
      reason: "channel_action_denied provider=slack action=delete",
      decision: "DENY"
    });

    await expect(
      hook.handler({ channelProvider: "slack", channelId: "C123", action: "upload_file", message: "send secrets.txt" })
    ).rejects.toMatchObject({
      code: "cordclaw.message_write.blocked",
      reason: "channel_action_denied provider=slack action=upload_file exfil-risk",
      decision: "DENY"
    });

    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("fails closed on unknown provider/action before a message write leaves OpenClaw", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({ decision: "ALLOW", reason: "should not be called", governanceStatus: "connected" })
    })) as unknown as typeof fetch;
    const hook = registerPlugin(fetchMock);

    await expect(
      hook.handler({ channelProvider: "unknown", channelId: "C123", action: "send", message: "hello" })
    ).rejects.toMatchObject({
      code: "cordclaw.message_write.blocked",
      reason: "unsupported channel provider: unknown"
    });

    await expect(
      hook.handler({ channelProvider: "slack", channelId: "C123", action: "nuke", message: "hello" })
    ).rejects.toMatchObject({
      code: "cordclaw.message_write.blocked",
      reason: "unsupported channel action: provider=slack action=nuke"
    });

    expect(fetchMock).not.toHaveBeenCalled();
  });
});
