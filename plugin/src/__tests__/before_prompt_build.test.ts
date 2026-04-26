import { describe, expect, it, vi, beforeEach } from "vitest";

import cordclawPlugin from "../index.js";

type HookRegistration = {
  name: string;
  handler: (ctx: Record<string, unknown>) => Promise<unknown>;
  options: Record<string, unknown>;
};

function registerPlugin(fetchImpl: typeof fetch = vi.fn() as unknown as typeof fetch) {
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
  const hook = hooks.find((entry) => entry.name === "before_prompt_build");
  return { hooks, hook, logger, fetchMock: fetchImpl as unknown as ReturnType<typeof vi.fn> };
}

describe("before_prompt_build hook", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("packages prompt_text into the /check envelope and returns constrained prompt", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({
        decision: "CONSTRAIN",
        reason: "redacted prompt",
        governanceStatus: "connected",
        constraints: { kind: "prompt_redact", modified_prompt: "hello <REDACTED-OPENAI_KEY>" }
      })
    })) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    const result = await hook!.handler({
      prompt: "hello sk-TESTKEY-DONTLEAK",
      agent: "agent-1",
      provider: "openai",
      model: "gpt-4.1-mini",
      session: "sess-1"
    });

    expect(result).toBe("hello <REDACTED-OPENAI_KEY>");
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
        hook: "before_prompt_build",
        prompt_text: "hello sk-TESTKEY-DONTLEAK",
        agent: "agent-1",
        provider: "openai",
        model: "gpt-4.1-mini",
        session: "sess-1"
      })
    );
  });

  it("returns the original prompt when policy allows", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({ decision: "ALLOW", reason: "ok", governanceStatus: "connected" })
    })) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    const result = await hook!.handler({ prompt: "normal update", agent: "agent-1" });

    expect(result).toBe("normal update");
  });

  it("throws stable cordclaw.prompt.dlp_block code on deny", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({ decision: "DENY", reason: "prompt contains pattern OPENAI_KEY", governanceStatus: "connected" })
    })) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    await expect(hook!.handler({ prompt: "sk-TESTKEY-DONTLEAK", agent: "agent-1" })).rejects.toMatchObject({
      code: "cordclaw.prompt.dlp_block",
      reason: "prompt contains pattern OPENAI_KEY"
    });
  });

  it("fails closed with stable error code when daemon is unreachable", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("offline");
    }) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    await expect(hook!.handler({ prompt: "hello", agent: "agent-1" })).rejects.toMatchObject({
      code: "cordclaw.prompt.dlp_block",
      reason: "CordClaw daemon unreachable"
    });
  });

  it("fails closed when the hook context does not expose prompt text", async () => {
    const fetchMock = vi.fn(async () => ({
      json: async () => ({ decision: "ALLOW", reason: "ok", governanceStatus: "connected" })
    })) as unknown as typeof fetch;
    const { hook } = registerPlugin(fetchMock);
    expect(hook).toBeDefined();

    await expect(hook!.handler({ agent: "agent-1" })).rejects.toMatchObject({
      code: "cordclaw.prompt.dlp_block",
      reason: "prompt_text_unavailable"
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
