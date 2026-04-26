import { CordClawShim } from "./shim.js";
import { agentStartBlocked, enforce, enforcePrompt } from "./enforcer.js";
import { buildAgentStartEnvelope, buildPromptBuildEnvelope, buildToolExecutionEnvelope, promptTextFromContext } from "./lib/envelope.js";
import type { CordClawConfig } from "./types.js";

function parseConfig(api: any): Required<CordClawConfig> {
  const config = (api.config?.plugins?.entries?.cordclaw?.config ?? {}) as CordClawConfig;
  return {
    daemonUrl: config.daemonUrl ?? "http://127.0.0.1:19090",
    timeoutMs: config.timeoutMs ?? 500,
    failMode: config.failMode ?? "deny",
    logDecisions: config.logDecisions ?? true,
    bypassTools: config.bypassTools ?? []
  };
}

function promptBlocked(reason: string): Error & { code: string; reason: string } {
  const err = new Error(`[CordClaw] Prompt blocked: ${reason}`) as Error & { code: string; reason: string };
  err.code = "cordclaw.prompt.dlp_block";
  err.reason = reason;
  return err;
}

export default {
  id: "cordclaw",
  name: "CordClaw - Cordum Governance",

  register(api: any): void {
    const config = parseConfig(api);
    const bypassTools = new Set(config.bypassTools);
    const shim = new CordClawShim(config.daemonUrl, config.timeoutMs, config.failMode);

    api.registerHook(
      "before_tool_execution",
      async (ctx: Record<string, unknown>) => {
        const envelope = buildToolExecutionEnvelope(ctx);
        if (bypassTools.has(envelope.tool)) {
          return ctx;
        }

        const response = await shim.check(envelope);
        if (config.logDecisions) {
          api.logger.info(`[CordClaw] ${response.decision} ${envelope.tool}: ${response.reason}`);
        }

        return enforce(response, { ...ctx, ...envelope }, api.logger);
      },
      { priority: 1000, name: "cordclaw-pre-dispatch" }
    );

    api.registerHook(
      "before_agent_start",
      async (ctx: Record<string, unknown>) => {
        let envelope: ReturnType<typeof buildAgentStartEnvelope>;
        try {
          envelope = buildAgentStartEnvelope(ctx);
        } catch (err) {
          const reason = err instanceof Error ? err.message : "agent_start_envelope_invalid";
          throw agentStartBlocked(reason);
        }

        const response = await shim.checkFailClosed(envelope);
        if (config.logDecisions) {
          api.logger.info(`[CordClaw] ${response.decision} agent_start origin=${envelope.turnOrigin}: ${response.reason}`);
        }

        return enforce(response, { ...ctx, ...envelope }, api.logger);
      },
      { priority: 1000, name: "cordclaw-before-agent-start" }
    );

    api.registerHook(
      "before_prompt_build",
      async (ctx: Record<string, unknown>) => {
        const prompt = promptTextFromContext(ctx);
        if (prompt === "") {
          throw promptBlocked("prompt_text_unavailable");
        }
        const response = await shim.checkFailClosed(buildPromptBuildEnvelope(ctx, prompt));
        if (config.logDecisions) {
          api.logger.info(`[CordClaw] ${response.decision} before_prompt_build: ${response.reason}`);
        }

        const enforced = enforcePrompt(response, prompt, api.logger);
        if (enforced.blocked) {
          throw promptBlocked(enforced.reason ?? response.reason);
        }
        return enforced.prompt;
      },
      { priority: 1000, name: "cordclaw-prompt-dlp" }
    );

    api.registerHook(
      "after_tool_execution",
      async (ctx: Record<string, unknown>) => {
        const tool = String(ctx.tool ?? "");
        if (bypassTools.has(tool)) {
          return;
        }
        await shim.audit(ctx).catch(() => undefined);
      },
      { priority: 1000, name: "cordclaw-audit" }
    );

    api.registerCli(
      ({ program }: any) => {
        const cmd = program.command("cordclaw");

        cmd
          .command("status")
          .description("Show CordClaw governance status")
          .action(async () => {
            const status = await shim.status();
            console.log(`Daemon: ${String(status.daemon ?? "unknown")}`);
            console.log(`Safety Kernel: ${String(status.kernel ?? "unknown")}`);
            console.log(`Policy Snapshot: ${String(status.snapshot ?? "n/a")}`);
            console.log(`Governance: ${String(status.governanceStatus ?? "unknown")}`);
            console.log(`Cached Decisions: ${String(status.cacheSize ?? "0")}`);
          });

        cmd
          .command("audit")
          .description("Show recent governance decisions")
          .option("--limit <n>", "Number of decisions", "20")
          .action(async (opts: { limit: string }) => {
            const limit = Number.parseInt(opts.limit, 10);
            const decisions = await shim.auditList(Number.isNaN(limit) ? 20 : limit);
            for (const entry of decisions) {
              const decision = String(entry.decision ?? "UNKNOWN");
              const icon = decision === "ALLOW" ? "[OK]" : decision === "DENY" ? "[X]" : "[!]";
              console.log(`${icon} ${String(entry.timestamp ?? "")}\t${decision}\t${String(entry.tool ?? "")}\t${String(entry.reason ?? "")}`);
            }
          });

        cmd
          .command("simulate")
          .description("Test a policy decision without executing")
          .requiredOption("--tool <name>", "Tool name")
          .option("--command <cmd>", "Command string (for exec)")
          .option("--path <path>", "Path (for read/write)")
          .option("--url <url>", "URL (for web tools)")
          .action(async (opts: Record<string, unknown>) => {
            const result = await shim.simulate(opts);
            console.log(`Decision: ${result.decision}`);
            console.log(`Reason: ${result.reason}`);
            if (result.constraints) {
              console.log(`Constraints: ${JSON.stringify(result.constraints)}`);
            }
          });
      },
      { commands: ["cordclaw"] }
    );

    api.logger.info("[CordClaw] Governance plugin registered");
  }
};
