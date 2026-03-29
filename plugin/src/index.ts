import { CordClawShim } from "./shim.js";
import { enforce } from "./enforcer.js";
import type { CheckRequest, CordClawConfig } from "./types.js";

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

export default {
  id: "cordclaw",
  name: "CordClaw - Cordum Governance",

  register(api: any): void {
    const config = parseConfig(api);
    const bypassTools = new Set(config.bypassTools);
    const shim = new CordClawShim(config.daemonUrl, config.timeoutMs, config.failMode);

    api.registerHook({
      event: "before_tool_execution",
      priority: 1000,
      handler: async (ctx: CheckRequest & Record<string, unknown>) => {
        if (bypassTools.has(ctx.tool)) {
          return ctx;
        }

        const response = await shim.check(ctx);
        if (config.logDecisions) {
          api.logger.info(`[CordClaw] ${response.decision} ${ctx.tool}: ${response.reason}`);
        }

        return enforce(response, ctx, api.logger);
      }
    });

    api.registerHook({
      event: "after_tool_execution",
      priority: 1000,
      handler: async (ctx: Record<string, unknown>) => {
        const tool = String(ctx.tool ?? "");
        if (bypassTools.has(tool)) {
          return;
        }
        await shim.audit(ctx).catch(() => undefined);
      }
    });

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
              console.log(`${icon} ${String(entry.timestamp ?? "")}	${decision}	${String(entry.tool ?? "")}	${String(entry.reason ?? "")}`);
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