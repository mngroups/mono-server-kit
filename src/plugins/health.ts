import fp from "fastify-plugin";
import { MESSAGES } from "../messages.js";

export type HealthOptions = {
  /** Readiness checks by name, e.g. `{ db: () => pool.query("select 1") }`. */
  checks?: Record<string, () => Promise<unknown>>;
  /** Per check. Default 2000ms. */
  timeoutMs?: number;
};

async function run(check: () => Promise<unknown>, timeoutMs: number): Promise<"ok" | "fail"> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
  });
  try {
    await Promise.race([check(), timeout]);
    return "ok";
  } catch {
    return "fail";
  } finally {
    clearTimeout(timer);
  }
}

/** `GET /health` (liveness) and `GET /ready` (runs the checks). Both are public. */
export const health = fp<HealthOptions>(
  async (app, opts) => {
    const checks = Object.entries(opts.checks ?? {});
    const timeoutMs = opts.timeoutMs ?? 2000;

    app.get("/health", { config: { public: true } }, (_request, reply) => {
      reply.ok({ status: "ok" });
    });

    app.get("/ready", { config: { public: true } }, async (_request, reply) => {
      const results = await Promise.all(
        checks.map(async ([name, check]) => [name, await run(check, timeoutMs)] as const)
      );
      const data = { checks: Object.fromEntries(results) };
      if (results.every(([, status]) => status === "ok")) return reply.ok(data);
      return reply.code(503).send({
        success: false,
        message: MESSAGES.notReady,
        code: 503,
        data,
        request_id: reply.request.id,
        timestamp: new Date().toISOString(),
      });
    });
  },
  { name: "@mono/health", fastify: "5.x", dependencies: ["@mono/envelope"] }
);
