import Fastify from "fastify";
import { auth } from "../auth/plugin.js";
import { MESSAGES } from "../messages.js";
import { envelope } from "../plugins/envelope.js";
import { errorHandler } from "../plugins/error-handler.js";
import { health } from "../plugins/health.js";
import { createServerOptions } from "../server-options.js";

async function buildApp(opts: Parameters<typeof health>[1] = {}, withAuth = false) {
  const app = Fastify(createServerOptions({ logLevel: "silent" }));
  await app.register(envelope);
  await app.register(errorHandler);
  if (withAuth) {
    await app.register(auth, {
      mode: "credentials",
      issuer: "http://127.0.0.1:1",
      clientId: "app-a",
      clientSecret: "s",
    });
  }
  await app.register(health, opts);
  return app;
}

describe("health", () => {
  it("GET /health answers ok", async () => {
    const res = await (await buildApp()).inject({ url: "/health" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ success: true, data: { status: "ok" } });
  });

  it("GET /ready runs every check", async () => {
    const res = await (
      await buildApp({ checks: { db: async () => "pong", cache: async () => undefined } })
    ).inject({ url: "/ready" });
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toEqual({ checks: { db: "ok", cache: "ok" } });
  });

  it("GET /ready with no checks is ready", async () => {
    const res = await (await buildApp()).inject({ url: "/ready" });
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toEqual({ checks: {} });
  });

  it("GET /ready is 503 naming the failing check", async () => {
    const res = await (
      await buildApp({
        checks: { db: async () => Promise.reject(new Error("down")), cache: async () => 1 },
      })
    ).inject({ url: "/ready" });
    expect(res.statusCode).toBe(503);
    expect(res.json()).toMatchObject({
      success: false,
      code: 503,
      message: MESSAGES.notReady,
      data: { checks: { db: "fail", cache: "ok" } },
    });
  });

  it("GET /ready treats a hanging check as failed after timeoutMs", async () => {
    const started = Date.now();
    const res = await (
      await buildApp({ timeoutMs: 50, checks: { db: () => new Promise(() => {}) } })
    ).inject({ url: "/ready" });
    expect(res.statusCode).toBe(503);
    expect(res.json().data).toEqual({ checks: { db: "fail" } });
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it("both routes are public when the auth plugin guards everything else", async () => {
    const app = await buildApp({}, true);
    expect((await app.inject({ url: "/health" })).statusCode).toBe(200);
    expect((await app.inject({ url: "/ready" })).statusCode).toBe(200);
  });
});
