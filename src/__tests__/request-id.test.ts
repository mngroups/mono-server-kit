import Fastify from "fastify";
import { requestId } from "../plugins/request-id.js";
import { createServerOptions } from "../server-options.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

async function buildApp() {
  const app = Fastify(createServerOptions({ logLevel: "silent" }));
  await app.register(requestId);
  app.get("/x", () => ({ ok: true }));
  return app;
}

describe("requestId", () => {
  it("echoes an incoming x-request-id header", async () => {
    const res = await (await buildApp()).inject({
      url: "/x",
      headers: { "x-request-id": "rid-1" },
    });
    expect(res.headers["x-request-id"]).toBe("rid-1");
  });

  it("generates a uuid when none is sent", async () => {
    const res = await (await buildApp()).inject({ url: "/x" });
    expect(res.headers["x-request-id"]).toMatch(UUID_RE);
  });
});

describe("createServerOptions", () => {
  it("redacts secrets and defaults the log level to info", () => {
    const opts = createServerOptions();
    const logger = opts.logger as { level: string; redact: string[] };
    expect(logger.level).toBe("info");
    expect(logger.redact).toEqual(
      expect.arrayContaining([
        "req.headers.authorization",
        "req.headers.cookie",
        "*.password",
        "*.refresh_token",
        "*.access_token",
        "*.client_secret",
        "*.code_verifier",
      ])
    );
  });
});
