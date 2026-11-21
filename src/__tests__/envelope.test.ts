import { apiResponseSchema } from "@mono/auth";
import Fastify from "fastify";
import { z } from "zod";
import { envelope, envelopeSchema } from "../plugins/envelope.js";
import { requestId } from "../plugins/request-id.js";
import { createServerOptions } from "../server-options.js";

async function buildApp() {
  const app = Fastify(createServerOptions({ logLevel: "silent" }));
  await app.register(requestId);
  await app.register(envelope);
  return app;
}

describe("envelope", () => {
  it("reply.ok wraps data in the envelope", async () => {
    const app = await buildApp();
    app.get("/x", (_req, reply) => reply.ok({ a: 1 }, { code: 201, message: "Dibuat" }));
    const res = await app.inject({ url: "/x", headers: { "x-request-id": "rid-1" } });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toEqual({
      success: true,
      message: "Dibuat",
      code: 201,
      data: { a: 1 },
      request_id: "rid-1",
      timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
    });
    expect(apiResponseSchema.safeParse(res.json()).success).toBe(true);
  });

  it("reply.ok defaults to 200 and message OK", async () => {
    const app = await buildApp();
    app.get("/x", (_req, reply) => reply.ok([1]));
    const res = await app.inject({ url: "/x" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ success: true, message: "OK", code: 200, data: [1] });
  });

  it("reply.fail sets success false and data null", async () => {
    const app = await buildApp();
    app.get("/x", (_req, reply) => reply.fail(409, "Duplikat"));
    const res = await app.inject({ url: "/x" });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({
      success: false,
      code: 409,
      message: "Duplikat",
      data: null,
    });
  });

  it("envelopeSchema validates an envelope with typed data", () => {
    const schema = envelopeSchema(z.object({ id: z.string() }));
    const ok = { success: true, message: "OK", code: 200, data: { id: "1" } };
    expect(schema.safeParse(ok).success).toBe(true);
    expect(schema.safeParse({ ...ok, data: { id: 1 } }).success).toBe(false);
  });
});
