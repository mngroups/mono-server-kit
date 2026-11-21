import Fastify from "fastify";
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from "fastify-type-provider-zod";
import { z } from "zod";
import { AppError } from "../errors.js";
import { MESSAGES } from "../messages.js";
import { envelope, envelopeSchema } from "../plugins/envelope.js";
import { errorHandler } from "../plugins/error-handler.js";
import { createServerOptions } from "../server-options.js";

async function buildApp() {
  const app = Fastify(createServerOptions({ logLevel: "silent" }));
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(envelope);
  await app.register(errorHandler);
  return app.withTypeProvider<ZodTypeProvider>();
}

describe("errorHandler", () => {
  it("maps zod request validation to 422 with field issues in data", async () => {
    const app = await buildApp();
    app.post("/x", { schema: { body: z.object({ name: z.string().min(1) }) } }, (_req, reply) =>
      reply.ok(null)
    );
    const res = await app.inject({ method: "POST", url: "/x", payload: {} });
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({
      success: false,
      code: 422,
      message: MESSAGES.validation,
      data: { issues: [expect.objectContaining({ path: ["name"], in: "body" })] },
    });
  });

  it("maps AppError to its own code and message", async () => {
    const app = await buildApp();
    app.get("/x", () => {
      throw new AppError(409, "Duplikat");
    });
    const res = await app.inject({ url: "/x" });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({
      success: false,
      code: 409,
      message: "Duplikat",
      data: null,
    });
  });

  it("logs the cause of a 5xx AppError and still sends its message", async () => {
    const app = await buildApp();
    const cause = new Error("ECONNREFUSED");
    app.get("/x", () => {
      throw new AppError(503, MESSAGES.authUnavailable, { cause });
    });
    app.get("/y", () => {
      throw new AppError(502, "Gateway");
    });
    const logged: unknown[] = [];
    app.addHook("onRequest", async (req) => {
      req.log.error = ((obj: unknown) => {
        logged.push(obj);
      }) as typeof req.log.error;
    });
    const res = await app.inject({ url: "/x" });
    expect(res.statusCode).toBe(503);
    expect(res.json().message).toBe(MESSAGES.authUnavailable);
    await app.inject({ url: "/y" });
    expect(logged).toEqual([{ err: cause }, { err: expect.any(AppError) }]);
  });

  it("maps unknown errors to 500 with the generic message and logs the error", async () => {
    const app = await buildApp();
    app.get("/x", () => {
      throw new Error("db password leaked in message");
    });
    let logged: unknown;
    app.addHook("onRequest", async (req) => {
      req.log.error = ((obj: unknown) => {
        logged = obj;
      }) as typeof req.log.error;
    });
    const res = await app.inject({ url: "/x" });
    expect(res.statusCode).toBe(500);
    expect(res.json().message).toBe(MESSAGES.internal);
    expect(JSON.stringify(res.json())).not.toContain("password");
    expect(logged).toMatchObject({ err: expect.any(Error) });
  });

  it("maps a response serialization mismatch to 500", async () => {
    const app = await buildApp();
    app.get(
      "/x",
      { schema: { response: { 200: envelopeSchema(z.object({ id: z.string() })) } } },
      (_req, reply) => {
        reply.ok({ id: 1 as unknown as string });
      }
    );
    const res = await app.inject({ url: "/x" });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toMatchObject({ success: false, message: MESSAGES.internal });
  });

  it("maps Fastify's own 4xx errors (invalid JSON body) to their status", async () => {
    const app = await buildApp();
    app.post("/x", (_req, reply) => reply.ok(null));
    const res = await app.inject({
      method: "POST",
      url: "/x",
      headers: { "content-type": "application/json" },
      payload: "{bad",
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ success: false, code: 400, message: MESSAGES.validation });
  });

  it("never sends Fastify's English messages: empty JSON body, bad media type, oversized body", async () => {
    const app = Fastify({ ...createServerOptions({ logLevel: "silent" }), bodyLimit: 10 });
    await app.register(envelope);
    await app.register(errorHandler);
    app.post("/x", (_req, reply) => reply.ok(null));
    app.get("/teapot", () => {
      throw Object.assign(new Error("I'm a teapot"), { statusCode: 418 });
    });
    const empty = await app.inject({
      method: "POST",
      url: "/x",
      headers: { "content-type": "application/json" },
    });
    expect(empty.json()).toMatchObject({ code: 400, message: MESSAGES.validation });
    const media = await app.inject({
      method: "POST",
      url: "/x",
      headers: { "content-type": "application/xml" },
      payload: "<a/>",
    });
    expect(media.json()).toMatchObject({ code: 415, message: MESSAGES.validation });
    const big = await app.inject({ method: "POST", url: "/x", payload: { long: "x".repeat(50) } });
    expect(big.json()).toMatchObject({ code: 413, message: MESSAGES.payloadTooLarge });
    const other = await app.inject({ url: "/teapot" });
    expect(other.json()).toMatchObject({ code: 418, message: MESSAGES.badRequest });
  });

  it("returns an envelope 404 for unknown routes", async () => {
    const res = await (await buildApp()).inject({ url: "/nope" });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({ success: false, code: 404, message: MESSAGES.notFound });
  });
});

describe("AppError", () => {
  it("keeps code, message and cause", () => {
    const cause = new Error("root");
    const err = new AppError(503, "x", { cause });
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe(503);
    expect(err.message).toBe("x");
    expect(err.cause).toBe(cause);
    expect(err.name).toBe("AppError");
  });
});
