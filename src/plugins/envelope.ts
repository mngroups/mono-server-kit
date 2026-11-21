import { apiEnvelope } from "@mono/auth";
import type { FastifyReply } from "fastify";
import fp from "fastify-plugin";

declare module "fastify" {
  interface FastifyReply {
    /** Sends `{ success: true, message, code, data, request_id, timestamp }`. */
    ok<T>(data: T, opts?: { message?: string; code?: number }): FastifyReply;
    /** Sends `{ success: false, message, code, data: null, request_id, timestamp }`. */
    fail(code: number, message: string): FastifyReply;
  }
}

/** Envelope response schema for routes; the same shape `@mono/auth` validates on the FE. */
export const envelopeSchema = apiEnvelope;

// #region handbook:envelope
function send(
  reply: FastifyReply,
  success: boolean,
  code: number,
  message: string,
  data: unknown
): FastifyReply {
  return reply.code(code).send({
    success,
    message,
    code,
    data,
    request_id: reply.request.id,
    timestamp: new Date().toISOString(),
  });
}
// #endregion

export const envelope = fp(
  async (app) => {
    app.decorateReply("ok", function <
      T,
    >(this: FastifyReply, data: T, opts: { message?: string; code?: number } = {}) {
      return send(this, true, opts.code ?? 200, opts.message ?? "OK", data);
    });
    app.decorateReply("fail", function (this: FastifyReply, code: number, message: string) {
      return send(this, false, code, message, null);
    });
  },
  { name: "@mono/envelope", fastify: "5.x" }
);
