import { randomUUID } from "node:crypto";
import type { FastifyServerOptions } from "fastify";

/** Paths pino must never print: tokens, cookies, passwords and client secrets. */
export const REDACT_PATHS = [
  "req.headers.authorization",
  "req.headers.cookie",
  "*.password",
  "*.refresh_token",
  "*.access_token",
  "*.client_secret",
  "*.code_verifier",
];

/**
 * Fastify constructor options every Monexa backend starts from: `x-request-id`
 * honoured or generated, and a pino logger that redacts secrets.
 */
export function createServerOptions(opts: { logLevel?: string } = {}): FastifyServerOptions {
  return {
    requestIdHeader: "x-request-id",
    genReqId: () => randomUUID(),
    logger: { level: opts.logLevel ?? "info", redact: REDACT_PATHS },
  };
}
