import type { FastifyError } from "fastify";
import fp from "fastify-plugin";
import {
  hasZodFastifySchemaValidationErrors,
  isResponseSerializationError,
} from "fastify-type-provider-zod";
import { AppError } from "../errors.js";
import { MESSAGES } from "../messages.js";

function clientMessage(status: number): string {
  if (status === 400 || status === 415) return MESSAGES.validation;
  if (status === 413) return MESSAGES.payloadTooLarge;
  return MESSAGES.badRequest;
}

// #region handbook:error-mapping
/**
 * Maps every thrown error onto the envelope: validation → 422 with issues,
 * `AppError` → its code, Fastify 4xx → that status, anything else → 500 with a
 * generic message (details only in logs).
 */
export const errorHandler = fp(
  async (app) => {
    app.setErrorHandler((error: FastifyError, request, reply) => {
      if (hasZodFastifySchemaValidationErrors(error)) {
        const issues = error.validation.map((v) => ({
          path: v.instancePath.split("/").filter(Boolean),
          message: v.message,
          in: error.validationContext,
        }));
        return reply.code(422).send({
          success: false,
          message: MESSAGES.validation,
          code: 422,
          data: { issues },
          request_id: request.id,
          timestamp: new Date().toISOString(),
        });
      }
      if (error instanceof AppError) {
        if (error.code >= 500) request.log.error({ err: error.cause ?? error });
        return reply.fail(error.code, error.message, error.data);
      }
      const status = error.statusCode ?? 500;
      if (!isResponseSerializationError(error) && status >= 400 && status < 500) {
        // Framework messages are English and technical; the FE shows `message` in toasts.
        request.log.info({ err: error }, "client error");
        return reply.fail(status, clientMessage(status));
      }
      request.log.error({ err: error });
      return reply.fail(500, MESSAGES.internal);
    });

    app.setNotFoundHandler((_request, reply) => reply.fail(404, MESSAGES.notFound));
  },
  { name: "@mono/error-handler", fastify: "5.x", dependencies: ["@mono/envelope"] }
);
// #endregion
