import fp from "fastify-plugin";

/** Echoes the request id (incoming `x-request-id` or a generated uuid) on every response. */
export const requestId = fp(
  async (app) => {
    app.addHook("onSend", async (request, reply) => {
      reply.header("x-request-id", request.id);
    });
  },
  { name: "@mono/request-id", fastify: "5.x" }
);
