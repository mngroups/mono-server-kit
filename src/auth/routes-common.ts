import type { FastifyInstance } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import { envelopeSchema } from "../plugins/envelope.js";
import type { OidcClient } from "./oidc-client.js";
import { tokenSetSchema } from "./schemas.js";

/** refresh, logout and check: the same in both modes. */
export function registerCommonRoutes(app: FastifyInstance, oidc: OidcClient): void {
  const r = app.withTypeProvider<ZodTypeProvider>();

  r.post(
    "/v1/auth/refresh",
    {
      config: { public: true },
      schema: {
        body: z.object({ refresh_token: z.string().min(1) }),
        response: { 200: envelopeSchema(tokenSetSchema) },
      },
    },
    async (request, reply) => {
      reply.ok(await oidc.refreshGrant(request.body.refresh_token));
    }
  );

  r.post(
    "/v1/auth/logout",
    {
      config: { public: true },
      schema: { body: z.object({ refresh_token: z.string().optional() }).nullish() },
    },
    async (request, reply) => {
      const refreshToken = request.body?.refresh_token;
      if (refreshToken) await oidc.revoke(refreshToken);
      reply.ok(null);
    }
  );

  r.get(
    "/v1/auth/check",
    {
      schema: {
        response: {
          200: envelopeSchema(z.object({ user_id: z.string(), permissions: z.array(z.string()) })),
        },
      },
    },
    async (request, reply) => {
      const user = request.user as NonNullable<typeof request.user>;
      reply.ok({ user_id: user.id, permissions: [...user.permissions] });
    }
  );
}
