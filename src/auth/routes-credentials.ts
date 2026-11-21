import type { FastifyInstance } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import { envelopeSchema } from "../plugins/envelope.js";
import type { OidcClient } from "./oidc-client.js";
import { tokenSetSchema } from "./schemas.js";

/** `credentials` mode: the FE's login form posts here; the password goes to the central service only. */
export function registerCredentialsRoutes(app: FastifyInstance, oidc: OidcClient): void {
  app.withTypeProvider<ZodTypeProvider>().post(
    "/v1/auth/login",
    {
      config: { public: true },
      schema: {
        body: z.object({
          username: z.string().trim().min(1),
          password: z.string().min(1),
          /** Optional: the org to sign in to (multi-org providers). */
          org_id: z.string().min(1).optional(),
        }),
        response: { 200: envelopeSchema(tokenSetSchema) },
      },
    },
    async (request, reply) => {
      const { username, password, org_id } = request.body;
      reply.ok(await oidc.passwordGrant(username, password, org_id));
    }
  );
}
