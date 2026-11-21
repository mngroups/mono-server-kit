import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";
import { envelopeSchema } from "../plugins/envelope.js";
import type { AuthOptions } from "./config.js";
import type { OidcClient } from "./oidc-client.js";
import { createPkce } from "./pkce.js";
import { tokenSetSchema } from "./schemas.js";

/**
 * `sso` mode: the FE asks for an authorize URL (holding `state` + `code_verifier`
 * in a short-lived HttpOnly cookie), sends the user to the central login, then
 * posts the returned code here. The client secret never leaves this backend.
 */
export function registerSsoRoutes(app: FastifyInstance, oidc: OidcClient, opts: AuthOptions) {
  const allowed = new Set(opts.redirectUris);
  const redirectUri = z
    .string()
    .refine((uri) => allowed.has(uri), { message: "redirect_uri tidak diizinkan" });
  const r = app.withTypeProvider<ZodTypeProvider>();

  r.get(
    "/v1/auth/authorize-url",
    {
      config: { public: true },
      schema: {
        querystring: z.object({ redirect_uri: redirectUri }),
        response: {
          200: envelopeSchema(
            z.object({ url: z.string(), state: z.string(), code_verifier: z.string() })
          ),
        },
      },
    },
    async (request, reply) => {
      const { verifier, challenge } = createPkce();
      const state = randomBytes(24).toString("base64url");
      const url = await oidc.authorizeUrl({
        redirectUri: request.query.redirect_uri,
        codeChallenge: challenge,
        state,
        idpHint: opts.idpHint,
        idpHintParam: opts.idpHintParam,
      });
      reply.ok({ url, state, code_verifier: verifier });
    }
  );

  r.post(
    "/v1/auth/callback",
    {
      config: { public: true },
      schema: {
        body: z.object({
          code: z.string().min(1),
          code_verifier: z.string().min(43).max(128),
          redirect_uri: redirectUri,
        }),
        response: { 200: envelopeSchema(tokenSetSchema) },
      },
    },
    async (request, reply) => {
      const { code, code_verifier, redirect_uri } = request.body;
      reply.ok(await oidc.codeGrant(code, code_verifier, redirect_uri));
    }
  );
}
