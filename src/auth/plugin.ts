import { isGranted } from "@mono/auth";
import type { preHandlerAsyncHookHandler } from "fastify";
import fp from "fastify-plugin";
import { serializerCompiler, validatorCompiler } from "fastify-type-provider-zod";
import { AppError } from "../errors.js";
import { MESSAGES } from "../messages.js";
import { type AuthOptions, validateAuthOptions } from "./config.js";
import { createOidcClient } from "./oidc-client.js";
import { registerCommonRoutes } from "./routes-common.js";
import { registerCredentialsRoutes } from "./routes-credentials.js";
import { registerSsoRoutes } from "./routes-sso.js";
import type { AuthUser } from "./types.js";
import { createVerifier } from "./verifier.js";

declare module "fastify" {
  interface FastifyRequest {
    /** The verified caller; `null` on public routes. */
    user: AuthUser | null;
  }
  interface FastifyInstance {
    /** preHandler: passes when the caller holds any of `permissions` (`x:all` covers `x.*`). */
    requirePermission(...permissions: string[]): preHandlerAsyncHookHandler;
  }
  interface FastifyContextConfig {
    /** Skip authentication for this route. */
    public?: boolean;
  }
}

/**
 * Central-auth plugin. Every route requires a valid Bearer token unless its
 * config sets `public: true`. Registers the `/v1/auth/*` routes for `mode`.
 */
export const auth = fp<AuthOptions>(
  async (app, opts) => {
    validateAuthOptions(opts);
    const oidc = createOidcClient({
      issuer: opts.issuer,
      clientId: opts.clientId,
      clientSecret: opts.clientSecret,
      timeoutMs: opts.timeoutMs,
      orgsEndpoint: opts.orgsEndpoint,
    });

    // Resolved on first use, so boot never depends on the central service being up.
    let verifier: Promise<ReturnType<typeof createVerifier>> | null = null;
    const getVerifier = () => {
      verifier ??= (async () =>
        createVerifier({
          jwksUri: opts.jwksUri ?? (await oidc.discovery()).jwks_uri,
          issuer: opts.issuer,
          audience: opts.clientId,
          jwksCooldownMs: opts.jwksCooldownMs,
        }))().catch((error: unknown) => {
        verifier = null;
        throw error;
      });
      return verifier;
    };

    app.decorateRequest("user", null);

    app.addHook("onRequest", async (request) => {
      if (request.is404 || request.routeOptions.config.public) return;
      const token = request.headers.authorization?.match(/^Bearer\s+(\S+)$/i)?.[1];
      if (!token) throw new AppError(401, MESSAGES.invalidToken);
      request.user = await (await getVerifier())(token);
    });

    // #region handbook:rbac-check
    app.decorate("requirePermission", (...permissions: string[]): preHandlerAsyncHookHandler => {
      return async (request) => {
        if (!request.user) throw new AppError(401, MESSAGES.invalidToken);
        const granted = request.user.permissions;
        if (!permissions.some((p) => isGranted(granted, p))) {
          throw new AppError(403, MESSAGES.forbidden);
        }
      };
    });
    // #endregion

    await app.register(async (scope) => {
      scope.setValidatorCompiler(validatorCompiler);
      scope.setSerializerCompiler(serializerCompiler);
      // @mono/auth's apiClient sends `Content-Type: application/json` even on body-less
      // POSTs (logout); Fastify's default parser rejects those with a 400.
      scope.removeContentTypeParser("application/json");
      scope.addContentTypeParser(
        "application/json",
        { parseAs: "string" },
        (_request, body, done) => {
          if (body === "") return done(null, undefined);
          try {
            done(null, JSON.parse(body as string));
          } catch {
            done(new AppError(400, MESSAGES.validation), undefined);
          }
        }
      );
      registerCommonRoutes(scope, oidc, opts);
      if (opts.mode === "credentials") registerCredentialsRoutes(scope, oidc);
      else registerSsoRoutes(scope, oidc, opts);
    });
  },
  {
    name: "@mono/auth",
    fastify: "5.x",
    dependencies: ["@mono/envelope", "@mono/error-handler"],
  }
);
