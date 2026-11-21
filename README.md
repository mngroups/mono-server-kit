# `@mono/server-kit`

Shared Fastify plugins for Monexa backends. The kit holds the **mechanism**: the response envelope, error mapping, request id, central OIDC auth in two modes, RBAC, presigned uploads, health checks and graceful shutdown. Each app supplies its **config**, the same split `@mono/auth` uses on the frontend. Responses match what `@mono/auth` validates, and the contract schemas (`apiEnvelope`, `isGranted`, `presignResponseSchema`) are imported from it rather than copied.

## Install

Private in GitLab Package Registry. Copy `.npmrc.example` to `.npmrc` and set `GITLAB_PACKAGE_GROUP_ID` and a `GITLAB_NPM_TOKEN` with `read_package_registry` access. Then:

```bash
pnpm add @mono/server-kit @mono/auth fastify fastify-type-provider-zod zod
```

Peers: `fastify ^5.5`, `fastify-type-provider-zod ^7` (one copy shared with your app's compilers), `zod ^4.1.5`, `@mono/auth ^0.2`.

## Entry points

| Import                 | Contents                                                                                                                                                                                         |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `@mono/server-kit`     | `createServerOptions`, `requestId`, `envelope`, `envelopeSchema`, `errorHandler`, `AppError`, `MESSAGES`, `defineEnv`, `auth`, `validateAuthOptions`, `createPresigner`, `health`, `startServer` |
| `@mono/server-kit/dev` | `createDevIssuer`: a stub OIDC provider for local dev and tests. It throws when `NODE_ENV=production`                                                                                            |

## Options

| Plugin / helper       | Option                       | Default                       | Notes                                                                        |
| --------------------- | ---------------------------- | ----------------------------- | ---------------------------------------------------------------------------- |
| `createServerOptions` | `logLevel`                   | `"info"`                      | Logger always redacts `REDACT_PATHS`                                         |
| `auth`                | `mode`                       | required                      | `"credentials"` or `"sso"`                                                   |
|                       | `issuer`                     | required                      | Absolute URL; discovery at `/.well-known/openid-configuration`               |
|                       | `clientId`, `clientSecret`   | required                      | Confidential client, `client_secret_basic`                                   |
|                       | `jwksUri`                    | discovery `jwks_uri`          | Resolved lazily on the first guarded request                                 |
|                       | `redirectUris`               | –                             | sso only, required; allowlist for `redirect_uri`                             |
|                       | `idpHint`                    | –                             | sso only; e.g. `"google"`                                                    |
|                       | `idpHintParam`               | `"kc_idp_hint"`               | Authorize-URL parameter carrying `idpHint`                                   |
|                       | `postLogoutRedirectUri`      | –                             | sso only; added to `end_session_url`                                         |
|                       | `timeoutMs`                  | `10000`                       | Per call to the central service; timeout → 503                               |
|                       | `orgsEndpoint`               | `<issuer origin>/api/me/orgs` | Provider orgs endpoint for `GET /v1/auth/orgs`                               |
|                       | `jwksCooldownMs`             | `30000`                       | Min gap between JWKS refetches; an unknown `kid` inside it → 503 (retryable) |
| `health`              | `checks`                     | `{}`                          | `{ name: () => Promise<unknown> }`                                           |
|                       | `timeoutMs`                  | `2000`                        | Per check; a slower check counts as `"fail"`                                 |
| `createPresigner`     | `bucket`, `region`           | required                      |                                                                              |
|                       | `endpoint`, `forcePathStyle` | –                             | S3-compatible storage (MinIO)                                                |
|                       | `credentials`                | AWS SDK chain                 |                                                                              |
|                       | `expiresInSeconds`           | `300`                         |                                                                              |
|                       | `keyPrefix`                  | `"uploads"`                   | Keys are `<prefix>/<uuid>/<safe-name>`                                       |
| `startServer`         | `port`                       | required                      |                                                                              |
|                       | `host`                       | `"0.0.0.0"`                   |                                                                              |
|                       | `graceMs`                    | `10000`                       | Max time to finish in-flight requests on SIGTERM                             |

## Usage

Register the plugins in this order:

```ts
import Fastify from "fastify";
import { serializerCompiler, validatorCompiler } from "fastify-type-provider-zod";
import {
  auth,
  createServerOptions,
  envelope,
  errorHandler,
  health,
  requestId,
} from "@mono/server-kit";

export async function buildApp() {
  const app = Fastify(createServerOptions({ logLevel: env.LOG_LEVEL }));
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(requestId);
  await app.register(envelope);
  await app.register(errorHandler);
  await app.register(auth, {
    mode: env.AUTH_MODE, // "credentials" | "sso"
    issuer: env.AUTH_ISSUER,
    clientId: env.AUTH_CLIENT_ID,
    clientSecret: env.AUTH_CLIENT_SECRET,
    redirectUris: env.AUTH_REDIRECT_URIS, // sso only
    idpHint: env.AUTH_IDP_HINT, // sso only, e.g. "google"
  });
  await app.register(health, { checks: { db: () => pool.query("select 1") } });
  // …feature routes
  return app;
}
```

### Routes and the envelope

- Reply with `reply.ok(data, { code?, message? })` or `reply.fail(code, message)`. Every response is `{ success, message, code, data, request_id, timestamp }`.
- Use `envelopeSchema(zodSchema)` as the route's response schema. Fastify then serializes it fast and rejects shape drift.
- In a route that has a Zod response schema, **call** `reply.ok(...)` and don't `return` it. The type provider types the handler's return value as the response body, so `return reply.ok(...)` is a TypeScript error. Routes without a response schema may return it.
- Throw `new AppError(409, "…")` for expected failures. Its message reaches the client as-is, so write it in Indonesian.

### Error mapping

| Cause                                                               | Status | Message                    |
| ------------------------------------------------------------------- | ------ | -------------------------- |
| Zod validation (`data.issues: [{ path, message, in }]`)             | 422    | `MESSAGES.validation`      |
| Missing, invalid or expired token                                   | 401    | `MESSAGES.invalidToken`    |
| Missing permission                                                  | 403    | `MESSAGES.forbidden`       |
| Unknown route                                                       | 404    | `MESSAGES.notFound`        |
| Central service down: network error, timeout, 5xx, unreachable JWKS | 503    | `MESSAGES.authUnavailable` |
| Anything else (details go to the log only)                          | 500    | `MESSAGES.internal`        |

The FE treats 401 as "refresh, then log out" and never logs a user out on a 5xx. That is why an outage is always reported as 503, never 401.

### Auth

**Secure by default.** Once `auth` is registered, every route requires `Authorization: Bearer <token>` unless it sets `config: { public: true }`. Tokens are verified locally against the issuer's JWKS, which is cached, refetched when an unknown `kid` appears, and checked with 30 s of clock tolerance. There is no network call per request. A token whose `azp` is another client is rejected even when `aud` also lists this app, because its `permissions` belong to that client.

- `request.user`: `{ id, permissions: ReadonlySet<string>, claims, orgId?, orgName? }`, taken from `sub`, the `permissions` claim and the string claims `org_id` / `org_name`. If the permissions claim is missing, the user has no permissions. `orgId` / `orgName` are `undefined` when the claim is missing or not a string.
- `app.requirePermission("example.item:view", …)` is a preHandler with OR semantics. A granted `example:all` covers every `example.*` permission.

Routes registered by mode:

| Route                        | `credentials`                                              | `sso`                                                                   |
| ---------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------------- |
| `POST /v1/auth/login`        | `{ username, password, org_id? }` → tokens                 | 404                                                                     |
| `GET /v1/auth/authorize-url` | 404                                                        | `?redirect_uri` (must be allowlisted) → `{ url, state, code_verifier }` |
| `POST /v1/auth/callback`     | 404                                                        | `{ code, code_verifier, redirect_uri }` → tokens                        |
| `POST /v1/auth/refresh`      | `{ refresh_token }` → tokens                               | same                                                                    |
| `POST /v1/auth/logout`       | optional `{ refresh_token }`, revoked best effort → `null` | same → `{ end_session_url }`                                            |
| `GET /v1/auth/check`         | `{ user_id, permissions }` from the token                  | same                                                                    |
| `POST /v1/auth/switch-org`   | `{ refresh_token, org_id }` → tokens for that org (public) | same                                                                    |
| `GET /v1/auth/orgs`          | the caller's orgs `[{ id, name }]` (guarded)               | same                                                                    |

Tokens are returned as `{ access_token, refresh_token, expires_in, refresh_expires_in }`.

**Multi-org (monexa-auth).** A token is for one active org.
- `request.user.orgId` / `orgName` come from the `org_id` / `org_name` claims.
- `org_id` on login picks the org; without it the provider uses the last-used or first eligible org.
- `switch-org` uses monexa-auth's grant `urn:monexa:params:oauth:grant-type:org-switch` and spends the old refresh token.
- `orgs` proxies `GET <issuer origin>/api/me/orgs` with the caller's token. Override it with the `orgsEndpoint` option.
- Provider outages answer 503; a rejected token answers 401.

**Refusal reasons.** When the provider refuses a grant with `invalid_grant` and a known `error_description`, the 401 envelope carries an Indonesian message and `data: { reason }`, so the FE can react (e.g. link to the account page on `password_change_required`):

| `data.reason`              | Message                           |
| -------------------------- | --------------------------------- |
| `invalid_credentials`      | `MESSAGES.invalidCredentials`     |
| `no_app_access`            | `MESSAGES.noAppAccess`            |
| `password_change_required` | `MESSAGES.passwordChangeRequired` |
| `org_not_eligible`         | `MESSAGES.orgNotEligible`         |
| `google_required`          | `MESSAGES.googleRequired`         |

Any other description keeps the generic message with `data: null`.

The central service must speak standard OIDC: discovery, the `password` grant (credentials mode), `authorization_code` + PKCE S256 (sso mode), `refresh_token`, RFC 7009 revocation and `end_session_endpoint`. The backend authenticates as a confidential client with `client_secret_basic`.

`validateAuthOptions` rejects a config that cannot work, at boot:
- `idpHint` without `sso`;
- `sso` without `redirectUris`;
- a relative issuer;
- an empty secret.

### Uploads

```ts
const presigner = createPresigner({ bucket, region, endpoint, forcePathStyle, credentials });
const target = await presigner.presign({ filename, contentType, size, maxBytes, allowedTypes });
// → { upload_uuid, s3_key: "uploads/<uuid>/<safe-name>", presign_url, fields }
```

The signed policy pins the content type and the size range. A file that is too big or of a type not in `allowedTypes` gets a 422.

Downloads and existence checks:

```ts
const dl = await presigner.presignDownload({ key, filename, expiresInSeconds });
// → { url, expires_in }   (expiry defaults to the presigner's, 300 s)
const head = await presigner.stat(key);
// → { size, contentType }, or null when the object does not exist
```

`presignDownload` signs a GET with `Content-Disposition: attachment; filename="<filename>"`. Quotes, backslashes and control characters are stripped from the filename. `stat` rethrows any error other than not-found.

### Health and shutdown

- `health` serves `GET /health` and `GET /ready`. `/ready` answers 503 and names the failing checks. Both routes are public.
- `startServer(app, { port })` is for the Docker entry only. It listens, then closes gracefully on SIGTERM/SIGINT.

### Local dev and tests

```ts
import { createDevIssuer } from "@mono/server-kit/dev";

const issuer = await createDevIssuer({
  issuer: "http://localhost:9000",
  users: [
    {
      username: "admin",
      password: "admin123",
      sub: "u1",
      permissions: { "my-app": ["example:all"] },
      // optional: orgs (first = default; per-org permissions override the user-level ones)
      orgs: [
        { id: "org-1", name: "PT A" },
        { id: "org-2", name: "PT B", permissions: { "my-app": ["example.item:view"] } },
      ],
      // mustChangePassword: true, // refuses login with password_change_required
    },
  ],
  clients: [
    {
      clientId: "my-app",
      clientSecret: "dev-secret",
      redirectUris: ["http://localhost:3000/auth/callback"],
    },
  ],
});
await issuer.listen({ port: 9000 });
```

It supports both modes end to end:
- the authorize step auto-approves (pass `login_hint=<username>` to pick a user);
- refresh tokens rotate;
- `signTestToken(claims)` mints tokens for tests;
- `rotateKey()` exercises key rotation;
- multi-org like monexa-auth: `org_id` on the password grant, the org-switch grant, `GET /api/me/orgs`, and the refusal reasons (`org_not_eligible`, `no_app_access`, `password_change_required`). The single `org` field from 0.2 still works.

## Development

`pnpm lint && pnpm typecheck && pnpm test:coverage && pnpm build`. Coverage of at least 80% is enforced; behavior that matters (auth, error mapping) must have a test.

Release with `pnpm release`, which tags `v<version>`. The Publish workflow then sends the tag to this project's GitLab Package Registry. It needs the GitHub Actions secret `GITLAB_NPM_TOKEN` and the variables `GITLAB_PACKAGE_GROUP_ID` and `GITLAB_PACKAGE_PROJECT_ID`.
