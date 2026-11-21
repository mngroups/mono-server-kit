import { createHash, randomBytes, randomUUID, type webcrypto } from "node:crypto";
import formbody from "@fastify/formbody";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWK,
  type JWTPayload,
  jwtVerify,
  SignJWT,
} from "jose";

export type DevUser = {
  username: string;
  password: string;
  sub: string;
  /** Permissions per client id: what lands in that client's token `permissions` claim. */
  permissions: Record<string, string[]>;
  /** Single org (0.2): adds `org_id` / `org_name` claims. Same as `orgs: [org]`. */
  org?: { id: string; name: string };
  /**
   * Orgs the user belongs to; the first is the default. Per-org `permissions` (by
   * client id) override the user-level ones. An empty list refuses with `no_app_access`.
   */
  orgs?: DevOrg[];
  /** Refuses the password grant with `password_change_required` after the password checks out. */
  mustChangePassword?: boolean;
};

export type DevOrg = { id: string; name: string; permissions?: Record<string, string[]> };

/** Grant type of monexa-auth's org switch (params `refresh_token`, `org_id`). */
export const ORG_SWITCH_GRANT = "urn:monexa:params:oauth:grant-type:org-switch";

export type DevClient = { clientId: string; clientSecret: string; redirectUris: string[] };

export type DevIssuerOptions = {
  /** Defaults to the address `listen()` binds. */
  issuer?: string;
  users: DevUser[];
  clients: DevClient[];
  accessTokenTtlSeconds?: number;
  refreshTokenTtlSeconds?: number;
};

export type DevIssuer = {
  app: FastifyInstance;
  issuer(): string;
  listen(opts?: { port?: number; host?: string }): Promise<string>;
  rotateKey(): Promise<void>;
  signTestToken(claims: JWTPayload): Promise<string>;
};

type SigningKey = { kid: string; privateKey: webcrypto.CryptoKey; jwk: JWK };
type Session = { sub: string; clientId: string; sid: string; orgId?: string };
type PendingCode = Session & { redirectUri: string; challenge: string };
type TokenBody = Record<string, string | undefined>;

const opaque = () => randomBytes(32).toString("base64url");
const orgsOf = (user: DevUser): DevOrg[] | undefined =>
  user.orgs ?? (user.org ? [user.org] : undefined);
const now = () => Math.floor(Date.now() / 1000);

async function newKey(): Promise<SigningKey> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const kid = randomUUID();
  return {
    kid,
    privateKey,
    jwk: { ...(await exportJWK(publicKey)), kid, alg: "RS256", use: "sig" },
  };
}

/**
 * A minimal OIDC provider for local development and tests: discovery, JWKS,
 * password / authorization_code (PKCE, auto-approve) / refresh_token grants,
 * revocation and end_session. State lives in memory. Never use it in production.
 */
export async function createDevIssuer(opts: DevIssuerOptions): Promise<DevIssuer> {
  if (process.env.NODE_ENV === "production") {
    throw new Error("@mono/server-kit/dev must not run in production");
  }
  const accessTtl = opts.accessTokenTtlSeconds ?? 900;
  const refreshTtl = opts.refreshTokenTtlSeconds ?? 86400;
  let issuer = opts.issuer ?? "";
  const keys: SigningKey[] = [await newKey()];
  const current = () => keys[keys.length - 1] as SigningKey;
  const refreshTokens = new Map<string, Session>();
  const codes = new Map<string, PendingCode>();

  /** The `sub` of an access token this issuer signed, or undefined. */
  async function verifiedSub(token: string): Promise<string | undefined> {
    try {
      const jwks = createLocalJWKSet({ keys: keys.map((k) => k.jwk) });
      const { payload } = await jwtVerify(token, jwks, { issuer });
      return payload.sub;
    } catch {
      return undefined;
    }
  }

  const sign = (claims: JWTPayload) =>
    new SignJWT({ iss: issuer, iat: now(), exp: now() + accessTtl, ...claims })
      .setProtectedHeader({ alg: "RS256", kid: current().kid, typ: "JWT" })
      .sign(current().privateKey);

  async function issueTokens(session: Session) {
    const user = opts.users.find((u) => u.sub === session.sub) as DevUser;
    const org = orgsOf(user)?.find((o) => o.id === session.orgId);
    const refreshToken = opaque();
    refreshTokens.set(refreshToken, session);
    return {
      access_token: await sign({
        sub: session.sub,
        aud: session.clientId,
        sid: session.sid,
        permissions: (org?.permissions ?? user.permissions)[session.clientId] ?? [],
        ...(org ? { org_id: org.id, org_name: org.name } : {}),
      }),
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: accessTtl,
      refresh_expires_in: refreshTtl,
    };
  }

  function authenticateClient(request: FastifyRequest): DevClient | null {
    const header = request.headers.authorization ?? "";
    if (!header.startsWith("Basic ")) return null;
    const [id, secret] = Buffer.from(header.slice(6), "base64").toString().split(":");
    return opts.clients.find((c) => c.clientId === id && c.clientSecret === secret) ?? null;
  }

  const oauthError = (reply: FastifyReply, status: number, error: string, description?: string) =>
    reply.code(status).send(description ? { error, error_description: description } : { error });

  /** The org a token is for: the requested one, else the first; undefined = user has no orgs concept. */
  function pickOrg(user: DevUser, requested?: string): { org?: DevOrg; refusal?: string } {
    const orgs = orgsOf(user);
    if (orgs === undefined) return {};
    if (orgs.length === 0) return { refusal: "no_app_access" };
    if (requested === undefined) return { org: orgs[0] };
    const org = orgs.find((o) => o.id === requested);
    return org ? { org } : { refusal: "org_not_eligible" };
  }

  const app = Fastify({ logger: false });
  await app.register(formbody);

  app.get("/.well-known/openid-configuration", async () => ({
    issuer,
    jwks_uri: `${issuer}/jwks`,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    revocation_endpoint: `${issuer}/revoke`,
    end_session_endpoint: `${issuer}/logout`,
    grant_types_supported: ["password", "authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic"],
  }));

  app.get("/jwks", async () => ({ keys: keys.map((k) => k.jwk) }));

  // monexa-auth's orgs endpoint: the token user's orgs, envelope-shaped.
  app.get("/api/me/orgs", async (request, reply) => {
    const token = request.headers.authorization?.match(/^Bearer\s+(\S+)$/i)?.[1];
    const sub = token ? await verifiedSub(token) : undefined;
    const user = opts.users.find((u) => u.sub === sub);
    if (!user) return reply.code(401).send({ error: "invalid_token" });
    return { data: (orgsOf(user) ?? []).map(({ id, name }) => ({ id, name })) };
  });

  app.get<{ Querystring: TokenBody }>("/authorize", async (request, reply) => {
    const q = request.query;
    const client = opts.clients.find((c) => c.clientId === q.client_id);
    if (!client?.redirectUris.includes(q.redirect_uri ?? "")) {
      return reply.code(400).send({ error: "invalid_request" });
    }
    const user = q.login_hint ? opts.users.find((u) => u.username === q.login_hint) : opts.users[0];
    if (!user) return reply.code(400).send({ error: "invalid_request" });
    const code = opaque();
    codes.set(code, {
      orgId: pickOrg(user).org?.id,
      sub: user.sub,
      clientId: client.clientId,
      sid: randomUUID(),
      redirectUri: q.redirect_uri as string,
      challenge: q.code_challenge ?? "",
    });
    const target = new URL(q.redirect_uri as string);
    target.searchParams.set("code", code);
    if (q.state) target.searchParams.set("state", q.state);
    return reply.redirect(target.toString());
  });

  app.post<{ Body: TokenBody }>("/token", async (request, reply) => {
    const client = authenticateClient(request);
    if (!client) return oauthError(reply, 401, "invalid_client");
    const body = request.body;

    if (body.grant_type === "password") {
      const user = opts.users.find(
        (u) => u.username === body.username && u.password === body.password
      );
      if (!user) return oauthError(reply, 400, "invalid_grant");
      if (user.mustChangePassword) {
        return oauthError(reply, 400, "invalid_grant", "password_change_required");
      }
      const { org, refusal } = pickOrg(user, body.org_id);
      if (refusal) return oauthError(reply, 400, "invalid_grant", refusal);
      return issueTokens({
        sub: user.sub,
        clientId: client.clientId,
        sid: randomUUID(),
        orgId: org?.id,
      });
    }

    if (body.grant_type === "refresh_token") {
      const session = refreshTokens.get(body.refresh_token ?? "");
      if (!session || session.clientId !== client.clientId) {
        return oauthError(reply, 400, "invalid_grant");
      }
      refreshTokens.delete(body.refresh_token as string);
      return issueTokens(session);
    }

    if (body.grant_type === "authorization_code") {
      const pending = codes.get(body.code ?? "");
      codes.delete(body.code ?? "");
      const challenge = createHash("sha256")
        .update(body.code_verifier ?? "")
        .digest("base64url");
      if (
        !pending ||
        pending.clientId !== client.clientId ||
        pending.redirectUri !== body.redirect_uri ||
        pending.challenge !== challenge
      ) {
        return oauthError(reply, 400, "invalid_grant");
      }
      return issueTokens({
        sub: pending.sub,
        clientId: pending.clientId,
        sid: pending.sid,
        orgId: pending.orgId,
      });
    }

    if (body.grant_type === ORG_SWITCH_GRANT) {
      const session = refreshTokens.get(body.refresh_token ?? "");
      if (!session || session.clientId !== client.clientId) {
        return oauthError(reply, 400, "invalid_grant");
      }
      const user = opts.users.find((u) => u.sub === session.sub) as DevUser;
      const { org, refusal } = pickOrg(user, body.org_id ?? "");
      if (refusal) return oauthError(reply, 400, "invalid_grant", refusal);
      refreshTokens.delete(body.refresh_token as string);
      return issueTokens({ ...session, orgId: org?.id });
    }

    return oauthError(reply, 400, "unsupported_grant_type");
  });

  app.post<{ Body: TokenBody }>("/revoke", async (request, reply) => {
    if (!authenticateClient(request)) return oauthError(reply, 401, "invalid_client");
    refreshTokens.delete(request.body.token ?? "");
    return reply.code(200).send();
  });

  app.get<{ Querystring: TokenBody }>("/logout", async (request, reply) => {
    const target = request.query.post_logout_redirect_uri;
    return target ? reply.redirect(target) : reply.code(200).send({ logged_out: true });
  });

  return {
    app,
    issuer: () => issuer,
    async listen(listenOpts = {}) {
      const address = await app.listen({
        port: listenOpts.port ?? 0,
        host: listenOpts.host ?? "127.0.0.1",
      });
      if (!issuer) issuer = address;
      return address;
    },
    async rotateKey() {
      keys.push(await newKey());
    },
    signTestToken: sign,
  };
}
