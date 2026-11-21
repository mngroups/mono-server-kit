import { createHash, randomBytes, randomUUID, type webcrypto } from "node:crypto";
import formbody from "@fastify/formbody";
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from "fastify";
import { exportJWK, generateKeyPair, type JWK, type JWTPayload, SignJWT } from "jose";

export type DevUser = {
  username: string;
  password: string;
  sub: string;
  /** Permissions per client id: what lands in that client's token `permissions` claim. */
  permissions: Record<string, string[]>;
};

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
type Session = { sub: string; clientId: string; sid: string };
type PendingCode = Session & { redirectUri: string; challenge: string };
type TokenBody = Record<string, string | undefined>;

const opaque = () => randomBytes(32).toString("base64url");
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

  const sign = (claims: JWTPayload) =>
    new SignJWT({ iss: issuer, iat: now(), exp: now() + accessTtl, ...claims })
      .setProtectedHeader({ alg: "RS256", kid: current().kid, typ: "JWT" })
      .sign(current().privateKey);

  async function issueTokens(session: Session) {
    const user = opts.users.find((u) => u.sub === session.sub) as DevUser;
    const refreshToken = opaque();
    refreshTokens.set(refreshToken, session);
    return {
      access_token: await sign({
        sub: session.sub,
        aud: session.clientId,
        sid: session.sid,
        permissions: user.permissions[session.clientId] ?? [],
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

  const oauthError = (reply: FastifyReply, status: number, error: string) =>
    reply.code(status).send({ error });

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
      return issueTokens({ sub: user.sub, clientId: client.clientId, sid: randomUUID() });
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
      return issueTokens({ sub: pending.sub, clientId: pending.clientId, sid: pending.sid });
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
