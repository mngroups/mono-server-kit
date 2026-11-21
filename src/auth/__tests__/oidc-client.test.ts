import { createHash } from "node:crypto";
import Fastify, { type FastifyInstance } from "fastify";
import { createDevIssuer, type DevIssuer } from "../../dev/issuer.js";
import { AppError } from "../../errors.js";
import { MESSAGES } from "../../messages.js";
import { createOidcClient } from "../oidc-client.js";

const CLIENT = {
  clientId: "app-a",
  clientSecret: "secret-a",
  redirectUris: ["http://localhost:3000/auth/callback"],
};
const USERS = [
  { username: "admin", password: "admin123", sub: "user-1", permissions: { "app-a": ["x:all"] } },
];
let issuer: DevIssuer;
let url: string;

beforeAll(async () => {
  issuer = await createDevIssuer({ users: USERS, clients: [CLIENT] });
  url = await issuer.listen();
});
afterAll(() => issuer.app.close());

const client = (over: Partial<Parameters<typeof createOidcClient>[0]> = {}) =>
  createOidcClient({ issuer: url, clientId: "app-a", clientSecret: "secret-a", ...over });

async function caught(promise: Promise<unknown>) {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(AppError);
  return error as AppError;
}

/** A misbehaving provider: discovery points at its own token endpoint. */
async function fakeProvider(
  token: (reply: import("fastify").FastifyReply) => unknown,
  discovery: Record<string, unknown> = {}
): Promise<{ app: FastifyInstance; base: string }> {
  const app = Fastify();
  app.addContentTypeParser(
    "application/x-www-form-urlencoded",
    { parseAs: "string" },
    (_req, body, done) => done(null, body)
  );
  let base = "";
  app.get("/.well-known/openid-configuration", async () => ({
    issuer: base,
    jwks_uri: `${base}/jwks`,
    token_endpoint: `${base}/token`,
    authorization_endpoint: `${base}/authorize`,
    ...discovery,
  }));
  app.post("/token", async (_req, reply) => token(reply));
  base = await app.listen({ port: 0, host: "127.0.0.1" });
  return { app, base };
}

describe("createOidcClient", () => {
  it("password grant returns a token set", async () => {
    const tokens = await client().passwordGrant("admin", "admin123");
    expect(tokens).toEqual({
      access_token: expect.any(String),
      refresh_token: expect.any(String),
      expires_in: 900,
      refresh_expires_in: 86400,
    });
  });

  it("refresh grant returns a new token set", async () => {
    const c = client();
    const first = await c.passwordGrant("admin", "admin123");
    const next = await c.refreshGrant(first.refresh_token);
    expect(next.refresh_token).not.toBe(first.refresh_token);
  });

  it("code grant exchanges an authorization code", async () => {
    const c = client();
    const verifier = "v".repeat(43);
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = await c.authorizeUrl({
      redirectUri: CLIENT.redirectUris[0] as string,
      codeChallenge: challenge,
      state: "s1",
    });
    const res = await fetch(authorize, { redirect: "manual" });
    const code = new URL(res.headers.get("location") as string).searchParams.get("code") as string;
    const tokens = await c.codeGrant(code, verifier, CLIENT.redirectUris[0] as string);
    expect(tokens.access_token).toEqual(expect.any(String));
    await expect(
      caught(c.codeGrant(code, verifier, CLIENT.redirectUris[0] as string))
    ).resolves.toMatchObject({ code: 401, message: MESSAGES.invalidToken });
  });

  it("maps a wrong password to 401 invalidCredentials", async () => {
    const error = await caught(client().passwordGrant("admin", "nope"));
    expect(error).toMatchObject({ code: 401, message: MESSAGES.invalidCredentials });
  });

  it("maps a revoked refresh token to 401 invalidToken", async () => {
    const c = client();
    const tokens = await c.passwordGrant("admin", "admin123");
    await c.revoke(tokens.refresh_token);
    const error = await caught(c.refreshGrant(tokens.refresh_token));
    expect(error).toMatchObject({ code: 401, message: MESSAGES.invalidToken });
  });

  it("maps a wrong client secret to 500 (misconfiguration)", async () => {
    const error = await caught(client({ clientSecret: "bad" }).passwordGrant("admin", "admin123"));
    expect(error).toMatchObject({ code: 500, message: MESSAGES.internal });
  });

  it("maps an unreachable issuer to 503", async () => {
    const error = await caught(
      client({ issuer: "http://127.0.0.1:1" }).passwordGrant("admin", "admin123")
    );
    expect(error).toMatchObject({ code: 503, message: MESSAGES.authUnavailable });
  });

  it("does not cache a failed discovery", async () => {
    let calls = 0;
    const app = Fastify();
    let base = "";
    app.get("/.well-known/openid-configuration", async (_req, reply) => {
      calls += 1;
      if (calls === 1) return reply.code(500).send("down");
      return { issuer: base, jwks_uri: `${base}/jwks`, token_endpoint: `${base}/token` };
    });
    base = await app.listen({ port: 0, host: "127.0.0.1" });
    const c = client({ issuer: base });
    expect((await caught(c.discovery())).code).toBe(503);
    expect((await c.discovery()).token_endpoint).toBe(`${base}/token`);
    await c.discovery();
    expect(calls).toBe(2);
    await app.close();
  });

  it("maps a missing or malformed discovery document to 503", async () => {
    const app = Fastify();
    app.get("/bad/.well-known/openid-configuration", async (_req, reply) =>
      reply.type("text/plain").send("not json")
    );
    app.get("/partial/.well-known/openid-configuration", async () => ({ issuer: "x" }));
    const base = await app.listen({ port: 0, host: "127.0.0.1" });
    expect((await caught(client({ issuer: `${base}/missing/` }).discovery())).code).toBe(503);
    expect((await caught(client({ issuer: `${base}/bad` }).discovery())).code).toBe(503);
    expect((await caught(client({ issuer: `${base}/partial` }).discovery())).code).toBe(503);
    await app.close();
  });

  it("maps a token endpoint timeout to 503", async () => {
    const { app, base } = await fakeProvider(async () => {
      await new Promise((r) => setTimeout(r, 300));
      return {};
    });
    const error = await caught(client({ issuer: base, timeoutMs: 50 }).passwordGrant("a", "b"));
    expect(error).toMatchObject({ code: 503 });
    await app.close();
  });

  it("maps a 5xx token response to 503", async () => {
    const { app, base } = await fakeProvider((reply) => reply.code(502).send("bad gateway"));
    expect((await caught(client({ issuer: base }).refreshGrant("r"))).code).toBe(503);
    await app.close();
  });

  it("maps other OAuth errors to 500 and a malformed success to 500", async () => {
    const other = await fakeProvider((reply) => reply.code(400).send({ error: "invalid_request" }));
    expect((await caught(client({ issuer: other.base }).passwordGrant("a", "b"))).code).toBe(500);
    await other.app.close();
    const malformed = await fakeProvider(() => ({ token_type: "Bearer" }));
    expect((await caught(client({ issuer: malformed.base }).passwordGrant("a", "b"))).code).toBe(
      500
    );
    await malformed.app.close();
    const notJson = await fakeProvider((reply) => reply.code(400).send("oops"));
    expect((await caught(client({ issuer: notJson.base }).passwordGrant("a", "b"))).code).toBe(500);
    await notJson.app.close();
  });

  it("fills refresh_expires_in from the fallback when the provider omits it", async () => {
    const { app, base } = await fakeProvider(() => ({
      access_token: "a",
      refresh_token: "r",
      expires_in: 300,
    }));
    const tokens = await client({ issuer: base, refreshExpiresInFallback: 3600 }).refreshGrant("r");
    expect(tokens).toEqual({
      access_token: "a",
      refresh_token: "r",
      expires_in: 300,
      refresh_expires_in: 3600,
    });
    expect((await client({ issuer: base }).refreshGrant("r")).refresh_expires_in).toBe(86400);
    await app.close();
  });

  it("builds an authorize URL with PKCE, state and an optional IdP hint", async () => {
    const plain = new URL(
      await client().authorizeUrl({ redirectUri: "http://r/cb", codeChallenge: "ch", state: "st" })
    );
    expect(plain.origin + plain.pathname).toBe(`${url}/authorize`);
    expect(Object.fromEntries(plain.searchParams)).toEqual({
      response_type: "code",
      client_id: "app-a",
      redirect_uri: "http://r/cb",
      scope: "openid",
      code_challenge: "ch",
      code_challenge_method: "S256",
      state: "st",
    });
    const hinted = new URL(
      await client().authorizeUrl({
        redirectUri: "http://r/cb",
        codeChallenge: "ch",
        state: "st",
        idpHint: "google",
      })
    );
    expect(hinted.searchParams.get("kc_idp_hint")).toBe("google");
    const custom = new URL(
      await client().authorizeUrl({
        redirectUri: "http://r/cb",
        codeChallenge: "ch",
        state: "st",
        idpHint: "google",
        idpHintParam: "idp",
      })
    );
    expect(custom.searchParams.get("idp")).toBe("google");
  });

  it("refuses authorizeUrl when the provider has no authorization endpoint", async () => {
    const { app, base } = await fakeProvider(() => ({}), { authorization_endpoint: undefined });
    const error = await caught(
      client({ issuer: base }).authorizeUrl({ redirectUri: "r", codeChallenge: "c", state: "s" })
    );
    expect(error.code).toBe(500);
    await app.close();
  });

  it("builds the end-session URL, or null when the provider has none", async () => {
    const withRedirect = new URL(
      (await client().endSessionUrl({
        postLogoutRedirectUri: "http://localhost:3000/login",
      })) as string
    );
    expect(withRedirect.origin + withRedirect.pathname).toBe(`${url}/logout`);
    expect(Object.fromEntries(withRedirect.searchParams)).toEqual({
      client_id: "app-a",
      post_logout_redirect_uri: "http://localhost:3000/login",
    });
    const bare = new URL((await client().endSessionUrl({})) as string);
    expect(bare.searchParams.has("post_logout_redirect_uri")).toBe(false);
    const { app, base } = await fakeProvider(() => ({}));
    expect(await client({ issuer: base }).endSessionUrl({})).toBeNull();
    await app.close();
  });

  it("revoke is best effort: unreachable issuer or no revocation endpoint resolves", async () => {
    await expect(client({ issuer: "http://127.0.0.1:1" }).revoke("r")).resolves.toBeUndefined();
    const { app, base } = await fakeProvider(() => ({}));
    await expect(client({ issuer: base }).revoke("r")).resolves.toBeUndefined();
    await app.close();
  });

  describe("org_id on the password grant", () => {
    async function recordingProvider() {
      const bodies: URLSearchParams[] = [];
      const provider = await fakeProvider((reply) => {
        bodies.push(new URLSearchParams(reply.request.body as string));
        return { access_token: "a", refresh_token: "r", expires_in: 60 };
      });
      return { ...provider, bodies };
    }

    it("sends org_id when given, as is", async () => {
      const { app, base, bodies } = await recordingProvider();
      await client({ issuer: base }).passwordGrant("u", "p", "not-a-uuid");
      expect(bodies[0]?.get("org_id")).toBe("not-a-uuid");
      await app.close();
    });

    it("omits org_id when not given", async () => {
      const { app, base, bodies } = await recordingProvider();
      await client({ issuer: base }).passwordGrant("u", "p");
      expect(bodies[0]?.has("org_id")).toBe(false);
      await app.close();
    });
  });

  describe("grant reasons", () => {
    const refuse = (description: string) =>
      fakeProvider((reply) =>
        reply.code(400).send({ error: "invalid_grant", error_description: description })
      );

    it.each([
      ["invalid_credentials", MESSAGES.invalidCredentials],
      ["no_app_access", MESSAGES.noAppAccess],
      ["password_change_required", MESSAGES.passwordChangeRequired],
      ["org_not_eligible", MESSAGES.orgNotEligible],
      ["google_required", MESSAGES.googleRequired],
    ])("passes %s through with its message and data.reason", async (reason, message) => {
      const { app, base } = await refuse(reason);
      const error = await caught(client({ issuer: base }).passwordGrant("a", "b"));
      expect(error).toMatchObject({ code: 401, message, data: { reason } });
      await app.close();
    });

    it("keeps today's message and no data for an unknown description", async () => {
      const { app, base } = await refuse("grant request is invalid");
      const login = await caught(client({ issuer: base }).passwordGrant("a", "b"));
      expect(login).toMatchObject({ code: 401, message: MESSAGES.invalidCredentials });
      expect(login.data).toBeUndefined();
      const refresh = await caught(client({ issuer: base }).refreshGrant("r"));
      expect(refresh).toMatchObject({ code: 401, message: MESSAGES.invalidToken });
      expect(refresh.data).toBeUndefined();
      await app.close();
    });
  });
});
