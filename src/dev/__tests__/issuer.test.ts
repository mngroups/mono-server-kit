import { createHash } from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { createDevIssuer, type DevClient, type DevUser } from "../issuer.js";

const ISSUER = "http://issuer.test";
const CLIENT: DevClient = {
  clientId: "app-a",
  clientSecret: "secret-a",
  redirectUris: ["http://localhost:3000/auth/callback"],
};
const USERS: DevUser[] = [
  {
    username: "admin",
    password: "admin123",
    sub: "user-1",
    permissions: { "app-a": ["example:all"], "app-b": ["other:view"] },
  },
  { username: "viewer", password: "viewer123", sub: "user-2", permissions: {} },
  {
    username: "member",
    password: "member123",
    sub: "user-3",
    permissions: {},
    org: { id: "org-1", name: "PT A" },
  },
];
const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;
const AUTH = basic(CLIENT.clientId, CLIENT.clientSecret);
const form = (body: Record<string, string>) => new URLSearchParams(body).toString();
const FORM = "application/x-www-form-urlencoded";

async function setup() {
  return createDevIssuer({ issuer: ISSUER, users: USERS, clients: [CLIENT] });
}

async function token(
  app: Awaited<ReturnType<typeof setup>>["app"],
  body: Record<string, string>,
  auth = AUTH
) {
  return app.inject({
    method: "POST",
    url: "/token",
    headers: { authorization: auth, "content-type": FORM },
    payload: form(body),
  });
}

async function verify(handle: Awaited<ReturnType<typeof setup>>, jwt: string) {
  const jwks = (await handle.app.inject({ url: "/jwks" })).json();
  return jwtVerify(jwt, createLocalJWKSet(jwks), { issuer: ISSUER });
}

function pkce() {
  const verifier = "v".repeat(43);
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

async function authorizeCode(
  handle: Awaited<ReturnType<typeof setup>>,
  challenge: string,
  extra: Record<string, string> = {}
) {
  const res = await handle.app.inject({
    url: `/authorize?${form({
      client_id: CLIENT.clientId,
      redirect_uri: CLIENT.redirectUris[0] as string,
      response_type: "code",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: "st-1",
      ...extra,
    })}`,
  });
  return res;
}

describe("createDevIssuer", () => {
  it("serves discovery with every endpoint under the issuer", async () => {
    const { app } = await setup();
    const doc = (await app.inject({ url: "/.well-known/openid-configuration" })).json();
    expect(doc).toMatchObject({
      issuer: ISSUER,
      jwks_uri: `${ISSUER}/jwks`,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      revocation_endpoint: `${ISSUER}/revoke`,
      end_session_endpoint: `${ISSUER}/logout`,
    });
  });

  it("password grant returns tokens whose access token is scoped to the client", async () => {
    const handle = await setup();
    const res = await token(handle.app, {
      grant_type: "password",
      username: "admin",
      password: "admin123",
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body).toMatchObject({
      expires_in: 900,
      refresh_expires_in: 86400,
      token_type: "Bearer",
      refresh_token: expect.any(String),
    });
    const { payload } = await verify(handle, body.access_token);
    expect(payload).toMatchObject({
      sub: "user-1",
      aud: "app-a",
      permissions: ["example:all"],
      sid: expect.any(String),
    });
  });

  it("gives an empty permissions claim to a user without grants for the client", async () => {
    const handle = await setup();
    const body = (
      await token(handle.app, { grant_type: "password", username: "viewer", password: "viewer123" })
    ).json();
    expect((await verify(handle, body.access_token)).payload.permissions).toEqual([]);
  });

  it("adds org_id and org_name claims for a user with an org, and none otherwise", async () => {
    const handle = await setup();
    const member = (
      await token(handle.app, { grant_type: "password", username: "member", password: "member123" })
    ).json();
    expect((await verify(handle, member.access_token)).payload).toMatchObject({
      org_id: "org-1",
      org_name: "PT A",
    });
    const viewer = (
      await token(handle.app, { grant_type: "password", username: "viewer", password: "viewer123" })
    ).json();
    const { payload } = await verify(handle, viewer.access_token);
    expect(payload).not.toHaveProperty("org_id");
    expect(payload).not.toHaveProperty("org_name");
  });

  it("rejects a wrong password with invalid_grant", async () => {
    const res = await token((await setup()).app, {
      grant_type: "password",
      username: "admin",
      password: "nope",
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "invalid_grant" });
  });

  it("rejects a wrong client secret or missing client auth with invalid_client", async () => {
    const { app } = await setup();
    const wrong = await token(app, { grant_type: "password" }, basic("app-a", "bad"));
    expect(wrong.statusCode).toBe(401);
    expect(wrong.json()).toEqual({ error: "invalid_client" });
    const none = await app.inject({
      method: "POST",
      url: "/token",
      headers: { "content-type": FORM },
      payload: form({ grant_type: "password" }),
    });
    expect(none.statusCode).toBe(401);
    const unknown = await token(app, { grant_type: "password" }, basic("ghost", "x"));
    expect(unknown.statusCode).toBe(401);
  });

  it("rejects an unknown grant type", async () => {
    const res = await token((await setup()).app, { grant_type: "client_credentials" });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "unsupported_grant_type" });
  });

  it("refresh grant rotates the refresh token and fails after revoke", async () => {
    const { app } = await setup();
    const first = (
      await token(app, { grant_type: "password", username: "admin", password: "admin123" })
    ).json();
    const second = await token(app, {
      grant_type: "refresh_token",
      refresh_token: first.refresh_token,
    });
    expect(second.statusCode).toBe(200);
    expect(second.json().refresh_token).not.toBe(first.refresh_token);
    // The rotated-away token is spent.
    const reused = await token(app, {
      grant_type: "refresh_token",
      refresh_token: first.refresh_token,
    });
    expect(reused.json()).toEqual({ error: "invalid_grant" });

    const revoke = await app.inject({
      method: "POST",
      url: "/revoke",
      headers: { authorization: AUTH, "content-type": FORM },
      payload: form({ token: second.json().refresh_token }),
    });
    expect(revoke.statusCode).toBe(200);
    const after = await token(app, {
      grant_type: "refresh_token",
      refresh_token: second.json().refresh_token,
    });
    expect(after.statusCode).toBe(400);
    expect(after.json()).toEqual({ error: "invalid_grant" });
  });

  it("refuses a refresh token issued to another client", async () => {
    const other: DevClient = { clientId: "app-b", clientSecret: "secret-b", redirectUris: [] };
    const { app } = await createDevIssuer({
      issuer: ISSUER,
      users: USERS,
      clients: [CLIENT, other],
    });
    const a = (
      await token(app, { grant_type: "password", username: "admin", password: "admin123" })
    ).json();
    const res = await token(
      app,
      { grant_type: "refresh_token", refresh_token: a.refresh_token },
      basic("app-b", "secret-b")
    );
    expect(res.json()).toEqual({ error: "invalid_grant" });
  });

  it("revoke requires client auth", async () => {
    const res = await (await setup()).app.inject({
      method: "POST",
      url: "/revoke",
      headers: { "content-type": FORM },
      payload: form({ token: "x" }),
    });
    expect(res.statusCode).toBe(401);
  });

  it("authorize auto-approves and the code exchanges with the right verifier", async () => {
    const handle = await setup();
    const { verifier, challenge } = pkce();
    const res = await authorizeCode(handle, challenge, { login_hint: "viewer" });
    expect(res.statusCode).toBe(302);
    const location = new URL(res.headers.location as string);
    expect(location.origin + location.pathname).toBe(CLIENT.redirectUris[0]);
    expect(location.searchParams.get("state")).toBe("st-1");
    const code = location.searchParams.get("code") as string;

    const exchanged = await token(handle.app, {
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      redirect_uri: CLIENT.redirectUris[0] as string,
    });
    expect(exchanged.statusCode).toBe(200);
    const { payload } = await verify(handle, exchanged.json().access_token);
    expect(payload.sub).toBe("user-2");

    // Codes are single-use.
    const again = await token(handle.app, {
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      redirect_uri: CLIENT.redirectUris[0] as string,
    });
    expect(again.json()).toEqual({ error: "invalid_grant" });
  });

  it("authorize without login_hint signs in the first user", async () => {
    const handle = await setup();
    const { verifier, challenge } = pkce();
    const res = await authorizeCode(handle, challenge);
    const code = new URL(res.headers.location as string).searchParams.get("code") as string;
    const exchanged = await token(handle.app, {
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      redirect_uri: CLIENT.redirectUris[0] as string,
    });
    expect((await verify(handle, exchanged.json().access_token)).payload.sub).toBe("user-1");
  });

  it("rejects a code exchanged with a wrong verifier or redirect", async () => {
    const handle = await setup();
    const { verifier, challenge } = pkce();
    const code1 = new URL(
      (await authorizeCode(handle, challenge)).headers.location as string
    ).searchParams.get("code") as string;
    const badVerifier = await token(handle.app, {
      grant_type: "authorization_code",
      code: code1,
      code_verifier: "w".repeat(43),
      redirect_uri: CLIENT.redirectUris[0] as string,
    });
    expect(badVerifier.json()).toEqual({ error: "invalid_grant" });

    const code2 = new URL(
      (await authorizeCode(handle, challenge)).headers.location as string
    ).searchParams.get("code") as string;
    const badRedirect = await token(handle.app, {
      grant_type: "authorization_code",
      code: code2,
      code_verifier: verifier,
      redirect_uri: "http://evil.test/cb",
    });
    expect(badRedirect.json()).toEqual({ error: "invalid_grant" });
  });

  it("rejects authorize for an unregistered redirect, unknown client, or unknown login_hint", async () => {
    const handle = await setup();
    const { challenge } = pkce();
    const badRedirect = await authorizeCode(handle, challenge, {
      redirect_uri: "http://evil.test/cb",
    });
    expect(badRedirect.statusCode).toBe(400);
    const badClient = await authorizeCode(handle, challenge, { client_id: "ghost" });
    expect(badClient.statusCode).toBe(400);
    const badUser = await authorizeCode(handle, challenge, { login_hint: "ghost" });
    expect(badUser.statusCode).toBe(400);
  });

  it("rejects requests with missing parameters instead of crashing", async () => {
    const handle = await setup();
    const { app } = handle;
    const noRedirect = await app.inject({ url: `/authorize?client_id=${CLIENT.clientId}` });
    expect(noRedirect.statusCode).toBe(400);
    expect((await token(app, { grant_type: "refresh_token" })).json()).toEqual({
      error: "invalid_grant",
    });
    expect((await token(app, { grant_type: "authorization_code" })).json()).toEqual({
      error: "invalid_grant",
    });
    // A code requested without a PKCE challenge never exchanges.
    const res = await app.inject({
      url: `/authorize?${form({
        client_id: CLIENT.clientId,
        redirect_uri: CLIENT.redirectUris[0] as string,
      })}`,
    });
    const location = new URL(res.headers.location as string);
    expect(location.searchParams.has("state")).toBe(false);
    const exchanged = await token(app, {
      grant_type: "authorization_code",
      code: location.searchParams.get("code") as string,
      code_verifier: "v".repeat(43),
      redirect_uri: CLIENT.redirectUris[0] as string,
    });
    expect(exchanged.json()).toEqual({ error: "invalid_grant" });
    const revoke = await app.inject({
      method: "POST",
      url: "/revoke",
      headers: { authorization: AUTH, "content-type": FORM },
      payload: "",
    });
    expect(revoke.statusCode).toBe(200);
  });

  it("logout redirects to post_logout_redirect_uri or answers 200", async () => {
    const { app } = await setup();
    const redirect = await app.inject({
      url: "/logout?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Flogin",
    });
    expect(redirect.statusCode).toBe(302);
    expect(redirect.headers.location).toBe("http://localhost:3000/login");
    expect((await app.inject({ url: "/logout" })).statusCode).toBe(200);
  });

  it("rotateKey keeps old keys in the JWKS and signs with the new one", async () => {
    const handle = await setup();
    const before = await handle.signTestToken({ sub: "user-1", aud: "app-a" });
    await handle.rotateKey();
    const after = await handle.signTestToken({ sub: "user-1", aud: "app-a" });
    const kids = (await handle.app.inject({ url: "/jwks" }))
      .json()
      .keys.map((k: { kid: string }) => k.kid);
    expect(kids).toHaveLength(2);
    expect(kids).toContain(decodeProtectedHeader(before).kid);
    expect(kids).toContain(decodeProtectedHeader(after).kid);
    expect(decodeProtectedHeader(before).kid).not.toBe(decodeProtectedHeader(after).kid);
  });

  it("signTestToken fills defaults that caller claims override", async () => {
    const handle = await setup();
    const now = Math.floor(Date.now() / 1000);
    const jwt = await handle.signTestToken({ sub: "x", aud: "app-a", exp: now + 5 });
    const { payload } = await verify(handle, jwt);
    expect(payload).toMatchObject({ iss: ISSUER, sub: "x", exp: now + 5 });
    expect(payload.iat).toBeGreaterThanOrEqual(now - 1);
  });

  it("listen() binds a port and adopts it as the issuer when none was given", async () => {
    const handle = await createDevIssuer({ users: USERS, clients: [CLIENT] });
    const url = await handle.listen();
    expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(handle.issuer()).toBe(url);
    const doc = (await (await fetch(`${url}/.well-known/openid-configuration`)).json()) as {
      issuer: string;
    };
    expect(doc.issuer).toBe(url);
    await handle.app.close();
  });

  it("listen() keeps an explicit issuer", async () => {
    const handle = await setup();
    await handle.listen({ port: 0 });
    expect(handle.issuer()).toBe(ISSUER);
    await handle.app.close();
  });

  it("refuses to run in production", async () => {
    const previous = process.env.NODE_ENV;
    process.env.NODE_ENV = "production";
    try {
      await expect(setup()).rejects.toThrow("@mono/server-kit/dev must not run in production");
    } finally {
      process.env.NODE_ENV = previous;
    }
  });

  describe("multi-org", () => {
    const ORG_A = { id: "org-a", name: "Org A" };
    const ORG_B = { id: "org-b", name: "Org B", permissions: { "app-a": ["b:view"] } };
    const MULTI: DevUser[] = [
      {
        username: "multi",
        password: "pw",
        sub: "u-multi",
        permissions: { "app-a": ["a:all"] },
        orgs: [ORG_A, ORG_B],
      },
      { username: "none", password: "pw", sub: "u-none", permissions: {}, orgs: [] },
      {
        username: "fresh",
        password: "pw",
        sub: "u-fresh",
        permissions: {},
        orgs: [ORG_A],
        mustChangePassword: true,
      },
      { username: "legacy", password: "pw", sub: "u-legacy", permissions: {}, org: ORG_A },
    ];
    const multiSetup = () => createDevIssuer({ issuer: ISSUER, users: MULTI, clients: [CLIENT] });
    const login = (
      app: Awaited<ReturnType<typeof multiSetup>>["app"],
      username: string,
      extra: Record<string, string> = {}
    ) => token(app, { grant_type: "password", username, password: "pw", ...extra });
    const SWITCH = "urn:monexa:params:oauth:grant-type:org-switch";

    it("signs in to the requested org with its per-org permissions", async () => {
      const handle = await multiSetup();
      const res = await login(handle.app, "multi", { org_id: "org-b" });
      const { payload } = await verify(handle as never, res.json().access_token);
      expect(payload).toMatchObject({
        org_id: "org-b",
        org_name: "Org B",
        permissions: ["b:view"],
      });
    });

    it("defaults to the first org and the user-level permissions", async () => {
      const handle = await multiSetup();
      const { payload } = await verify(
        handle as never,
        (await login(handle.app, "multi")).json().access_token
      );
      expect(payload).toMatchObject({ org_id: "org-a", permissions: ["a:all"] });
    });

    it("refuses an org the user isn't in, an empty org list, and a forced password change", async () => {
      const { app } = await multiSetup();
      expect((await login(app, "multi", { org_id: "org-c" })).json()).toEqual({
        error: "invalid_grant",
        error_description: "org_not_eligible",
      });
      expect((await login(app, "none")).json()).toEqual({
        error: "invalid_grant",
        error_description: "no_app_access",
      });
      expect((await login(app, "fresh")).json()).toEqual({
        error: "invalid_grant",
        error_description: "password_change_required",
      });
    });

    it("keeps the legacy single org field working", async () => {
      const handle = await multiSetup();
      const { payload } = await verify(
        handle as never,
        (await login(handle.app, "legacy")).json().access_token
      );
      expect(payload).toMatchObject({ org_id: "org-a", org_name: "Org A" });
    });

    it("switches org with a refresh token and spends the old one", async () => {
      const handle = await multiSetup();
      const first = (await login(handle.app, "multi")).json();
      const switched = await token(handle.app, {
        grant_type: SWITCH,
        refresh_token: first.refresh_token,
        org_id: "org-b",
      });
      expect(switched.statusCode).toBe(200);
      const { payload } = await verify(handle as never, switched.json().access_token);
      expect(payload.org_id).toBe("org-b");
      const reused = await token(handle.app, {
        grant_type: "refresh_token",
        refresh_token: first.refresh_token,
      });
      expect(reused.json()).toEqual({ error: "invalid_grant" });
      const refused = await token(handle.app, {
        grant_type: SWITCH,
        refresh_token: switched.json().refresh_token,
        org_id: "org-c",
      });
      expect(refused.json()).toEqual({
        error: "invalid_grant",
        error_description: "org_not_eligible",
      });
      const unknown = await token(handle.app, {
        grant_type: SWITCH,
        refresh_token: "nope",
        org_id: "org-a",
      });
      expect(unknown.json()).toEqual({ error: "invalid_grant" });
    });

    it("lists the token user's orgs at /api/me/orgs", async () => {
      const { app } = await multiSetup();
      const { access_token } = (await login(app, "multi")).json();
      const res = await app.inject({
        url: "/api/me/orgs",
        headers: { authorization: `Bearer ${access_token}` },
      });
      expect(res.json()).toEqual({
        data: [
          { id: "org-a", name: "Org A" },
          { id: "org-b", name: "Org B" },
        ],
      });
      expect((await app.inject({ url: "/api/me/orgs" })).statusCode).toBe(401);
      expect(
        (await app.inject({ url: "/api/me/orgs", headers: { authorization: "Bearer junk" } }))
          .statusCode
      ).toBe(401);
    });
  });
});
