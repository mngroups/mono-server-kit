import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { DevIssuer } from "../../dev/issuer.js";
import { MESSAGES } from "../../messages.js";
import { buildApp, json, REDIRECT, startIssuer } from "./helpers.js";

// The FE's own schema (monexa-app-template features/auth/schema.ts).
const feLoginData = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1),
  expires_in: z.number(),
  refresh_expires_in: z.number(),
});

let issuer: DevIssuer;
let app: FastifyInstance;

beforeAll(async () => {
  issuer = await startIssuer();
  app = await buildApp(issuer.issuer());
});
afterAll(async () => {
  await app.close();
  await issuer.app.close();
});

const login = (username: string, password: string) =>
  app.inject({ method: "POST", url: "/v1/auth/login", payload: { username, password } });

async function tokensFor(username: string, password: string) {
  return (await login(username, password)).json().data as z.infer<typeof feLoginData>;
}
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

describe("auth plugin — credentials mode", () => {
  it("login returns the token envelope the FE expects", async () => {
    const res = await login("admin", "admin123");
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ success: true, code: 200 });
    expect(feLoginData.safeParse(res.json().data).success).toBe(true);
  });

  it("login with a wrong password is 401 invalidCredentials", async () => {
    const res = await login("admin", "nope");
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ success: false, message: MESSAGES.invalidCredentials });
  });

  it("login with an empty username is 422", async () => {
    expect((await login("   ", "x")).statusCode).toBe(422);
  });

  it("refresh returns new tokens; a revoked refresh token is 401", async () => {
    const tokens = await tokensFor("admin", "admin123");
    const refreshed = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refresh_token: tokens.refresh_token },
    });
    expect(refreshed.statusCode).toBe(200);
    expect(feLoginData.safeParse(refreshed.json().data).success).toBe(true);

    const newRefresh = refreshed.json().data.refresh_token;
    const out = await app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      headers: bearer(refreshed.json().data.access_token),
      payload: { refresh_token: newRefresh },
    });
    expect(out.statusCode).toBe(200);
    expect(out.json()).toMatchObject({ success: true, data: null });
    const again = await app.inject({
      method: "POST",
      url: "/v1/auth/refresh",
      payload: { refresh_token: newRefresh },
    });
    expect(again.statusCode).toBe(401);
    expect(again.json().message).toBe(MESSAGES.invalidToken);
  });

  it("logout without a body succeeds, even with the FE's JSON content type", async () => {
    const tokens = await tokensFor("admin", "admin123");
    const bare = await app.inject({ method: "POST", url: "/v1/auth/logout" });
    expect(bare.statusCode).toBe(200);
    // @mono/auth's apiClient always sends Content-Type: application/json, even with no body.
    const feStyle = await app.inject({
      method: "POST",
      url: "/v1/auth/logout",
      headers: { ...json, ...bearer(tokens.access_token) },
    });
    expect(feStyle.statusCode).toBe(200);
  });

  it("/v1/auth/check returns the user id and permissions from the token", async () => {
    const tokens = await tokensFor("admin", "admin123");
    const res = await app.inject({ url: "/v1/auth/check", headers: bearer(tokens.access_token) });
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toEqual({ user_id: "user-1", permissions: ["example:all"] });
  });

  it("/v1/auth/check returns [] for a user without permissions", async () => {
    const tokens = await tokensFor("nobody", "nobody123");
    const res = await app.inject({ url: "/v1/auth/check", headers: bearer(tokens.access_token) });
    expect(res.json().data).toEqual({ user_id: "user-3", permissions: [] });
  });

  it("guards every non-public route: no token or a bad token is 401", async () => {
    const none = await app.inject({ url: "/me" });
    expect(none.statusCode).toBe(401);
    expect(none.json().message).toBe(MESSAGES.invalidToken);
    expect(
      (await app.inject({ url: "/me", headers: { authorization: "Basic abc" } })).statusCode
    ).toBe(401);
    expect((await app.inject({ url: "/me", headers: bearer("garbage") })).statusCode).toBe(401);
    expect((await app.inject({ url: "/v1/auth/check" })).statusCode).toBe(401);
  });

  it("sets request.user on guarded routes and leaves it null on public ones", async () => {
    const tokens = await tokensFor("admin", "admin123");
    const me = await app.inject({
      url: "/me",
      headers: { authorization: `bearer ${tokens.access_token}` },
    });
    expect(me.json().data).toEqual({ id: "user-1" });
    const open = await app.inject({ url: "/open" });
    expect(open.statusCode).toBe(200);
    expect(open.json().data).toEqual({ user: null });
  });

  it("keeps 404 for unknown routes instead of answering 401", async () => {
    expect((await app.inject({ url: "/nope" })).statusCode).toBe(404);
  });

  it("requirePermission: :all wildcard grants, an unrelated permission is 403", async () => {
    const admin = await tokensFor("admin", "admin123");
    expect(
      (await app.inject({ url: "/items", headers: bearer(admin.access_token) })).statusCode
    ).toBe(200);
    const other = await tokensFor("other", "other123");
    const denied = await app.inject({ url: "/items", headers: bearer(other.access_token) });
    expect(denied.statusCode).toBe(403);
    expect(denied.json()).toMatchObject({ success: false, message: MESSAGES.forbidden });
    const nobody = await tokensFor("nobody", "nobody123");
    expect(
      (await app.inject({ url: "/items", headers: bearer(nobody.access_token) })).statusCode
    ).toBe(403);
  });

  it("requirePermission takes any of several permissions (OR)", async () => {
    const other = await tokensFor("other", "other123");
    expect(
      (await app.inject({ url: "/either", headers: bearer(other.access_token) })).statusCode
    ).toBe(200);
  });

  it("answers 401 when requirePermission runs on a public route without a user", async () => {
    expect((await app.inject({ url: "/public-guarded" })).statusCode).toBe(401);
  });

  it("rejects malformed JSON on auth routes with 400", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/login",
      headers: json,
      payload: "{bad",
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ success: false, code: 400 });
  });

  it("does not register sso routes in credentials mode", async () => {
    expect((await app.inject({ url: "/v1/auth/authorize-url?redirect_uri=x" })).statusCode).toBe(
      404
    );
    expect(
      (await app.inject({ method: "POST", url: "/v1/auth/callback", payload: {} })).statusCode
    ).toBe(404);
  });

  it("login is 503 when the central service is down", async () => {
    const down = await buildApp("http://127.0.0.1:1");
    const res = await down.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { username: "admin", password: "admin123" },
    });
    expect(res.statusCode).toBe(503);
    expect(res.json().message).toBe(MESSAGES.authUnavailable);
    // Guarded routes too: the JWKS can't be resolved, which is an outage, not a bad token.
    const guarded = await down.inject({ url: "/me", headers: bearer("x.y.z") });
    expect(guarded.statusCode).toBe(503);
    await down.close();
  });

  it("uses an explicit jwksUri without discovery", async () => {
    const explicit = await buildApp(issuer.issuer(), { jwksUri: `${issuer.issuer()}/jwks` });
    const tokens = await tokensFor("admin", "admin123");
    const res = await explicit.inject({ url: "/me", headers: bearer(tokens.access_token) });
    expect(res.statusCode).toBe(200);
    await explicit.close();
  });

  it("does not register the login route in sso mode", async () => {
    const sso = await buildApp(issuer.issuer(), { mode: "sso", redirectUris: [REDIRECT] });
    const res = await sso.inject({
      method: "POST",
      url: "/v1/auth/login",
      payload: { username: "admin", password: "admin123" },
    });
    expect(res.statusCode).toBe(404);
    await sso.close();
  });
});
