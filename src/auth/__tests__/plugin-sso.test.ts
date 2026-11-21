import type { FastifyInstance } from "fastify";
import type { DevIssuer } from "../../dev/issuer.js";
import { MESSAGES } from "../../messages.js";
import { createPkce } from "../pkce.js";
import { buildApp, REDIRECT, startIssuer } from "./helpers.js";

let issuer: DevIssuer;
let app: FastifyInstance;

beforeAll(async () => {
  issuer = await startIssuer();
  app = await buildApp(issuer.issuer(), {
    mode: "sso",
    redirectUris: [REDIRECT],
    postLogoutRedirectUri: "http://localhost:3000/login",
  });
});
afterAll(async () => {
  await app.close();
  await issuer.app.close();
});

async function authorize(redirect = REDIRECT) {
  return app.inject({ url: `/v1/auth/authorize-url?redirect_uri=${encodeURIComponent(redirect)}` });
}

async function codeFrom(url: string) {
  const res = await fetch(url, { redirect: "manual" });
  return new URL(res.headers.get("location") as string);
}

describe("createPkce", () => {
  it("makes a 43-char base64url verifier and its S256 challenge", async () => {
    const { verifier, challenge } = createPkce();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const { createHash } = await import("node:crypto");
    expect(challenge).toBe(createHash("sha256").update(verifier).digest("base64url"));
    expect(createPkce().verifier).not.toBe(verifier);
  });
});

describe("auth plugin — sso mode", () => {
  it("runs the full authorize → callback → check flow", async () => {
    const start = await authorize();
    expect(start.statusCode).toBe(200);
    const { url, state, code_verifier } = start.json().data;
    expect(url.startsWith(`${issuer.issuer()}/authorize?`)).toBe(true);
    expect(state).toMatch(/^[A-Za-z0-9_-]{20,}$/);

    const back = await codeFrom(url);
    expect(back.searchParams.get("state")).toBe(state);
    const callback = await app.inject({
      method: "POST",
      url: "/v1/auth/callback",
      payload: { code: back.searchParams.get("code"), code_verifier, redirect_uri: REDIRECT },
    });
    expect(callback.statusCode).toBe(200);
    const tokens = callback.json().data;
    expect(tokens).toMatchObject({ expires_in: 900, refresh_expires_in: 86400 });

    const check = await app.inject({
      url: "/v1/auth/check",
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(check.json().data).toEqual({ user_id: "user-1", permissions: ["example:all"] });
  });

  it("rejects a redirect_uri outside the allowlist on both routes with 422", async () => {
    const start = await authorize("http://evil.test/cb");
    expect(start.statusCode).toBe(422);
    expect(start.json().data.issues[0].message).toBe(MESSAGES.redirectNotAllowed);
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/callback",
      payload: { code: "c", code_verifier: "v".repeat(43), redirect_uri: "http://evil.test/cb" },
    });
    expect(res.statusCode).toBe(422);
  });

  it("rejects a wrong code_verifier with 401", async () => {
    const { url } = (await authorize()).json().data;
    const back = await codeFrom(url);
    const res = await app.inject({
      method: "POST",
      url: "/v1/auth/callback",
      payload: {
        code: back.searchParams.get("code"),
        code_verifier: "w".repeat(43),
        redirect_uri: REDIRECT,
      },
    });
    expect(res.statusCode).toBe(401);
  });

  it("adds the IdP hint to the authorize URL", async () => {
    const google = await buildApp(issuer.issuer(), {
      mode: "sso",
      redirectUris: [REDIRECT],
      idpHint: "google",
    });
    const res = await google.inject({
      url: `/v1/auth/authorize-url?redirect_uri=${encodeURIComponent(REDIRECT)}`,
    });
    expect(new URL(res.json().data.url).searchParams.get("kc_idp_hint")).toBe("google");
    await google.close();
  });

  it("logout returns the end-session URL for global logout", async () => {
    const res = await app.inject({ method: "POST", url: "/v1/auth/logout" });
    expect(res.statusCode).toBe(200);
    const endSession = new URL(res.json().data.end_session_url);
    expect(endSession.origin + endSession.pathname).toBe(`${issuer.issuer()}/logout`);
    expect(endSession.searchParams.get("post_logout_redirect_uri")).toBe(
      "http://localhost:3000/login"
    );
  });

  it("logout still succeeds with end_session_url null when the IdP is down", async () => {
    const down = await buildApp("http://127.0.0.1:1", { mode: "sso", redirectUris: [REDIRECT] });
    const res = await down.inject({ method: "POST", url: "/v1/auth/logout" });
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toEqual({ end_session_url: null });
    await down.close();
  });
});
