import Fastify, { type FastifyInstance } from "fastify";
import { decodeJwt } from "jose";
import type { DevIssuer } from "../../dev/issuer.js";
import { MESSAGES } from "../../messages.js";
import { buildApp, startIssuer } from "./helpers.js";

let issuer: DevIssuer;
let app: FastifyInstance;
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

beforeAll(async () => {
  issuer = await startIssuer();
  app = await buildApp(issuer.issuer());
});
afterAll(async () => {
  await app.close();
  await issuer.app.close();
});

const login = async (username = "multi", password = "multi123") =>
  (
    await app.inject({ method: "POST", url: "/v1/auth/login", payload: { username, password } })
  ).json().data as { access_token: string; refresh_token: string };
const switchOrg = (payload: Record<string, unknown>) =>
  app.inject({ method: "POST", url: "/v1/auth/switch-org", payload });

describe("POST /v1/auth/switch-org", () => {
  it("returns tokens for the requested org", async () => {
    const { refresh_token } = await login();
    const res = await switchOrg({ refresh_token, org_id: "org-b" });
    expect(res.statusCode).toBe(200);
    expect(decodeJwt(res.json().data.access_token)).toMatchObject({ org_id: "org-b" });
  });

  it("refuses an ineligible org with data.reason, an unknown token without one", async () => {
    const { refresh_token } = await login();
    const refused = await switchOrg({ refresh_token, org_id: "org-c" });
    expect(refused.statusCode).toBe(401);
    expect(refused.json()).toMatchObject({
      message: MESSAGES.orgNotEligible,
      data: { reason: "org_not_eligible" },
    });
    const unknown = await switchOrg({ refresh_token: "nope", org_id: "org-a" });
    expect(unknown.statusCode).toBe(401);
    expect(unknown.json()).toMatchObject({ message: MESSAGES.invalidToken, data: null });
  });

  it("validates the body", async () => {
    const { refresh_token } = await login();
    expect((await switchOrg({ refresh_token })).statusCode).toBe(422);
  });
});

describe("GET /v1/auth/orgs", () => {
  it("lists the caller's orgs", async () => {
    const { access_token } = await login();
    const res = await app.inject({ url: "/v1/auth/orgs", headers: bearer(access_token) });
    expect(res.statusCode).toBe(200);
    expect(res.json().data).toEqual([
      { id: "org-a", name: "Org A" },
      { id: "org-b", name: "Org B" },
    ]);
  });

  it("requires a token", async () => {
    expect((await app.inject({ url: "/v1/auth/orgs" })).statusCode).toBe(401);
  });

  it("answers 503 when the orgs endpoint fails, 401 when it rejects the token", async () => {
    const { access_token } = await login();
    const fake = Fastify();
    fake.get("/down", async (_req, reply) => reply.code(502).send("bad gateway"));
    fake.get("/junk", async () => ({ nope: true }));
    fake.get("/deny", async (_req, reply) => reply.code(401).send({ error: "invalid_token" }));
    const base = await fake.listen({ port: 0, host: "127.0.0.1" });
    for (const [path, code, message] of [
      ["/down", 503, MESSAGES.authUnavailable],
      ["/junk", 503, MESSAGES.authUnavailable],
      ["/deny", 401, MESSAGES.invalidToken],
    ] as const) {
      const custom = await buildApp(issuer.issuer(), { orgsEndpoint: `${base}${path}` });
      const res = await custom.inject({ url: "/v1/auth/orgs", headers: bearer(access_token) });
      expect(res.statusCode).toBe(code);
      expect(res.json().message).toBe(message);
      await custom.close();
    }
    const closed = await buildApp(issuer.issuer(), { orgsEndpoint: "http://127.0.0.1:1/x" });
    expect(
      (await closed.inject({ url: "/v1/auth/orgs", headers: bearer(access_token) })).statusCode
    ).toBe(503);
    await closed.close();
    await fake.close();
  });
});

describe("GET /v1/auth/check — active org", () => {
  it("returns the token's org", async () => {
    const { refresh_token } = await login();
    const switched = (await switchOrg({ refresh_token, org_id: "org-b" })).json().data;
    const res = await app.inject({ url: "/v1/auth/check", headers: bearer(switched.access_token) });
    expect(res.json().data.org).toEqual({ id: "org-b", name: "Org B" });
  });

  it("returns null when the token has no org", async () => {
    const { access_token } = await login("admin", "admin123");
    const res = await app.inject({ url: "/v1/auth/check", headers: bearer(access_token) });
    expect(res.json().data.org).toBeNull();
  });
});
