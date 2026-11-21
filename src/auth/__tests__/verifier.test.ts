import { createDevIssuer, type DevIssuer } from "../../dev/issuer.js";
import { AppError } from "../../errors.js";
import { MESSAGES } from "../../messages.js";
import { createVerifier } from "../verifier.js";

const CLIENT = { clientId: "app-a", clientSecret: "secret-a", redirectUris: [] };
let issuer: DevIssuer;
let verify: (token: string) => ReturnType<ReturnType<typeof createVerifier>>;
const now = () => Math.floor(Date.now() / 1000);

beforeAll(async () => {
  issuer = await createDevIssuer({ users: [], clients: [CLIENT] });
  await issuer.listen();
  verify = createVerifier({
    jwksUri: `${issuer.issuer()}/jwks`,
    issuer: issuer.issuer(),
    audience: "app-a",
    jwksCooldownMs: 0,
  });
});
afterAll(() => issuer.app.close());

async function expectInvalid(promise: Promise<unknown>) {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(AppError);
  expect(error).toMatchObject({ code: 401, message: MESSAGES.invalidToken });
}

describe("createVerifier", () => {
  it("maps sub to id and the permissions claim to a Set", async () => {
    const user = await verify(
      await issuer.signTestToken({ sub: "user-1", aud: "app-a", permissions: ["a:view", "b:all"] })
    );
    expect(user.id).toBe("user-1");
    expect([...user.permissions]).toEqual(["a:view", "b:all"]);
    expect(user.claims.aud).toBe("app-a");
  });

  it("rejects an expired token", async () => {
    await expectInvalid(
      verify(await issuer.signTestToken({ sub: "u", aud: "app-a", exp: now() - 60 }))
    );
  });

  it("accepts a token that expired within the 30s clock tolerance", async () => {
    const user = await verify(
      await issuer.signTestToken({ sub: "u", aud: "app-a", exp: now() - 20 })
    );
    expect(user.id).toBe("u");
  });

  it("accepts a token issued slightly in the future (clock skew)", async () => {
    const user = await verify(
      await issuer.signTestToken({ sub: "u", aud: "app-a", nbf: now() + 20, iat: now() + 20 })
    );
    expect(user.id).toBe("u");
  });

  it("rejects a token minted for another app", async () => {
    await expectInvalid(verify(await issuer.signTestToken({ sub: "u", aud: "app-b" })));
  });

  it("rejects a token from a different issuer", async () => {
    await expectInvalid(
      verify(await issuer.signTestToken({ sub: "u", aud: "app-a", iss: "http://evil.test" }))
    );
  });

  it("rejects a token signed by a foreign key", async () => {
    const foreign = await createDevIssuer({ issuer: issuer.issuer(), users: [], clients: [] });
    await expectInvalid(verify(await foreign.signTestToken({ sub: "u", aud: "app-a" })));
  });

  it("rejects garbage and a token without sub", async () => {
    await expectInvalid(verify("not-a-jwt"));
    await expectInvalid(verify(await issuer.signTestToken({ aud: "app-a" })));
  });

  it("maps string org_id and org_name claims to orgId and orgName", async () => {
    const user = await verify(
      await issuer.signTestToken({ sub: "u", aud: "app-a", org_id: "org-1", org_name: "PT A" })
    );
    expect(user.orgId).toBe("org-1");
    expect(user.orgName).toBe("PT A");
  });

  it("leaves orgId and orgName undefined when the claims are missing or not strings", async () => {
    const none = await verify(await issuer.signTestToken({ sub: "u", aud: "app-a" }));
    expect(none.orgId).toBeUndefined();
    expect(none.orgName).toBeUndefined();
    const bad = await verify(
      await issuer.signTestToken({ sub: "u", aud: "app-a", org_id: 7, org_name: ["x"] })
    );
    expect(bad.orgId).toBeUndefined();
    expect(bad.orgName).toBeUndefined();
  });

  it("treats a missing or non-array permissions claim as no permissions", async () => {
    const none = await verify(await issuer.signTestToken({ sub: "u", aud: "app-a" }));
    expect(none.permissions.size).toBe(0);
    const scalar = await verify(
      await issuer.signTestToken({ sub: "u", aud: "app-a", permissions: "a:view" })
    );
    expect(scalar.permissions.size).toBe(0);
    const mixed = await verify(
      await issuer.signTestToken({ sub: "u", aud: "app-a", permissions: ["a:view", 7] })
    );
    expect([...mixed.permissions]).toEqual(["a:view"]);
  });

  it("refetches the JWKS when a token carries a rotated key id", async () => {
    await verify(await issuer.signTestToken({ sub: "u", aud: "app-a" }));
    await issuer.rotateKey();
    const user = await verify(await issuer.signTestToken({ sub: "rotated", aud: "app-a" }));
    expect(user.id).toBe("rotated");
  });

  it("works with the default JWKS cooldown", async () => {
    const strict = createVerifier({
      jwksUri: `${issuer.issuer()}/jwks`,
      issuer: issuer.issuer(),
      audience: "app-a",
    });
    expect((await strict(await issuer.signTestToken({ sub: "d", aud: "app-a" }))).id).toBe("d");
  });

  it("answers 503, not 401, when the JWKS cannot be fetched", async () => {
    const unreachable = createVerifier({
      jwksUri: "http://127.0.0.1:1/jwks",
      issuer: issuer.issuer(),
      audience: "app-a",
    });
    const error = await unreachable(await issuer.signTestToken({ sub: "u", aud: "app-a" })).catch(
      (e: unknown) => e
    );
    expect(error).toMatchObject({ code: 503, message: MESSAGES.authUnavailable });
  });

  it("rejects a token issued to another client even when aud also lists this app", async () => {
    await expectInvalid(
      verify(
        await issuer.signTestToken({
          sub: "u",
          aud: ["app-b", "app-a"],
          azp: "app-b",
          permissions: ["x:all"],
        })
      )
    );
    await expectInvalid(
      verify(
        await issuer.signTestToken({ sub: "u", aud: ["app-b", "app-a"], permissions: ["x:all"] })
      )
    );
  });

  it("accepts a multi-audience token whose authorized party is this app", async () => {
    const user = await verify(
      await issuer.signTestToken({ sub: "u", aud: ["app-a", "account"], azp: "app-a" })
    );
    expect(user.id).toBe("u");
    expect(
      (await verify(await issuer.signTestToken({ sub: "u", aud: "app-a", azp: "app-a" }))).id
    ).toBe("u");
  });

  it("answers 503 (retryable) for a rotated key seen during the JWKS cooldown, 401 once cooled", async () => {
    const own = await createDevIssuer({ users: [], clients: [CLIENT] });
    await own.listen();
    const cooled = createVerifier({
      jwksUri: `${own.issuer()}/jwks`,
      issuer: own.issuer(),
      audience: "app-a",
      jwksCooldownMs: 200,
    });
    await cooled(await own.signTestToken({ sub: "u", aud: "app-a" })); // primes the cache
    await own.rotateKey();
    const rotated = await own.signTestToken({ sub: "u", aud: "app-a" });
    const during = await cooled(rotated).catch((e: unknown) => e);
    expect(during).toMatchObject({ code: 503, message: MESSAGES.authUnavailable });
    await new Promise((r) => setTimeout(r, 250));
    expect((await cooled(rotated)).id).toBe("u");

    await new Promise((r) => setTimeout(r, 250));
    const foreign = await createDevIssuer({ issuer: own.issuer(), users: [], clients: [] });
    await expectInvalid(cooled(await foreign.signTestToken({ sub: "u", aud: "app-a" })));
    await own.app.close();
  });
});
