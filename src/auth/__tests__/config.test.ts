import { type AuthOptions, validateAuthOptions } from "../config.js";

const base: AuthOptions = {
  mode: "credentials",
  issuer: "http://localhost:9000",
  clientId: "app-a",
  clientSecret: "secret",
};

describe("validateAuthOptions", () => {
  it("accepts a valid credentials config and a valid sso config", () => {
    expect(() => validateAuthOptions(base)).not.toThrow();
    expect(() =>
      validateAuthOptions({
        ...base,
        mode: "sso",
        redirectUris: ["http://x/cb"],
        idpHint: "google",
      })
    ).not.toThrow();
  });

  it("rejects an org hint outside sso mode", () => {
    expect(() => validateAuthOptions({ ...base, orgHint: "pt-maju" })).toThrow(
      /orgHint requires mode "sso"/
    );
  });

  it("rejects an IdP hint outside sso mode", () => {
    expect(() => validateAuthOptions({ ...base, idpHint: "google" })).toThrow(
      /idpHint requires mode "sso"/
    );
  });

  it("rejects sso without redirect URIs", () => {
    expect(() => validateAuthOptions({ ...base, mode: "sso" })).toThrow(/redirectUris/);
    expect(() => validateAuthOptions({ ...base, mode: "sso", redirectUris: [] })).toThrow(
      /redirectUris/
    );
  });

  it("rejects a relative issuer and an empty client secret", () => {
    expect(() => validateAuthOptions({ ...base, issuer: "/auth" })).toThrow(/issuer/);
    expect(() => validateAuthOptions({ ...base, clientSecret: "" })).toThrow(/clientSecret/);
  });

  it("rejects an unknown mode", () => {
    expect(() => validateAuthOptions({ ...base, mode: "magic" as "sso" })).toThrow(/mode/);
  });
});
