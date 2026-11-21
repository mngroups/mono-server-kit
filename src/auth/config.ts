export type AuthMode = "credentials" | "sso";

export type AuthOptions = {
  /** `credentials`: in-app login form proxied to the central service. `sso`: OIDC redirect + PKCE. */
  mode: AuthMode;
  /** Central OIDC issuer (discovery at `${issuer}/.well-known/openid-configuration`). */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Defaults to the discovery document's `jwks_uri`. */
  jwksUri?: string;
  /** sso only: skip the central login page and go straight to this IdP (e.g. "google"). */
  idpHint?: string;
  /** Query parameter carrying `idpHint`. Default `kc_idp_hint`. */
  idpHintParam?: string;
  /** sso only: the FE callback URLs allowed as `redirect_uri`. */
  redirectUris?: string[];
  /** sso only: where the central end-session page sends the user afterwards. */
  postLogoutRedirectUri?: string;
  /** Per call to the central service. Default 10s. */
  timeoutMs?: number;
  /** See `createVerifier`. Default 30s. */
  jwksCooldownMs?: number;
};

/** Fails fast at registration on a config that cannot work. */
export function validateAuthOptions(o: AuthOptions): void {
  if (o.mode !== "credentials" && o.mode !== "sso") {
    throw new Error(`auth: mode must be "credentials" or "sso", got "${String(o.mode)}"`);
  }
  if (!URL.canParse(o.issuer)) throw new Error("auth: issuer must be an absolute URL");
  if (!o.clientSecret) throw new Error("auth: clientSecret is required");
  if (o.idpHint && o.mode !== "sso") throw new Error('auth: idpHint requires mode "sso"');
  if (o.mode === "sso" && !o.redirectUris?.length) {
    throw new Error('auth: mode "sso" requires at least one redirectUris entry');
  }
}
