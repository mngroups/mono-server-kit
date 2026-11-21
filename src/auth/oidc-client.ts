import { z } from "zod";
import { AppError } from "../errors.js";
import { MESSAGES } from "../messages.js";
import { isGrantReason, reasonMessage } from "./reasons.js";

/** What login / refresh / callback return to the FE (the shape `@mono/auth` expects). */
export type TokenSet = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  refresh_expires_in: number;
};

const discoverySchema = z.object({
  issuer: z.string(),
  jwks_uri: z.string(),
  token_endpoint: z.string(),
  authorization_endpoint: z.string().optional(),
  revocation_endpoint: z.string().optional(),
  end_session_endpoint: z.string().optional(),
});

export type Discovery = z.infer<typeof discoverySchema>;

/** monexa-auth's org-switch grant type. */
export const ORG_SWITCH_GRANT = "urn:monexa:params:oauth:grant-type:org-switch";

const orgsResponseSchema = z.object({
  data: z.array(z.object({ id: z.string(), name: z.string() })),
});

const tokenResponseSchema = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1),
  expires_in: z.number(),
  refresh_expires_in: z.number().optional(),
});

export type OidcClientOptions = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Per call to the central service. Default 10s. */
  timeoutMs?: number;
  /** Provider orgs endpoint. Default `<issuer origin>/api/me/orgs`. */
  orgsEndpoint?: string;
  /** Used when the provider omits `refresh_expires_in`. Default 86400 (1 day). */
  refreshExpiresInFallback?: number;
};

export interface OidcClient {
  discovery(): Promise<Discovery>;
  /** `orgId` asks the provider for that org; it decides eligibility. */
  passwordGrant(username: string, password: string, orgId?: string): Promise<TokenSet>;
  codeGrant(code: string, codeVerifier: string, redirectUri: string): Promise<TokenSet>;
  refreshGrant(refreshToken: string): Promise<TokenSet>;
  /** monexa-auth's org switch: new tokens for `orgId`, the old refresh token is spent. */
  orgSwitchGrant(refreshToken: string, orgId: string): Promise<TokenSet>;
  /** The caller's orgs from the provider's orgs endpoint. */
  listOrgs(accessToken: string): Promise<{ id: string; name: string }[]>;
  revoke(refreshToken: string): Promise<void>;
  authorizeUrl(p: {
    redirectUri: string;
    codeChallenge: string;
    state: string;
    idpHint?: string;
    idpHintParam?: string;
  }): Promise<string>;
  endSessionUrl(p: { postLogoutRedirectUri?: string }): Promise<string | null>;
}

const unavailable = (cause: unknown) => new AppError(503, MESSAGES.authUnavailable, { cause });
const misconfigured = (cause: unknown) => new AppError(500, MESSAGES.internal, { cause });

/**
 * Talks to the central OIDC provider as a confidential client
 * (`client_secret_basic`). Outages (network, timeout, 5xx) become 503 so the FE
 * never logs a user out for them; a rejected grant becomes 401.
 */
export function createOidcClient(opts: OidcClientOptions): OidcClient {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const refreshFallback = opts.refreshExpiresInFallback ?? 86400;
  const basic = `Basic ${Buffer.from(`${opts.clientId}:${opts.clientSecret}`).toString("base64")}`;
  let cached: Promise<Discovery> | null = null;

  async function call(input: string, init: RequestInit = {}): Promise<Response> {
    try {
      const res = await fetch(input, { ...init, signal: AbortSignal.timeout(timeoutMs) });
      if (res.status >= 500) throw new Error(`central auth answered ${res.status}`);
      return res;
    } catch (error) {
      throw unavailable(error);
    }
  }

  function discovery(): Promise<Discovery> {
    cached ??= (async () => {
      const res = await call(`${opts.issuer.replace(/\/$/, "")}/.well-known/openid-configuration`);
      const parsed = discoverySchema.safeParse(await res.json().catch(() => null));
      if (!res.ok || !parsed.success) {
        throw unavailable(new Error(`discovery failed (HTTP ${res.status})`));
      }
      return parsed.data;
    })().catch((error: unknown) => {
      cached = null;
      throw error;
    });
    return cached;
  }

  // #region handbook:refresh-proxy
  async function grant(params: Record<string, string>, rejectedMessage: string): Promise<TokenSet> {
    const { token_endpoint } = await discovery();
    const res = await call(token_endpoint, {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params),
    });
    const body: unknown = await res.json().catch(() => null);
    if (!res.ok) {
      const { error, error_description: reason } =
        (body as { error?: string; error_description?: unknown } | null) ?? {};
      if (error === "invalid_grant") {
        // A known reason reaches the FE as data.reason; anything else keeps today's copy.
        if (isGrantReason(reason)) {
          throw new AppError(401, reasonMessage(reason), { data: { reason } });
        }
        throw new AppError(401, rejectedMessage);
      }
      throw misconfigured(new Error(`token endpoint ${res.status}: ${error ?? "no error code"}`));
    }
    const parsed = tokenResponseSchema.safeParse(body);
    if (!parsed.success) throw misconfigured(parsed.error);
    return {
      access_token: parsed.data.access_token,
      refresh_token: parsed.data.refresh_token,
      expires_in: parsed.data.expires_in,
      refresh_expires_in: parsed.data.refresh_expires_in ?? refreshFallback,
    };
  }
  // #endregion

  return {
    discovery,
    passwordGrant: (username, password, orgId) =>
      grant(
        {
          grant_type: "password",
          username,
          password,
          scope: "openid",
          ...(orgId !== undefined && { org_id: orgId }),
        },
        MESSAGES.invalidCredentials
      ),
    codeGrant: (code, codeVerifier, redirectUri) =>
      grant(
        {
          grant_type: "authorization_code",
          code,
          code_verifier: codeVerifier,
          redirect_uri: redirectUri,
        },
        MESSAGES.invalidToken
      ),
    refreshGrant: (refreshToken) =>
      grant({ grant_type: "refresh_token", refresh_token: refreshToken }, MESSAGES.invalidToken),
    orgSwitchGrant: (refreshToken, orgId) =>
      grant(
        { grant_type: ORG_SWITCH_GRANT, refresh_token: refreshToken, org_id: orgId },
        MESSAGES.invalidToken
      ),

    async listOrgs(accessToken) {
      const endpoint = opts.orgsEndpoint ?? new URL("/api/me/orgs", opts.issuer).toString();
      const res = await call(endpoint, { headers: { authorization: `Bearer ${accessToken}` } });
      if (res.status === 401) throw new AppError(401, MESSAGES.invalidToken);
      const parsed = orgsResponseSchema.safeParse(await res.json().catch(() => null));
      if (!res.ok || !parsed.success) throw unavailable(new Error(`orgs endpoint ${res.status}`));
      return parsed.data.data;
    },

    async revoke(refreshToken) {
      try {
        const { revocation_endpoint } = await discovery();
        if (!revocation_endpoint) return;
        await call(revocation_endpoint, {
          method: "POST",
          headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ token: refreshToken, token_type_hint: "refresh_token" }),
        });
      } catch {
        // Best effort: an unrevoked refresh token still expires on its own.
      }
    },

    async authorizeUrl(p) {
      const { authorization_endpoint } = await discovery();
      if (!authorization_endpoint) {
        throw misconfigured(new Error("provider has no authorization_endpoint"));
      }
      const target = new URL(authorization_endpoint);
      target.search = new URLSearchParams({
        response_type: "code",
        client_id: opts.clientId,
        redirect_uri: p.redirectUri,
        scope: "openid",
        code_challenge: p.codeChallenge,
        code_challenge_method: "S256",
        state: p.state,
      }).toString();
      if (p.idpHint) target.searchParams.set(p.idpHintParam ?? "kc_idp_hint", p.idpHint);
      return target.toString();
    },

    async endSessionUrl(p) {
      const { end_session_endpoint } = await discovery();
      if (!end_session_endpoint) return null;
      const target = new URL(end_session_endpoint);
      target.searchParams.set("client_id", opts.clientId);
      if (p.postLogoutRedirectUri) {
        target.searchParams.set("post_logout_redirect_uri", p.postLogoutRedirectUri);
      }
      return target.toString();
    },
  };
}
