import { createRemoteJWKSet, errors, type JWTPayload, jwtVerify } from "jose";
import { AppError } from "../errors.js";
import { MESSAGES } from "../messages.js";
import type { AuthUser } from "./types.js";

export type VerifierOptions = {
  jwksUri: string;
  issuer: string;
  audience: string;
  /** Minimum gap between JWKS refetches on an unknown `kid`. Default 30s (jose's default). */
  jwksCooldownMs?: number;
};

/**
 * Whether verification failed because the key set could not be fetched (an
 * outage: 503) rather than because the token is bad (401).
 */
function isJwksOutage(error: unknown): boolean {
  if (!(error instanceof errors.JOSEError)) return true; // network errors from fetch
  return (
    error instanceof errors.JWKSTimeout ||
    error instanceof errors.JWKSInvalid ||
    error.code === "ERR_JOSE_GENERIC" // non-200 JWKS response
  );
}

/**
 * The `permissions` claim belongs to the client the token was issued to. A
 * token for another client that merely lists this app in `aud` must not carry
 * that client's permissions here: require `azp` to be this app, and require
 * `azp` whenever `aud` names several audiences.
 */
function isIssuedTo(payload: JWTPayload, clientId: string): boolean {
  if (payload.azp !== undefined) return payload.azp === clientId;
  return !Array.isArray(payload.aud) || payload.aud.length === 1;
}

function toPermissions(claim: unknown): ReadonlySet<string> {
  if (!Array.isArray(claim)) return new Set();
  return new Set(claim.filter((p): p is string => typeof p === "string"));
}

// #region handbook:auth-verify
/**
 * Verifies central access tokens locally against the issuer's JWKS (cached,
 * refetched on an unknown `kid`), checking signature, `iss`, `aud` and `exp`
 * with 30s clock tolerance. A bad token is a 401 (the FE refreshes on it); an
 * unreachable key set is a 503 (never log users out over an outage).
 */
export function createVerifier(opts: VerifierOptions): (token: string) => Promise<AuthUser> {
  const jwks = createRemoteJWKSet(new URL(opts.jwksUri), {
    cooldownDuration: opts.jwksCooldownMs ?? 30_000,
  });
  return async (token) => {
    // jose won't refetch the key set inside the cooldown. An unknown `kid` then may be
    // a freshly rotated key, so answer a retryable 503 rather than a logout-inducing 401.
    const wasCoolingDown = jwks.coolingDown;
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: opts.issuer,
        audience: opts.audience,
        algorithms: ["RS256", "ES256"],
        clockTolerance: 30,
        requiredClaims: ["sub", "exp"],
      });
      if (!isIssuedTo(payload, opts.audience)) {
        throw new errors.JWTClaimValidationFailed(
          "token was issued to another client",
          payload,
          "azp"
        );
      }
      return {
        id: payload.sub as string,
        permissions: toPermissions(payload.permissions),
        claims: payload,
      };
    } catch (error) {
      if (isJwksOutage(error) || (wasCoolingDown && error instanceof errors.JWKSNoMatchingKey)) {
        throw new AppError(503, MESSAGES.authUnavailable, { cause: error });
      }
      throw new AppError(401, MESSAGES.invalidToken, { cause: error });
    }
  };
}
// #endregion
