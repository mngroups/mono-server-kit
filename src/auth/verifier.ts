import { createRemoteJWKSet, errors, jwtVerify } from "jose";
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
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: opts.issuer,
        audience: opts.audience,
        algorithms: ["RS256", "ES256"],
        clockTolerance: 30,
        requiredClaims: ["sub", "exp"],
      });
      return {
        id: payload.sub as string,
        permissions: toPermissions(payload.permissions),
        claims: payload,
      };
    } catch (error) {
      if (isJwksOutage(error)) throw new AppError(503, MESSAGES.authUnavailable, { cause: error });
      throw new AppError(401, MESSAGES.invalidToken, { cause: error });
    }
  };
}
// #endregion
