import { createHash, randomBytes } from "node:crypto";

/** A PKCE pair: 43-char base64url verifier and its S256 challenge (RFC 7636). */
export function createPkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}
