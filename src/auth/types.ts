import type { JWTPayload } from "jose";

/** The caller, from a verified central access token. */
export type AuthUser = {
  /** The token's `sub`. */
  id: string;
  /** This app's permissions (`permissions` claim, scoped by `aud`). */
  permissions: ReadonlySet<string>;
  claims: JWTPayload;
  /** The token's `org_id`, when it is a string. */
  orgId?: string;
  /** The token's `org_name`, when it is a string. */
  orgName?: string;
};
