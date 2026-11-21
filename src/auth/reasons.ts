import { MESSAGES } from "../messages.js";

/** Machine-readable grant refusals the provider sends as `error_description`. */
export const GRANT_REASONS = [
  "invalid_credentials",
  "no_app_access",
  "password_change_required",
  "org_not_eligible",
  "google_required",
] as const;

export type GrantReason = (typeof GRANT_REASONS)[number];

const REASON_MESSAGES: Record<GrantReason, string> = {
  invalid_credentials: MESSAGES.invalidCredentials,
  no_app_access: MESSAGES.noAppAccess,
  password_change_required: MESSAGES.passwordChangeRequired,
  org_not_eligible: MESSAGES.orgNotEligible,
  google_required: MESSAGES.googleRequired,
};

export function isGrantReason(value: unknown): value is GrantReason {
  return typeof value === "string" && (GRANT_REASONS as readonly string[]).includes(value);
}

/** The Indonesian message the FE shows for a refusal reason. */
export function reasonMessage(reason: GrantReason): string {
  return REASON_MESSAGES[reason];
}
