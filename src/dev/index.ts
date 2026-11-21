// Development-only entry: a stub OIDC issuer. Refuses to start when NODE_ENV=production.
export {
  createDevIssuer,
  type DevClient,
  type DevIssuer,
  type DevIssuerOptions,
  type DevOrg,
  type DevUser,
  ORG_SWITCH_GRANT,
} from "./issuer.js";
