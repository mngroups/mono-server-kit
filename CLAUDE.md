# @mono/server-kit: agent guide

Shared Fastify 5 plugins for Monexa backends. ESM, TypeScript (NodeNext), Node 24, pnpm 10.33.0. See `README.md` for the public API.

## Commands

| Command              | What it does                                   |
| -------------------- | ---------------------------------------------- |
| `pnpm test:coverage` | Vitest. Coverage must stay at or above **80%** |
| `pnpm typecheck`     | `tsc --noEmit`                                 |
| `pnpm lint`          | Biome. Use `pnpm lint:fix` to apply fixes      |
| `pnpm build`         | Emits `dist/` (`tsconfig.build.json`)          |

## Rules

- Responses always use the envelope `{ success, message, code, data, request_id, timestamp }`, with `code` equal to the HTTP status. Contract shapes come from `@mono/auth` and are never copied.
- Status mapping: validation 422, bad token 401, permission 403, unknown route 404, central-service outage **503 (never 401)**, everything else 500.
- User-facing copy is Indonesian and lives only in `src/messages.ts`.
- Auth is secure by default. Only routes with `config: { public: true }` skip the token check.
- Never log tokens, passwords or secrets. Extend `REDACT_PATHS` in `src/server-options.ts` when a new secret field appears.
- No cross-request in-memory state, except the JWKS and discovery caches, so the plugins run unchanged on Vercel Functions.
- `src/dev/` (the stub issuer) must never be imported from the root entry.
- Tests use `app.inject()` and the real dev issuer over HTTP. Avoid mocks except for process-level hooks (`close-with-grace`).
- Keep `// #region handbook:*` markers on the key flows. The Monexa handbook generator embeds them.
