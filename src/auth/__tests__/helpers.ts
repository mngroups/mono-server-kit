import Fastify from "fastify";
import { createDevIssuer, type DevIssuer, type DevUser } from "../../dev/issuer.js";
import { envelope } from "../../plugins/envelope.js";
import { errorHandler } from "../../plugins/error-handler.js";
import { createServerOptions } from "../../server-options.js";
import type { AuthOptions } from "../config.js";
import { auth } from "../plugin.js";

export const REDIRECT = "http://localhost:3000/auth/callback";
export const CLIENT = { clientId: "app-a", clientSecret: "secret-a", redirectUris: [REDIRECT] };
export const USERS: DevUser[] = [
  {
    username: "admin",
    password: "admin123",
    sub: "user-1",
    permissions: { "app-a": ["example:all"] },
  },
  {
    username: "other",
    password: "other123",
    sub: "user-2",
    permissions: { "app-a": ["other:view"] },
  },
  { username: "nobody", password: "nobody123", sub: "user-3", permissions: {} },
  {
    username: "multi",
    password: "multi123",
    sub: "user-4",
    permissions: { "app-a": ["example:all"] },
    orgs: [
      { id: "org-a", name: "Org A" },
      { id: "org-b", name: "Org B", permissions: { "app-a": ["b:view"] } },
    ],
  },
  {
    username: "fresh",
    password: "fresh123",
    sub: "user-5",
    permissions: {},
    mustChangePassword: true,
  },
];

export async function startIssuer(): Promise<DevIssuer> {
  const issuer = await createDevIssuer({ users: USERS, clients: [CLIENT] });
  await issuer.listen();
  return issuer;
}

export async function buildApp(issuer: string, over: Partial<AuthOptions> = {}) {
  const app = Fastify(createServerOptions({ logLevel: "silent" }));
  await app.register(envelope);
  await app.register(errorHandler);
  await app.register(auth, {
    mode: "credentials",
    issuer,
    clientId: CLIENT.clientId,
    clientSecret: CLIENT.clientSecret,
    ...over,
  } as AuthOptions);
  app.get("/items", { preHandler: app.requirePermission("example.item:view") }, (_req, reply) => {
    reply.ok({ items: [] });
  });
  app.get(
    "/either",
    { preHandler: app.requirePermission("nope:view", "other:view") },
    (_r, reply) => {
      reply.ok(null);
    }
  );
  app.get(
    "/public-guarded",
    { config: { public: true }, preHandler: app.requirePermission("example:view") },
    (_r, reply) => {
      reply.ok(null);
    }
  );
  app.get("/me", (req, reply) => {
    reply.ok({ id: req.user?.id });
  });
  app.get("/open", { config: { public: true } }, (req, reply) => {
    reply.ok({ user: req.user });
  });
  return app;
}

export const json = { "content-type": "application/json" };
