import type { z } from "zod";

/**
 * Parses environment variables against a Zod schema at boot. The error lists
 * every invalid key with its issue, never the value, so secrets stay out of logs.
 */
export function defineEnv<S extends z.ZodObject>(
  schema: S,
  source: NodeJS.ProcessEnv = process.env
): z.infer<S> {
  const result = schema.safeParse(source);
  if (result.success) return result.data;
  const lines = result.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`);
  throw new Error(`Invalid environment variables:\n${lines.join("\n")}`);
}
