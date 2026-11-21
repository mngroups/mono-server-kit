import closeWithGrace from "close-with-grace";
import type { FastifyInstance } from "fastify";

/**
 * Docker entry only: listens, and on SIGTERM/SIGINT (or a fatal error) closes
 * the app — finishing in-flight requests and running onClose hooks such as
 * closing the DB pool — within `graceMs`. Vercel never calls this.
 */
export async function startServer(
  app: FastifyInstance,
  opts: { port: number; host?: string; graceMs?: number }
): Promise<void> {
  await app.listen({ port: opts.port, host: opts.host ?? "0.0.0.0" });
  closeWithGrace({ delay: opts.graceMs ?? 10_000 }, async ({ err }) => {
    if (err) app.log.error({ err });
    await app.close();
  });
}
