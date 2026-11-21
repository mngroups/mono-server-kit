import Fastify from "fastify";

type GraceFn = (arg: { err?: Error }) => Promise<void>;
const captured: { fn?: GraceFn; opts?: { delay?: number } } = {};
vi.mock("close-with-grace", () => ({
  default: (opts: { delay?: number }, fn: GraceFn) => {
    captured.opts = opts;
    captured.fn = fn;
    return { close: () => {}, uninstall: () => {} };
  },
}));

const { startServer } = await import("../lifecycle.js");

describe("startServer", () => {
  it("listens, then closes the app when the grace handler fires", async () => {
    const app = Fastify();
    let closed = false;
    app.addHook("onClose", async () => {
      closed = true;
    });
    await startServer(app, { port: 0, host: "127.0.0.1", graceMs: 5000 });
    expect(app.server.address()).not.toBeNull();
    expect(captured.opts?.delay).toBe(5000);
    await captured.fn?.({});
    expect(closed).toBe(true);
  });

  it("defaults to host 0.0.0.0 and a 10s grace period", async () => {
    const app = Fastify();
    await startServer(app, { port: 0 });
    expect((app.server.address() as { address: string }).address).toBe("0.0.0.0");
    expect(captured.opts?.delay).toBe(10_000);
    await app.close();
  });

  it("logs the fatal error that triggered the shutdown", async () => {
    const app = Fastify();
    const logged: unknown[] = [];
    app.log.error = ((obj: unknown) => {
      logged.push(obj);
    }) as typeof app.log.error;
    await startServer(app, { port: 0, host: "127.0.0.1" });
    const err = new Error("boom");
    await captured.fn?.({ err });
    expect(logged).toEqual([{ err }]);
  });
});
