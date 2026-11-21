import { z } from "zod";
import { defineEnv } from "../env.js";

const schema = z.object({
  PORT: z.coerce.number().int().positive(),
  AUTH_CLIENT_SECRET: z.string().min(32),
  AUTH_ISSUER: z.url(),
});

describe("defineEnv", () => {
  it("returns the parsed, typed values", () => {
    const env = defineEnv(schema, {
      PORT: "8080",
      AUTH_CLIENT_SECRET: "s".repeat(32),
      AUTH_ISSUER: "http://localhost:9000",
    });
    expect(env.PORT).toBe(8080);
    expect(env.AUTH_ISSUER).toBe("http://localhost:9000");
  });

  it("lists every invalid key, one per line", () => {
    expect(() => defineEnv(schema, { AUTH_CLIENT_SECRET: "s".repeat(32) })).toThrowError(
      /Invalid environment variables:\nPORT: .+\nAUTH_ISSUER: .+/
    );
  });

  it("never includes the offending value in the message", () => {
    const secret = "super-secret-but-too-short";
    let message = "";
    try {
      defineEnv(schema, { PORT: "8080", AUTH_ISSUER: "http://x", AUTH_CLIENT_SECRET: secret });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toContain("AUTH_CLIENT_SECRET");
    expect(message).not.toContain(secret);
  });

  it("reads process.env by default", () => {
    process.env.KIT_TEST_VALUE = "yes";
    expect(defineEnv(z.object({ KIT_TEST_VALUE: z.string() })).KIT_TEST_VALUE).toBe("yes");
    delete process.env.KIT_TEST_VALUE;
  });
});
