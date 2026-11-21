import * as dev from "../dev/index.js";
import * as kit from "../index.js";

describe("public API", () => {
  it("exports every production building block from the root", () => {
    for (const name of [
      "createServerOptions",
      "requestId",
      "envelope",
      "envelopeSchema",
      "errorHandler",
      "AppError",
      "MESSAGES",
      "defineEnv",
      "auth",
      "validateAuthOptions",
      "createPresigner",
      "health",
      "startServer",
    ]) {
      expect(kit, name).toHaveProperty(name);
    }
  });

  it("keeps the dev issuer out of the root entry", () => {
    expect(kit).not.toHaveProperty("createDevIssuer");
    expect(dev).toHaveProperty("createDevIssuer");
  });
});
