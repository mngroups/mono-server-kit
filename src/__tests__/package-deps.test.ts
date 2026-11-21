import { readdirSync, readFileSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { join } from "node:path";

const root = join(import.meta.dirname, "..", "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === "__tests__" ? [] : sourceFiles(path);
    return path.endsWith(".ts") ? [path] : [];
  });
}

function packageName(specifier: string): string {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? `${parts[0]}/${parts[1]}` : (parts[0] as string);
}

describe("package.json", () => {
  it("declares every package the shipped code imports at runtime", () => {
    const declared = new Set([
      ...Object.keys(pkg.dependencies ?? {}),
      ...Object.keys(pkg.peerDependencies ?? {}),
    ]);
    const missing = new Set<string>();
    for (const file of sourceFiles(join(root, "src"))) {
      const code = readFileSync(file, "utf8");
      // Value imports only: `import type` is erased from the build.
      for (const [, specifier] of code.matchAll(/^import (?!type )[^;]*?from "([^".][^"]*)";/gms)) {
        const name = packageName(specifier as string);
        if (name.startsWith("node:") || builtinModules.includes(name)) continue;
        if (!declared.has(name)) missing.add(name);
      }
    }
    expect([...missing]).toEqual([]);
  });
});
