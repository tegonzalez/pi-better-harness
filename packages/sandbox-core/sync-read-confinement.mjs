// Vendors read-confinement.ts into pi-better-sandbox (single-file copy, like shared-sandbox-core.ts).
// Usage: node packages/sandbox-core/sync-read-confinement.mjs [--check]
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const here = import.meta.dirname;
export const target = resolve(here, "../pi-better-sandbox/shared-read-confinement.ts");
export function vendoredContent() {
  const source = readFileSync(resolve(here, "read-confinement.ts"), "utf8");
  return `// Generated from packages/sandbox-core/read-confinement.ts. Do not edit directly.\n${source.replace('from "./index.ts"', 'from "./shared-sandbox-core.ts"')}`;
}
if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  if (process.argv.includes("--check")) {
    if (readFileSync(target, "utf8") !== vendoredContent()) { console.error("shared-read-confinement.ts is stale"); process.exit(1); }
  } else writeFileSync(target, vendoredContent());
}
