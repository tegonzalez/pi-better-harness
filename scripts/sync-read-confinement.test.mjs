// The vendored read-confinement copy in pi-better-sandbox must match its source.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");

test("shared-read-confinement.ts is in sync with sandbox-core/read-confinement.ts", () => {
  const result = spawnSync(process.execPath, [resolve(root, "packages/sandbox-core/sync-read-confinement.mjs"), "--check"], { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
});

test("pi-better-sandbox pretest/pretypecheck/prepack run the read-confinement sync", () => {
  const scripts = JSON.parse(readFileSync(resolve(root, "packages/pi-better-sandbox/package.json"), "utf8")).scripts;
  for (const name of ["pretest", "pretypecheck", "prepack"]) assert.match(scripts[name], /sync-read-confinement\.mjs/, name);
});
