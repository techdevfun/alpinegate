/**
 * Live smoke tests. Offline-safe; they only assert the CLI behaves
 * sanely on the machine it runs on. Skipped softly when the
 * environment cannot answer (no /proc, no fixture dir).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "dist", "cli.js");

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

test("live: --help and --version exit 0", () => {
  assert.equal(run(["--help"]).status, 0);
  assert.match(run(["--version"]).stdout, /alpinegate 0\.1\.0/);
});

test("live: scanning the host root reports a verdict, never crashes", () => {
  const r = run(["scan", "/"]);
  // This machine is not Alpine: expect UNKNOWN (no alpine-release),
  // exit 0 (not EXPOSED). Either way the CLI must not crash.
  assert.ok([0, 1, 2].includes(r.status));
  assert.match(r.stdout + r.stderr, /UNKNOWN|SAFE|EXPOSED|AT-RISK|alpinegate/);
  if (r.status === 0) assert.match(r.stdout, /UNKNOWN|SAFE/);
});
