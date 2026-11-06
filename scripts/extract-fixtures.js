#!/usr/bin/env node
/**
 * Extract the committed fixture tarballs into fixtures/exposed and
 * fixtures/patched. The extracted trees are derived artifacts: they
 * are gitignored and never published (the batch push cannot represent
 * symlinks, which a real Alpine rootfs is full of). Idempotent: skips
 * a tree that already exists and looks complete. Runs automatically
 * as `npm run pretest` before `npm test`.
 */
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIX = join(ROOT, "fixtures");

const JOBS = [
  ["alpine-3.18-exposed.tar.gz", "exposed"],
  ["alpine-3.18-patched.tar.gz", "patched"],
];

for (const [tar, dir] of JOBS) {
  const dest = join(FIX, dir);
  const marker = join(dest, "etc", "alpine-release");
  if (existsSync(marker)) {
    console.log(`fixtures/${dir}: already extracted, skipping`);
    continue;
  }
  console.log(`extracting fixtures/${tar} -> fixtures/${dir}`);
  // Two steps: the docker-save tarball holds layer.tar; the layer tar
  // holds the rootfs tree. System tar preserves the symlinks.
  const tmp = mkdtempSync(join(tmpdir(), "alpinegate-layer-"));
  const layerPath = join(tmp, "layer.tar");
  execFileSync(
    "sh",
    [
      "-c",
      `tar -xzOf ${join(FIX, tar)} layer.tar > ${layerPath} && mkdir -p ${dest} && tar --no-same-owner -xf ${layerPath} -C ${dest}`,
    ],
    { stdio: "inherit" },
  );
  rmSync(tmp, { recursive: true, force: true });
  if (!existsSync(marker)) {
    console.error(`extract-fixtures: ${dir} still incomplete after extraction`);
    process.exit(1);
  }
}
console.log("fixtures ready");
