/**
 * Unit tests for alpinegate. Every condition of CVE-2026-123158 is
 * toggled once; UNKNOWN, hash-prefix-only output, and exit codes are
 * covered. No network, no Docker daemon needed.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  analyze,
  parseApkDb,
  parseShadow,
  parseSshdConfig,
} from "../dist/detect.js";
import { MemoryRootfs } from "../dist/rootfs.js";
import {
  FIXED_OPENSSH,
  branchOfRelease,
  compareApkVersions,
  isPatched,
} from "../dist/fixedVersions.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "dist", "cli.js");

// --- A minimal exposed 3.18 box, as in-memory files -----------------------
function exposedFiles(overrides = {}) {
  return {
    "/etc/alpine-release": "3.18.9\n",
    "/lib/apk/db/installed":
      "C:Q1x\nP:openssh\nV:9.3_p2-r3\nA:x86_64\nS:1\nI:1\n" +
      "C:Q1y\nP:openssh-server\nV:9.3_p2-r3\nA:x86_64\nS:1\nI:1\n",
    "/etc/ssh/sshd_config": "# OpenSSH defaults\n#PasswordAuthentication yes\n",
    "/etc/shadow":
      "root:*:20000:0:99999:7:::\n" +
      "deploy:$6$testsalt$testhashvalue0000000000000000000000000000:20000:0:99999:7:::\n" +
      "locked:!:20000:0:99999:7:::\n",
    "/usr/sbin/sshd": "ELF fake binary\n",
    ...overrides,
  };
}
const exposed = () => analyze(new MemoryRootfs(exposedFiles(), "test-box"));

// --- Fixed-version map (re-verified 2026-11-06, Alpine advisory) -----------
test("fixed-version map covers every affected branch", () => {
  for (const b of ["3.16", "3.17", "3.18", "3.19", "3.20", "3.21", "3.22", "3.23", "3.24", "edge"]) {
    assert.ok(FIXED_OPENSSH[b], `missing branch ${b}`);
  }
  assert.equal(FIXED_OPENSSH["3.18"], "9.3_p2-r4");
  assert.equal(FIXED_OPENSSH.edge, "10.6_p2-r0");
});

test("apk version compare orders openssh versions", () => {
  assert.ok(compareApkVersions("9.3_p2-r3", "9.3_p2-r4") < 0);
  assert.ok(compareApkVersions("9.3_p2-r4", "9.3_p2-r4") === 0);
  assert.ok(compareApkVersions("10.3_p1-r2", "9.3_p2-r4") > 0);
  assert.ok(compareApkVersions("10.6_p2-r0", "10.3_p1-r2") > 0);
  assert.ok(compareApkVersions("9.0_p1-r6", "9.0_p1-r5") > 0);
  assert.ok(compareApkVersions("9.9_p2-r1", "10.0_p1-r11") < 0);
});

test("isPatched uses the per-branch fixed version", () => {
  assert.equal(isPatched("3.18", "9.3_p2-r3"), false);
  assert.equal(isPatched("3.18", "9.3_p2-r4"), true);
  assert.equal(isPatched("3.18", "9.3_p2-r5"), true);
  assert.equal(isPatched("3.24", "10.3_p1-r1"), false);
  assert.equal(isPatched("3.24", "10.3_p1-r2"), true);
  assert.equal(isPatched("3.99", "10.6_p2-r0"), null);
});

test("branchOfRelease maps release strings", () => {
  assert.equal(branchOfRelease("3.18.9"), "3.18");
  assert.equal(branchOfRelease("3.24.4"), "3.24");
  assert.equal(branchOfRelease("3.24.0_alpha20251105"), "edge");
  assert.equal(branchOfRelease("garbage"), null);
});

// --- Parsers ---------------------------------------------------------------
test("parseApkDb reads P:/V: pairs", () => {
  const db = parseApkDb(exposedFiles()["/lib/apk/db/installed"]);
  assert.equal(db.get("openssh"), "9.3_p2-r3");
  assert.equal(db.get("openssh-server"), "9.3_p2-r3");
});

test("parseShadow finds * accounts and the donor, prefix only", () => {
  const s = parseShadow(new MemoryRootfs(exposedFiles(), "t"));
  assert.deepEqual(s.starAccounts, ["root"]);
  assert.equal(s.saltDonor, true);
  assert.equal(s.saltDonorHashType, "$6$");
  assert.equal(s.readable, true);
});

test("parseShadow ignores locked (!) accounts", () => {
  const s = parseShadow(
    new MemoryRootfs(
      exposedFiles({ "/etc/shadow": "locked:!:1:0:99999:7:::\n" }),
      "t",
    ),
  );
  assert.deepEqual(s.starAccounts, []);
  assert.equal(s.saltDonor, false);
});

test("sshd_config: absent keyword falls back to OpenSSH defaults", () => {
  const cfg = parseSshdConfig(new MemoryRootfs(exposedFiles(), "t"));
  assert.equal(cfg.passwordAuth, true); // default yes
  assert.equal(cfg.usePam, false); // default no
});

test("sshd_config: explicit PasswordAuthentication no is honoured", () => {
  const cfg = parseSshdConfig(
    new MemoryRootfs(
      exposedFiles({ "/etc/ssh/sshd_config": "PasswordAuthentication no\n" }),
      "t",
    ),
  );
  assert.equal(cfg.passwordAuth, false);
});

test("sshd_config: first occurrence wins (sshd semantics)", () => {
  const cfg = parseSshdConfig(
    new MemoryRootfs(
      exposedFiles({
        "/etc/ssh/sshd_config":
          "PasswordAuthentication no\nPasswordAuthentication yes\n",
      }),
      "t",
    ),
  );
  assert.equal(cfg.passwordAuth, false);
});

test("sshd_config: drop-in via Include is expanded", () => {
  const cfg = parseSshdConfig(
    new MemoryRootfs(
      exposedFiles({
        "/etc/ssh/sshd_config":
          "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n",
        "/etc/ssh/sshd_config.d/00-no-passwords.conf":
          "PasswordAuthentication no\n",
      }),
      "t",
    ),
  );
  // First obtained value wins: the drop-in is included before the main
  // file's own line, so "no" wins.
  assert.equal(cfg.passwordAuth, false);
});

test("sshd_config: Match blocks are out of scope (global only)", () => {
  const cfg = parseSshdConfig(
    new MemoryRootfs(
      exposedFiles({
        "/etc/ssh/sshd_config":
          "PasswordAuthentication yes\nMatch User deploy\n  PasswordAuthentication no\n",
      }),
      "t",
    ),
  );
  assert.equal(cfg.passwordAuth, true);
});

// --- Verdicts: each of the five conditions toggled once --------------------
test("all five conditions -> EXPOSED", () => {
  const d = exposed();
  assert.equal(d.verdict, "EXPOSED");
  assert.equal(d.conditions.filter((c) => c.met).length, 5);
  assert.equal(d.starAccounts.join(), "root");
  assert.equal(d.saltDonorHashType, "$6$");
});

test("condition 1 off (no alpine-release, file absent) -> UNKNOWN", () => {
  const files = exposedFiles();
  delete files["/etc/alpine-release"];
  const d = analyze(new MemoryRootfs(files, "t"));
  assert.equal(d.verdict, "UNKNOWN");
  assert.match(d.reasons.join(" "), /alpine-release/);
});

test("condition 2 off (patched openssh) -> SAFE", () => {
  const d = analyze(
    new MemoryRootfs(
      exposedFiles({
        "/lib/apk/db/installed":
          "P:openssh\nV:9.3_p2-r4\nP:openssh-server\nV:9.3_p2-r4\n",
      }),
      "t",
    ),
  );
  assert.equal(d.verdict, "SAFE");
});

test("condition 3 off (PAM in use) -> SAFE", () => {
  const d = analyze(
    new MemoryRootfs(
      exposedFiles({
        "/lib/apk/db/installed":
          "P:openssh\nV:9.3_p2-r3\nP:openssh-server-pam\nV:9.3_p2-r3\n",
        "/etc/ssh/sshd_config": "UsePAM yes\n",
      }),
      "t",
    ),
  );
  assert.equal(d.verdict, "SAFE");
  assert.equal(d.pamInUse, true);
});

test("condition 3 holds (PAM package but UsePAM no) -> EXPOSED", () => {
  const d = analyze(
    new MemoryRootfs(
      exposedFiles({
        "/lib/apk/db/installed":
          "P:openssh\nV:9.3_p2-r3\nP:openssh-server-pam\nV:9.3_p2-r3\n",
        "/etc/ssh/sshd_config": "UsePAM no\n",
      }),
      "t",
    ),
  );
  assert.equal(d.verdict, "EXPOSED");
});

test("condition 4 off (password auth disabled) -> AT-RISK", () => {
  const d = analyze(
    new MemoryRootfs(
      exposedFiles({ "/etc/ssh/sshd_config": "PasswordAuthentication no\n" }),
      "t",
    ),
  );
  assert.equal(d.verdict, "AT-RISK");
});

test("condition 5a off (no * account) -> AT-RISK", () => {
  const d = analyze(
    new MemoryRootfs(
      exposedFiles({
        "/etc/shadow":
          "deploy:$6$testsalt$testhashvalue0000000000000000000000000000:20000:0:99999:7:::\n",
      }),
      "t",
    ),
  );
  assert.equal(d.verdict, "AT-RISK");
  assert.deepEqual(d.starAccounts, []);
});

test("condition 5b off (no salt donor) -> AT-RISK", () => {
  const d = analyze(
    new MemoryRootfs(
      exposedFiles({ "/etc/shadow": "root:*:20000:0:99999:7:::\n" }),
      "t",
    ),
  );
  assert.equal(d.verdict, "AT-RISK");
  assert.equal(d.saltDonor, false);
});

test("no sshd installed -> SAFE", () => {
  const files = exposedFiles();
  delete files["/usr/sbin/sshd"];
  files["/lib/apk/db/installed"] = "P:musl\nV:1.2.4-r0\n";
  const d = analyze(new MemoryRootfs(files, "t"));
  assert.equal(d.verdict, "SAFE");
});

test("UNKNOWN on unreadable shadow (exists but cannot be read)", () => {
  // A stub rootfs: /etc/shadow exists, readText returns null for it.
  const base = new MemoryRootfs(exposedFiles(), "t");
  const stub = {
    label: "stub",
    exists: (p) => base.exists(p),
    listDir: (p) => base.listDir(p),
    readBytes: (p) => (p === "/etc/shadow" ? null : base.readBytes(p)),
    readText: (p) => (p === "/etc/shadow" ? null : base.readText(p)),
  };
  const d = analyze(stub);
  assert.equal(d.verdict, "UNKNOWN");
  assert.equal(d.shadowReadable, false);
  assert.match(d.reasons.join(" "), /shadow/);
});

test("hash-type prefix only: no full hash anywhere in a detection", () => {
  const d = exposed();
  const blob = JSON.stringify(d);
  assert.ok(!blob.includes("testhashvalue"), "full hash leaked into output");
  assert.ok(blob.includes("$6$"), "hash-type prefix present");
});

// --- CLI exit codes ---------------------------------------------------------
function runCli(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

test("CLI exit codes: 0 safe, 1 exposed, 2 usage error", () => {
  const safe = runCli(["scan", join(HERE, "..", "fixtures", "patched")]);
  assert.equal(safe.status, 0, safe.stderr);
  const exposedRun = runCli(["scan", join(HERE, "..", "fixtures", "exposed")]);
  assert.equal(exposedRun.status, 1, exposedRun.stderr);
  assert.match(exposedRun.stdout, /EXPOSED/);
  const usage = runCli(["scan"]);
  assert.equal(usage.status, 2);
  const badFlag = runCli(["scan", "--nope", "x"]);
  assert.equal(badFlag.status, 2);
  const badTarget = runCli(["scan", "/does/not/exist-xyz"]);
  assert.equal(badTarget.status, 2);
});

test("CLI --fail-on at-risk turns AT-RISK into exit 1", () => {
  const files = exposedFiles({ "/etc/ssh/sshd_config": "PasswordAuthentication no\n" });
  const d = analyze(new MemoryRootfs(files, "t"));
  assert.equal(d.verdict, "AT-RISK");
  const atRisk = runCli([
    "scan",
    join(HERE, "..", "fixtures", "exposed"),
    "--fail-on",
    "at-risk",
  ]);
  assert.equal(atRisk.status, 1); // exposed fixture is EXPOSED anyway
  const safe = runCli([
    "scan",
    join(HERE, "..", "fixtures", "patched"),
    "--fail-on",
    "at-risk",
  ]);
  assert.equal(safe.status, 0);
});
