/**
 * End-to-end tests: the real CLI against the real fixtures built from
 * the Alpine 3.18.9 minirootfs + real openssh APKs
 * (fixtures/PROVENANCE.md). No network, no Docker daemon required
 * for the file/dir paths; the Docker-socket path is tested against a
 * fake unix-socket server serving the same fixture tarball.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync, spawn } from "node:child_process";
import { createServer } from "node:net";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "dist", "cli.js");
const EXPOSED = join(ROOT, "fixtures", "exposed");
const PATCHED = join(ROOT, "fixtures", "patched");
const EXPOSED_TAR = join(ROOT, "fixtures", "alpine-3.18-exposed.tar.gz");
const PATCHED_TAR = join(ROOT, "fixtures", "alpine-3.18-patched.tar.gz");

function run(args, env = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

test("e2e: scan of the real exposed rootfs dir -> EXPOSED, exit 1", () => {
  const r = run(["scan", EXPOSED]);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stdout, /3\.18\.9/);
  assert.match(r.stdout, /9\.3_p2-r3/);
  assert.match(r.stdout, /EXPOSED/);
  assert.match(r.stdout, /root/);
});

test("e2e: scan of the real patched rootfs dir -> SAFE, exit 0", () => {
  const r = run(["scan", PATCHED]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /9\.3_p2-r4/);
  assert.match(r.stdout, /SAFE/);
});

test("e2e: scan of both fixtures together lists both verdicts", () => {
  const r = run(["scan", EXPOSED, PATCHED]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /EXPOSED/);
  assert.match(r.stdout, /SAFE/);
});

test("e2e: docker-save tarballs give the same verdicts as the dirs", () => {
  const r = run(["scan", EXPOSED_TAR, PATCHED_TAR]);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stdout, /EXPOSED/);
  assert.match(r.stdout, /SAFE/);
});

test("e2e: check --format json is machine-readable and hash-free", () => {
  const r = run(["check", EXPOSED, "--format", "json"]);
  assert.equal(r.status, 1);
  const doc = JSON.parse(r.stdout);
  assert.equal(doc.cve, "CVE-2026-123158");
  assert.equal(doc.results[0].verdict, "EXPOSED");
  assert.equal(doc.results[0].salt_donor_hash_type, "$6$");
  // The real fixture shadow contains a full $6$ hash; it must never
  // appear in any CLI output.
  const shadow = readFileSync(join(EXPOSED, "etc", "shadow"), "utf8");
  const deployLine = shadow.split("\n").find((l) => l.startsWith("deploy:"));
  const fullHash = deployLine.split(":")[1];
  assert.ok(fullHash.length > 20, "fixture hash unexpectedly short");
  assert.ok(!r.stdout.includes(fullHash), "full password hash leaked");
  assert.ok(!r.stdout.includes(fullHash.slice(4, 24)), "hash fragment leaked");
});

test("e2e: playbook on the exposed fixture names the fix + restart", () => {
  const r = run(["playbook", EXPOSED]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /PasswordAuthentication no/);
  assert.match(r.stdout, /rc-service sshd restart/);
  assert.match(r.stdout, /apk upgrade/);
  assert.match(r.stdout, /9\.3_p2-r4/);
});

test("e2e: playbook on the patched fixture says SAFE, no stopgap", () => {
  const r = run(["playbook", PATCHED]);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /not exposed/);
  assert.ok(!r.stdout.includes("00-no-passwords.conf"));
});

test("e2e: unknown target is a usage error (exit 2), never SAFE", () => {
  const r = run(["scan", "/nonexistent-target-xyz"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /alpinegate/);
});

test("e2e: local Docker image via a fake daemon socket", async () => {
  const sock = join(tmpdir(), `alpinegate-test-${process.pid}.sock`);
  const tarball = readFileSync(EXPOSED_TAR);
  const server = createServer((socket) => {
    let buf = Buffer.alloc(0);
    // Keep the connection open between requests: Node's http agent
    // reuses it (keep-alive) for the second call, so answering the
    // first request with socket.end() makes the second fail with
    // "socket hang up" (seen on Node 20.x). Only end after /get.
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        const head = buf.toString("utf8");
        const end = head.indexOf("\r\n\r\n");
        if (end === -1) return;
        const firstLine = head.split("\r\n")[0];
        buf = buf.subarray(end + 4); // consume this request (GET: no body)
        if (firstLine.includes("/json")) {
          const body = JSON.stringify({ Id: "sha256:fake", RepoTags: ["alpine:3.18"] });
          socket.write(
            `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
          );
        } else if (firstLine.includes("/get")) {
          socket.write(
            `HTTP/1.1 200 OK\r\nContent-Type: application/x-tar\r\nContent-Length: ${tarball.length}\r\n\r\n`,
          );
          socket.write(tarball);
          socket.end();
        } else {
          socket.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        }
      }
    });
  });
  await new Promise((resolve) => server.listen(sock, resolve));
  try {
    // Async spawn: spawnSync would block this process's event loop,
    // starving the fake daemon server in the same process.
    const r = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [CLI, "scan", "alpine:3.18"], {
        env: { ...process.env, DOCKER_SOCK: sock },
      });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (c) => (stdout += c));
      child.stderr.on("data", (c) => (stderr += c));
      child.on("error", reject);
      child.on("close", (status) => resolve({ status, stdout, stderr }));
    });
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stdout, /EXPOSED/);
    assert.match(r.stdout, /docker:alpine:3\.18/);
  } finally {
    server.close();
  }
});

test("e2e: missing Docker socket is exit 2, not a false verdict", () => {
  const r = run(["scan", "alpine:3.18"], {
    DOCKER_SOCK: "/tmp/definitely-no-socket-here.sock",
  });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /no Docker daemon socket/);
  assert.ok(!r.stdout.includes("SAFE"), "must not report SAFE on error");
});
