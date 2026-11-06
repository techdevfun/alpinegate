#!/usr/bin/env node
/**
 * alpinegate — which of my Alpine images and containers is actually
 * exposed to the OpenSSH musl password bypass (CVE-2026-123158)?
 *
 * Read-only, zero network, zero dependencies. It checks five live
 * conditions (Alpine/musl, vulnerable openssh version, no PAM,
 * PasswordAuthentication yes, a `*` account plus a $5$/$6$ salt
 * donor) and reports EXPOSED / AT-RISK / SAFE / UNKNOWN. It never
 * attempts an SSH login and never prints a password hash.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { analyze, type Detection } from "./detect.js";
import { exportImage, DockerError } from "./docker.js";
import { jsonText, tableText } from "./output.js";
import { playbookText } from "./playbook.js";
import {
  DirRootfs,
  DockerSaveRootfs,
  TarRootfs,
  parseTar,
  type Rootfs,
} from "./rootfs.js";

const VERSION = "0.1.0";

const USAGE = `alpinegate ${VERSION} — OpenSSH musl bypass exposure check (CVE-2026-123158)

Usage:
  alpinegate scan [targets...] [--format table|json] [--fail-on exposed|at-risk]
  alpinegate check <target> [--format table|json]
  alpinegate playbook <target>
  alpinegate --help | --version

Targets (v0.1.0, all read-only, no network):
  <path>          a rootfs directory, or "/" for the live host
  <file.tar>      an image tarball (docker save), plain or gzipped
  <image>         a local Docker image name (read via /var/run/docker.sock)

Exit codes: 0 = no EXPOSED target; 1 = at least one EXPOSED target
(or AT-RISK with --fail-on at-risk); 2 = usage or config error.`;

function fail(message: string): never {
  console.error(`alpinegate: ${message}`);
  process.exit(2);
}

function isDockerSave(data: Buffer): boolean {
  try {
    const raw =
      data.length > 2 && data[0] === 0x1f && data[1] === 0x8b
        ? gunzipSync(data)
        : data;
    const outer = parseTar(raw);
    return outer.has("manifest.json");
  } catch {
    return false;
  }
}

async function resolveTarget(arg: string): Promise<Rootfs> {
  if (existsSync(arg)) {
    const st = statSync(arg);
    if (st.isDirectory()) return new DirRootfs(arg);
    if (st.isFile()) {
      const data = readFileSync(arg);
      if (isDockerSave(data)) return new DockerSaveRootfs(arg, data);
      return new TarRootfs(arg, data);
    }
    fail(`not a directory or file: ${arg}`);
  }
  // Otherwise: a local Docker image name.
  try {
    const data = await exportImage(arg);
    return new DockerSaveRootfs(`docker:${arg}`, data);
  } catch (e) {
    if (e instanceof DockerError) fail(e.message);
    throw e;
  }
}

interface Options {
  format: "table" | "json";
  failOn: "exposed" | "at-risk";
}

function parseOptions(args: string[]): { targets: string[]; opts: Options } {
  const targets: string[] = [];
  const opts: Options = { format: "table", failOn: "exposed" };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--format") {
      const v = args[++i];
      if (v !== "table" && v !== "json") {
        fail(`--format must be table or json, got: ${v ?? "(missing)"}`);
      }
      opts.format = v;
    } else if (a.startsWith("--format=")) {
      const v = a.slice("--format=".length);
      if (v !== "table" && v !== "json") fail(`--format must be table or json, got: ${v}`);
      opts.format = v;
    } else if (a === "--fail-on") {
      const v = args[++i];
      if (v !== "exposed" && v !== "at-risk") {
        fail(`--fail-on must be exposed or at-risk, got: ${v ?? "(missing)"}`);
      }
      opts.failOn = v;
    } else if (a.startsWith("--fail-on=")) {
      const v = a.slice("--fail-on=".length);
      if (v !== "exposed" && v !== "at-risk") {
        fail(`--fail-on must be exposed or at-risk, got: ${v}`);
      }
      opts.failOn = v;
    } else if (a.startsWith("-")) {
      fail(`unknown option: ${a}`);
    } else {
      targets.push(a);
    }
  }
  return { targets, opts };
}

function exitFor(results: Detection[], failOn: Options["failOn"]): number {
  const bad = results.some(
    (d) =>
      d.verdict === "EXPOSED" ||
      (failOn === "at-risk" && d.verdict === "AT-RISK"),
  );
  return bad ? 1 : 0;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    console.log(USAGE);
    process.exit(argv.length === 0 ? 2 : 0);
  }
  if (argv[0] === "--version" || argv[0] === "-V") {
    console.log(`alpinegate ${VERSION}`);
    process.exit(0);
  }

  const [cmd, ...rest] = argv;
  if (cmd === "scan") {
    const { targets, opts } = parseOptions(rest);
    if (targets.length === 0) fail("scan needs at least one target");
    const results: Detection[] = [];
    for (const t of targets) results.push(analyze(await resolveTarget(t)));
    console.log(opts.format === "json" ? jsonText(results) : tableText(results));
    process.exit(exitFor(results, opts.failOn));
  }
  if (cmd === "check") {
    const { targets, opts } = parseOptions(rest);
    if (targets.length !== 1) fail("check needs exactly one target");
    const d = analyze(await resolveTarget(targets[0]));
    console.log(opts.format === "json" ? jsonText([d]) : tableText([d]));
    process.exit(exitFor([d], opts.failOn));
  }
  if (cmd === "playbook") {
    const { targets } = parseOptions(rest);
    if (targets.length !== 1) fail("playbook needs exactly one target");
    const d = analyze(await resolveTarget(targets[0]));
    console.log(playbookText(d));
    process.exit(0);
  }
  fail(`unknown command: ${cmd}\n${USAGE}`);
}

main().catch((e: unknown) => {
  console.error(`alpinegate: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(2);
});
