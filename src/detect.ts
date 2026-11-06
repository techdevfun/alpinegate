/**
 * The five-condition check for CVE-2026-123158 ("sshole").
 *
 * All five must hold for EXPOSED (Alpine advisory, 2026-11-05):
 *   1. Alpine / musl (an /etc/alpine-release exists)
 *   2. A vulnerable openssh version (below the fixed version for the
 *      branch, per the Alpine advisory — re-verified 2026-11-06)
 *   3. No PAM (openssh-server without PAM, or openssh-server-pam
 *      with UsePAM no)
 *   4. PasswordAuthentication yes (the OpenSSH default)
 *   5. At least one account with password field exactly `*`, AND at
 *      least one other account with a $5$ or $6$ hash (the salt donor)
 *
 * The tool never prints a password hash: only the hash-type prefix
 * ($5$ / $6$) is recorded. It never attempts an SSH login.
 */
import { readdirSync, readFileSync } from "node:fs";
import {
  FIXED_OPENSSH,
  branchOfRelease,
  compareApkVersions,
  isPatched,
} from "./fixedVersions.js";
import type { Rootfs } from "./rootfs.js";
import { DirRootfs } from "./rootfs.js";

export type Verdict = "EXPOSED" | "AT-RISK" | "SAFE" | "UNKNOWN";

export interface Condition {
  id: string;
  name: string;
  met: boolean;
  detail: string;
}

export interface Detection {
  target: string;
  alpineRelease: string | null;
  branch: string | null;
  opensshVersion: string | null;
  opensshServerVersion: string | null;
  fixedVersion: string | null;
  pamInUse: boolean;
  passwordAuth: boolean;
  passwordAuthSource: string;
  starAccounts: string[];
  saltDonor: boolean;
  saltDonorHashType: string | null;
  sshdInstalled: boolean;
  sshdRunning: boolean | null;
  shadowReadable: boolean;
  conditions: Condition[];
  verdict: Verdict;
  reasons: string[];
}

interface ApkEntry {
  name: string;
  version: string;
}

/** Parse /lib/apk/db/installed into name -> version (P: / V: lines). */
export function parseApkDb(text: string): Map<string, string> {
  const out = new Map<string, string>();
  let name: string | null = null;
  for (const line of text.split("\n")) {
    if (line.startsWith("P:")) name = line.slice(2).trim();
    else if (line.startsWith("V:") && name !== null) {
      out.set(name, line.slice(2).trim());
      name = null;
    } else if (line === "") {
      name = null;
    }
  }
  return out;
}

export function parseApkDbEntries(text: string): ApkEntry[] {
  return [...parseApkDb(text).entries()].map(([name, version]) => ({
    name,
    version,
  }));
}

interface SshdConfig {
  passwordAuth: boolean;
  usePam: boolean;
  source: string;
}

/**
 * Parse sshd_config the way sshd itself resolves it: the FIRST
 * occurrence of a keyword wins, Include lines expand in place
 * (sorted), and only the global context is read — directives inside
 * a Match block apply to matching users only and are out of scope
 * for v0.1.0 (see README, "Honest limits"). Absent keywords fall
 * back to the OpenSSH defaults: PasswordAuthentication yes,
 * UsePAM no.
 */
export function parseSshdConfig(rootfs: Rootfs): SshdConfig {
  const found = new Map<string, string>();
  const seen = new Set<string>();

  const readInto = (path: string): void => {
    if (seen.has(path)) return;
    seen.add(path);
    const text = rootfs.readText(path);
    if (text === null) return;
    for (const raw of text.split("\n")) {
      const line = raw.replace(/#.*$/, "").trim();
      if (line === "") continue;
      const [keyword, ...rest] = line.split(/\s+/);
      const lower = keyword.toLowerCase();
      if (lower === "match") break; // Match block: stop, global only
      if (lower === "include") {
        for (const pattern of rest) expandInclude(rootfs, pattern, readInto);
        continue;
      }
      if (!found.has(lower)) {
        found.set(lower, rest.join(" "));
      }
    }
  };

  readInto("/etc/ssh/sshd_config");
  const passwordAuth =
    found.get("passwordauthentication")?.toLowerCase() !== "no";
  const usePam = found.get("usepam")?.toLowerCase() === "yes";
  const source = found.has("passwordauthentication")
    ? "/etc/ssh/sshd_config (or drop-in)"
    : "OpenSSH default (no PasswordAuthentication line)";
  return { passwordAuth, usePam, source };
}

function expandInclude(
  rootfs: Rootfs,
  pattern: string,
  readInto: (path: string) => void,
): void {
  // Only the drop-in directory form is expanded; anything else is a
  // literal path. Patterns never leave the rootfs.
  if (!pattern.includes("*")) {
    readInto(pattern);
    return;
  }
  const dir = pattern.slice(0, pattern.lastIndexOf("/"));
  const names = rootfs.listDir(dir) ?? [];
  const suffix = pattern.slice(pattern.lastIndexOf("/") + 1);
  const re = new RegExp(
    "^" + suffix.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$",
  );
  for (const name of names.sort()) {
    if (re.test(name)) readInto(`${dir}/${name}`);
  }
}

export interface ShadowInfo {
  readable: boolean;
  starAccounts: string[];
  saltDonor: boolean;
  saltDonorHashType: string | null;
}

/** Read /etc/shadow. Only account names and hash-type prefixes leave. */
export function parseShadow(rootfs: Rootfs): ShadowInfo {
  const exists = rootfs.exists("/etc/shadow");
  const text = rootfs.readText("/etc/shadow");
  if (!exists || text === null) {
    return {
      readable: false,
      starAccounts: [],
      saltDonor: false,
      saltDonorHashType: null,
    };
  }
  const starAccounts: string[] = [];
  let saltDonor = false;
  let saltDonorHashType: string | null = null;
  for (const line of text.split("\n")) {
    const parts = line.split(":");
    if (parts.length < 2) continue;
    const [user, field] = parts;
    if (field === "*") starAccounts.push(user);
    if (field.startsWith("$5$") || field.startsWith("$6$")) {
      saltDonor = true;
      saltDonorHashType ??= field.slice(0, 3);
    }
  }
  return { readable: true, starAccounts, saltDonor, saltDonorHashType };
}

function sshdRunningOnLiveHost(): boolean | null {
  try {
    for (const pid of readdirSync("/proc")) {
      if (!/^\d+$/.test(pid)) continue;
      try {
        const comm = readFileSync(`/proc/${pid}/comm`, "utf8").trim();
        if (comm === "sshd") return true;
      } catch {
        // process vanished; ignore
      }
    }
    return false;
  } catch {
    return null;
  }
}

export function analyze(rootfs: Rootfs): Detection {
  const target = rootfs.label;
  const reasons: string[] = [];

  const releaseRaw = rootfs.readText("/etc/alpine-release");
  const alpineRelease = releaseRaw === null ? null : releaseRaw.trim();
  const branch =
    alpineRelease === null ? null : branchOfRelease(alpineRelease);

  const apkText = rootfs.readText("/lib/apk/db/installed");
  const pkgs = apkText === null ? new Map<string, string>() : parseApkDb(apkText);
  const opensshVersion = pkgs.get("openssh") ?? null;
  const opensshServerVersion =
    pkgs.get("openssh-server") ?? pkgs.get("openssh-server-pam") ?? null;
  const installedVersion = opensshVersion ?? opensshServerVersion;

  const sshdInstalled =
    rootfs.exists("/usr/sbin/sshd") ||
    opensshServerVersion !== null ||
    pkgs.has("openssh-server") ||
    pkgs.has("openssh-server-pam");

  const pamPackageInstalled =
    pkgs.has("openssh-server-pam") && !pkgs.has("openssh-server");
  const cfg = parseSshdConfig(rootfs);
  // A non-PAM sshd build ignores UsePAM entirely; PAM only counts
  // when the PAM build is installed AND UsePAM is yes.
  const pamInUse = pamPackageInstalled && cfg.usePam;

  const shadow = parseShadow(rootfs);

  const sshdRunning =
    rootfs instanceof DirRootfs && rootfs.isLiveHost
      ? sshdRunningOnLiveHost()
      : null;

  const fixedVersion =
    branch !== null ? (FIXED_OPENSSH[branch] ?? null) : null;
  const patched =
    branch !== null && installedVersion !== null
      ? isPatched(branch, installedVersion)
      : null;

  const conditions: Condition[] = [
    {
      id: "alpine-musl",
      name: "Alpine / musl (alpine-release present)",
      met: alpineRelease !== null,
      detail: alpineRelease ?? "no /etc/alpine-release found",
    },
    {
      id: "vulnerable-openssh",
      name: "Vulnerable openssh version",
      met:
        installedVersion !== null &&
        fixedVersion !== null &&
        compareApkVersions(installedVersion, fixedVersion) < 0,
      detail:
        installedVersion === null
          ? "no openssh version in apk database"
          : fixedVersion === null
            ? `${installedVersion} (branch ${branch ?? "?"}: no fixed version known)`
            : `${installedVersion} (fixed for ${branch}: ${fixedVersion})`,
    },
    {
      id: "no-pam",
      name: "No PAM",
      met: !pamInUse,
      detail: pamInUse
        ? "openssh-server-pam installed with UsePAM yes"
        : pamPackageInstalled
          ? "openssh-server-pam installed but UsePAM no"
          : "openssh-server built without PAM",
    },
    {
      id: "password-auth",
      name: "PasswordAuthentication yes",
      met: cfg.passwordAuth,
      detail: cfg.passwordAuth
        ? "yes (or OpenSSH default)"
        : "no — password logins disabled",
    },
    {
      id: "star-plus-donor",
      name: "`*` account + $5$/$6$ salt donor",
      met:
        shadow.readable &&
        shadow.starAccounts.length > 0 &&
        shadow.saltDonor,
      detail: !shadow.readable
        ? "/etc/shadow not readable"
        : shadow.starAccounts.length === 0
          ? "no account with password field `*`"
          : !shadow.saltDonor
            ? "no account with a $5$/$6$ hash (no salt donor)"
            : `* accounts: ${shadow.starAccounts.join(", ")}; donor hash type ${shadow.saltDonorHashType}`,
    },
  ];

  let verdict: Verdict;
  if (!sshdInstalled) {
    verdict = "SAFE";
    reasons.push("no sshd installed in this target");
  } else if (alpineRelease === null) {
    verdict = "UNKNOWN";
    reasons.push("not an Alpine rootfs: no /etc/alpine-release");
  } else if (branch === null) {
    verdict = "UNKNOWN";
    reasons.push(`unparseable /etc/alpine-release: ${alpineRelease}`);
  } else if (installedVersion === null) {
    verdict = "UNKNOWN";
    reasons.push("no openssh version in the apk database");
  } else if (patched === null) {
    verdict = "UNKNOWN";
    reasons.push(`no fixed-version entry for branch ${branch}`);
  } else if (pamInUse) {
    verdict = "SAFE";
    reasons.push("PAM in use (openssh-server-pam + UsePAM yes)");
  } else if (patched) {
    verdict = "SAFE";
    reasons.push(
      `openssh ${installedVersion} is at or above the fixed version ${fixedVersion} for Alpine ${branch}`,
    );
  } else if (!shadow.readable) {
    verdict = "UNKNOWN";
    reasons.push("/etc/shadow not readable — cannot confirm the last condition");
  } else if (conditions.every((c) => c.met)) {
    verdict = "EXPOSED";
    reasons.push(
      `all five conditions hold: Alpine ${branch}, openssh ${installedVersion} < fixed ${fixedVersion}, no PAM, password auth on, ` +
        `* accounts (${shadow.starAccounts.join(", ")}) + ${shadow.saltDonorHashType} salt donor`,
    );
  } else {
    verdict = "AT-RISK";
    const missing = conditions.filter((c) => !c.met).map((c) => c.name);
    reasons.push(
      `vulnerable openssh ${installedVersion} present, but not all conditions hold (missing: ${missing.join("; ")})`,
    );
  }

  return {
    target,
    alpineRelease,
    branch,
    opensshVersion,
    opensshServerVersion,
    fixedVersion,
    pamInUse,
    passwordAuth: cfg.passwordAuth,
    passwordAuthSource: cfg.source,
    starAccounts: shadow.starAccounts,
    saltDonor: shadow.saltDonor,
    saltDonorHashType: shadow.saltDonorHashType,
    sshdInstalled,
    sshdRunning,
    shadowReadable: shadow.readable,
    conditions,
    verdict,
    reasons,
  };
}
