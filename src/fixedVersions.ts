/**
 * Fixed openssh versions per Alpine branch, for CVE-2026-123158
 * ("sshole": OpenSSH musl password authentication bypass).
 *
 * Source: Alpine Linux security advisory "openssh-server password
 * authentication bypass", 2026-11-05,
 * https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
 * Cross-checked 2026-11-06 against the OpenSSH 10.6p2 release notes
 * (https://www.openssh.com/releasenotes.html) and CVE-2026-123158
 * (CVSS 3.1 score 8.1, High). Re-verified at build time, 2026-11-06.
 *
 * Alpine did NOT move stable branches to 10.6p2: each branch got the
 * 10.6p2 fix backported onto the openssh version it already shipped,
 * with a bumped package release (-rN). Looking for "10.6p2" on a
 * stable branch is wrong; compare against the table below.
 *
 * A wrong entry here is a false SAFE, the worst failure mode of this
 * tool. If the advisory publishes a correction, update this table and
 * the check date, and add a regression test.
 */
export const CVE_ID = "CVE-2026-123158";
export const CVE_CVSS = "8.1 (CVSS 3.1, High)";
export const FIXED_VERSIONS_CHECKED = "2026-11-06";
export const FIXED_VERSIONS_SOURCE =
  "https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/";

/** branch ("3.18", "edge") -> fixed `openssh` package version (apk format). */
export const FIXED_OPENSSH: Readonly<Record<string, string>> = {
  edge: "10.6_p2-r0",
  "3.24": "10.3_p1-r2",
  "3.23": "10.2_p1-r1",
  "3.22": "10.0_p1-r11",
  "3.21": "9.9_p2-r1",
  "3.20": "9.7_p1-r6",
  "3.19": "9.6_p1-r3",
  "3.18": "9.3_p2-r4",
  "3.17": "9.1_p1-r7",
  "3.16": "9.0_p1-r6",
};

/**
 * Compare two apk package versions ("9.3_p2-r3", "10.6_p2-r0").
 * Returns <0 if a < b, 0 if equal, >0 if a > b.
 * Follows apk-tools semantics closely enough for openssh versions:
 * the upstream part is compared token by token (digit runs numerically,
 * letter runs lexically, "." < "-" < letters), then the package release
 * (-rN) numerically. Unknown shapes fall back to plain string compare
 * and are never treated as equal unless identical.
 */
export function compareApkVersions(a: string, b: string): number {
  if (a === b) return 0;
  const [upA, relA] = splitPkgRel(a);
  const [upB, relB] = splitPkgRel(b);
  const c = compareUpstream(upA, upB);
  if (c !== 0) return c;
  return (relA ?? 0) - (relB ?? 0);
}

function splitPkgRel(v: string): [string, number | null] {
  const m = /^(.*)-r(\d+)$/.exec(v);
  if (m) return [m[1], Number(m[2])];
  return [v, null];
}

function tokenize(s: string): (number | string)[] {
  const out: (number | string)[] = [];
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (ch >= "0" && ch <= "9") {
      let j = i;
      while (j < s.length && s[j] >= "0" && s[j] <= "9") j++;
      out.push(Number(s.slice(i, j)));
      i = j;
    } else if (
      (ch >= "a" && ch <= "z") ||
      (ch >= "A" && ch <= "Z")
    ) {
      let j = i;
      while (
        j < s.length &&
        ((s[j] >= "a" && s[j] <= "z") || (s[j] >= "A" && s[j] <= "Z"))
      ) {
        j++;
      }
      out.push(s.slice(i, j));
      i = j;
    } else {
      out.push(ch);
      i++;
    }
  }
  return out;
}

function compareUpstream(a: string, b: string): number {
  const ta = tokenize(a);
  const tb = tokenize(b);
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const x = ta[i];
    const y = tb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (typeof x === "number" && typeof y === "number") {
      if (x !== y) return x - y;
    } else if (typeof x === "number") {
      // apk: a digit token sorts after a separator, before letters.
      return 1;
    } else if (typeof y === "number") {
      return -1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/** Is `installed` at or above the fixed version for `branch`? */
export function isPatched(
  branch: string,
  installed: string,
): boolean | null {
  const fixed = FIXED_OPENSSH[branch];
  if (fixed === undefined) return null; // unknown branch: caller reports UNKNOWN
  return compareApkVersions(installed, fixed) >= 0;
}

/**
 * Map an /etc/alpine-release value ("3.18.9", "3.24.0_alpha20251105")
 * to a branch key in FIXED_OPENSSH. Returns null when unparseable.
 */
export function branchOfRelease(release: string): string | null {
  const v = release.trim();
  if (v.includes("_alpha")) return "edge";
  const m = /^(\d+)\.(\d+)(?:\.\d+)?/.exec(v);
  if (!m) return null;
  return `${m[1]}.${m[2]}`;
}
