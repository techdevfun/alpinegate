/**
 * The first-hour stopgap playbook. PRINT ONLY — alpinegate never edits
 * sshd_config and never restarts a daemon by itself.
 *
 * Steps follow the Alpine advisory of 2026-11-05:
 * https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
 * Upgrading the package does NOT restart the running daemon, so every
 * path ends with an explicit restart.
 */
import type { Detection } from "./detect.js";

export function playbookText(d: Detection): string {
  const lines: string[] = [];
  lines.push(`alpinegate playbook — ${d.target}`);
  lines.push(`verdict: ${d.verdict}`);
  lines.push("");
  if (d.verdict === "SAFE") {
    lines.push("This target is not exposed to CVE-2026-123158.");
    for (const r of d.reasons) lines.push(`- ${r}`);
    lines.push("");
    lines.push("Still worth doing on a schedule:");
    lines.push("  1. Keep openssh updated: apk upgrade -U -a");
    lines.push("  2. Restart sshd after every openssh upgrade:");
    lines.push("     rc-service sshd restart");
    lines.push("  3. Check for past logins: grep 'Accepted password for'");
    lines.push("     /var/log/messages — any accepted password login for an");
    lines.push("     account with no password means the box was compromised.");
    return lines.join("\n");
  }
  if (d.verdict === "UNKNOWN") {
    lines.push("alpinegate cannot tell whether this target is exposed.");
    for (const r of d.reasons) lines.push(`- ${r}`);
    lines.push("");
    lines.push("Do not treat UNKNOWN as SAFE. Fix the visibility gap first:");
    lines.push("  - Make /etc/shadow and /etc/ssh/sshd_config readable to the");
    lines.push("    account running the scan, or scan a copy of the rootfs.");
    lines.push("  - If this is not Alpine at all, this CVE does not apply.");
    return lines.join("\n");
  }

  // EXPOSED or AT-RISK: the stopgap.
  lines.push("CVE-2026-123158 — an attacker who can reach your SSH port can");
  lines.push("log in without knowing any password (257–1024 byte password,");
  lines.push("musl crypt() returns \"*\", matching the stored \"*\" field).");
  lines.push("");
  lines.push("Do this in the first hour, in order:");
  lines.push("");
  lines.push("1. Close the hole NOW (no package needed):");
  lines.push("   mkdir -p /etc/ssh/sshd_config.d");
  lines.push("   echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/00-no-passwords.conf");
  lines.push("   # Alpine's default sshd_config reads that directory from 3.19 on;");
  lines.push("   # on older releases also edit /etc/ssh/sshd_config directly.");
  lines.push("   sshd -t && rc-service sshd restart");
  lines.push("   sshd -T | grep -i passwordauthentication   # must print: no");
  lines.push("");
  lines.push("   Make sure key login works FIRST, and keep your current");
  lines.push("   session open until a new login is tested.");
  lines.push("");
  lines.push("2. Then upgrade and restart (the upgrade alone does NOT");
  lines.push("   replace the running daemon):");
  lines.push("   apk upgrade -U -a");
  lines.push("   rc-service sshd restart");
  if (d.fixedVersion !== null) {
    lines.push(
      `   # fixed openssh for Alpine ${d.branch ?? "?"}: ${d.fixedVersion}`,
    );
  }
  lines.push("");
  lines.push("3. Check whether you were already attacked:");
  lines.push("   grep 'Accepted password for' /var/log/messages");
  lines.push("   Any accepted password login for an account with no");
  lines.push("   password (root, alpine, any key-only user) means the");
  lines.push("   machine was compromised — treat it as such, rotate keys,");
  lines.push("   review doas use and recently created users and files.");
  lines.push("");
  lines.push("Why this works: with password logins off, the bypass has");
  lines.push("nothing to compare against; with the fixed package, sshd");
  lines.push("refuses stored fields shorter than four characters.");
  return lines.join("\n");
}
