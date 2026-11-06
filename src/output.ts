/** Table and JSON rendering. Never prints a password hash. */
import type { Detection } from "./detect.js";
import { CVE_ID, CVE_CVSS, FIXED_VERSIONS_CHECKED } from "./fixedVersions.js";

function cell(v: string | null, fallback = "-"): string {
  return v === null || v === "" ? fallback : v;
}

export function tableText(results: Detection[]): string {
  const headers = [
    "TARGET",
    "ALPINE",
    "OPENSSH",
    "PAM",
    "PASSAUTH",
    "`*` ACCOUNTS",
    "DONOR",
    "VERDICT",
  ];
  const rows = results.map((d) => [
    d.target,
    cell(d.alpineRelease),
    d.opensshVersion ?? cell(d.opensshServerVersion),
    d.pamInUse ? "yes" : "no",
    d.passwordAuth ? "yes" : "no",
    d.starAccounts.length > 0 ? d.starAccounts.join(",") : "-",
    d.saltDonor ? (d.saltDonorHashType ?? "yes") : "no",
    d.verdict,
  ]);
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => r[i].length)),
  );
  const pad = (s: string, i: number) => s.padEnd(widths[i]);
  const line = (r: string[]) => r.map(pad).join("  ");
  const out: string[] = [line(headers), widths.map((w) => "-".repeat(w)).join("  ")];
  for (const r of rows) out.push(line(r));
  out.push("");
  for (const d of results) {
    for (const reason of d.reasons) out.push(`${d.target}: ${reason}`);
  }
  return out.join("\n");
}

export function jsonText(results: Detection[]): string {
  return JSON.stringify(
    {
      tool: "alpinegate",
      version: "0.1.0",
      cve: CVE_ID,
      cvss: CVE_CVSS,
      fixed_versions_checked: FIXED_VERSIONS_CHECKED,
      results: results.map((d) => ({
        target: d.target,
        alpine_release: d.alpineRelease,
        branch: d.branch,
        openssh_version: d.opensshVersion,
        openssh_server_version: d.opensshServerVersion,
        fixed_version: d.fixedVersion,
        pam_in_use: d.pamInUse,
        password_authentication: d.passwordAuth,
        star_accounts: d.starAccounts,
        salt_donor: d.saltDonor,
        salt_donor_hash_type: d.saltDonorHashType,
        sshd_installed: d.sshdInstalled,
        sshd_running: d.sshdRunning,
        verdict: d.verdict,
        reasons: d.reasons,
        conditions: d.conditions.map((c) => ({
          id: c.id,
          met: c.met,
          detail: c.detail,
        })),
      })),
    },
    null,
    2,
  );
}
