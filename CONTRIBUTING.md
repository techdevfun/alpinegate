# Contributing to alpinegate

Thanks for helping. This is a small, focused tool: it checks five live
conditions for one vulnerability (CVE-2026-123158) and prints a
first-hour playbook. Keep it that way.

## What belongs here

- A new target source (another image format, another container runtime)
  that stays read-only and offline.
- A new Alpine branch in the fixed-version map — with the advisory or
  SecDB link and the check date in `src/fixedVersions.ts`, plus a test.
- Better detection of one of the five conditions, with a fixture that
  proves it.

## What does not belong here

- Exploit code, login attempts, or any form of authentication against a
  target. The tool checks conditions; it never logs in.
- A general CVE scanner. Trivy and Grype already own that; alpinegate
  answers one narrower question.
- Auto-remediation. The playbook prints steps; it never edits a config
  or restarts a daemon.
- Network calls in the scan path. v0.1.0 is fully offline.

## How to contribute

1. Fork, branch, and make your change with tests (`npm test`).
2. If you touch the fixed-version map, cite the source and the date.
3. Run the preflight check before opening a PR: `node scripts/preflight.js`
   (public content must be 100% English, no internal names).
4. Keep the demo honest: the GIF is rendered from a real transcript
   (`demo/transcript.txt`), never hand-edited.

## Reporting a wrong verdict

A false SAFE is the worst failure mode of this tool. If alpinegate
says SAFE on a target you believe is exposed (or EXPOSED on a target
you believe is safe), open an issue with the target type, the Alpine
release, the openssh version, and the full CLI output — and say which
of the five conditions you dispute.
