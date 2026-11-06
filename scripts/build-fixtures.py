#!/usr/bin/env python3
"""Build alpinegate fixtures from REAL Alpine artifacts (no hand-made systems).

Downloads (pinned, checksummed where Alpine publishes one):
  - alpine-minirootfs-3.18.9-x86_64.tar.gz (sha256 verified against the
    published .sha256 file)
  - openssh / openssh-server / openssh-server-common 9.3_p2-r3 (vulnerable)
    and 9.3_p2-r4 (fixed, per the Alpine advisory of 2026-11-05)
    from dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/

Builds:
  fixtures/exposed/  - 3.18.9 rootfs + r3 packages (EXPOSED shape)
  fixtures/patched/  - 3.18.9 rootfs + r4 packages (SAFE shape)
  fixtures/alpine-3.18-exposed.tar.gz / alpine-3.18-patched.tar.gz
                     - docker-save-format tarballs of the same trees
                       (gzipped; the CLI reads .tar.gz directly)
  fixtures/PROVENANCE.md - URLs, sha256 digests, download date

What is synthetic (and labelled as such in PROVENANCE.md):
  - The `deploy` user added to /etc/passwd and /etc/shadow: a real
    SHA-512 crypt hash (python crypt, random salt, random password that
    is never stored) so the fixture has a $6$ salt donor, the way a
    real deployed box does. The root account line (root:*) is untouched
    from the real minirootfs.
  - The apk-database entries for the three openssh packages: generated
    mechanically from each APK's real .PKGINFO (same fields apk writes:
    P/V/A/S/I/T/U/L/o/m/t/c/D). The C: checksum and F: file-list lines
    are omitted and documented; alpinegate reads only P: and V:.
  - The docker-save wrapper (manifest.json / config.json) around the
    layer tar: the layer itself is the real rootfs tree.

Requires network. NOT run by CI. Re-run to rebuild fixtures.
"""
import crypt
import hashlib
import io
import json
import os
import secrets
import tarfile
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BASE)  # repo root (scripts/ lives one level down)
FIX = os.path.join(ROOT, "fixtures")
CACHE = os.path.join(FIX, ".cache")
MIRROR = "https://dl-cdn.alpinelinux.org/alpine/v3.18"
DATE = "2026-11-06"

FILES = {
    "minirootfs": (
        f"{MIRROR}/releases/x86_64/alpine-minirootfs-3.18.9-x86_64.tar.gz",
        "1d90362d504b1846488bda4d9fd11ea8b8f3a567eeba01d3d881a9c98e900c3f",
    ),
    "openssh-r3": (f"{MIRROR}/main/x86_64/openssh-9.3_p2-r3.apk", None),
    "openssh-server-r3": (
        f"{MIRROR}/main/x86_64/openssh-server-9.3_p2-r3.apk",
        None,
    ),
    "openssh-server-common-r3": (
        f"{MIRROR}/main/x86_64/openssh-server-common-9.3_p2-r3.apk",
        None,
    ),
    "openssh-r4": (f"{MIRROR}/main/x86_64/openssh-9.3_p2-r4.apk", None),
    "openssh-server-r4": (
        f"{MIRROR}/main/x86_64/openssh-server-9.3_p2-r4.apk",
        None,
    ),
    "openssh-server-common-r4": (
        f"{MIRROR}/main/x86_64/openssh-server-common-9.3_p2-r4.apk",
        None,
    ),
}


def fetch(name, url, sha256):
    path = os.path.join(CACHE, os.path.basename(url))
    if not os.path.exists(path):
        print(f"download {url}")
        urllib.request.urlretrieve(url, path)
    data = open(path, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    if sha256 and digest != sha256:
        raise SystemExit(f"sha256 MISMATCH for {name}: {digest} != {sha256}")
    print(f"{name}: sha256={digest}")
    return path, digest


def pkginfo(apk_path):
    """Read .PKGINFO out of an .apk (a gzipped tar)."""
    with tarfile.open(apk_path, "r:gz") as tf:
        member = tf.getmember(".PKGINFO")
        text = tf.extractfile(member).read().decode()
    info = {}
    depends = []
    for line in text.splitlines():
        if " = " not in line or line.startswith("#"):
            continue
        k, v = line.split(" = ", 1)
        if k == "depend":
            depends.append(v)
        else:
            info[k] = v
    info["depend"] = depends
    return info


def apk_db_entry(info):
    """Render an /lib/apk/db/installed record from a real .PKGINFO.

    Same field set apk writes (P/V/A/S/I/T/U/L/o/m/t/c/D); the C:
    checksum line and the F: file list are intentionally omitted
    (documented in PROVENANCE.md). alpinegate parses P: and V: only.
    """
    lines = [
        f"P:{info['pkgname']}",
        f"V:{info['pkgver']}",
        f"A:{info.get('arch', 'x86_64')}",
        f"S:{info.get('size', '0')}",
        f"I:{info.get('size', '0')}",
        f"T:{info.get('pkgdesc', '')}",
        f"U:{info.get('url', '')}",
        f"L:{info.get('license', '')}",
        f"o:{info.get('origin', '')}",
        f"m:{info.get('maintainer', info.get('packager', ''))}",
        f"t:{info.get('builddate', '0')}",
        f"c:{info.get('commit', '')}",
    ]
    if info["depend"]:
        lines.append("D:" + " ".join(info["depend"]))
    lines.append("")
    return "\n".join(lines)


def extract_apk(apk_path, dest):
    """Extract an .apk into a rootfs, skipping signature/metadata files."""
    with tarfile.open(apk_path, "r:gz") as tf:
        members = [
            m
            for m in tf.getmembers()
            if m.name not in (".PKGINFO",)
            and not m.name.startswith(".SIGN.")
            and m.isfile()
        ]
        tf.extractall(dest, members=members)


def add_salt_donor(rootfs):
    """Add a `deploy` user with a real $6$ (SHA-512 crypt) password hash.

    Password is random and never stored; only the hash lands in the
    fixture, exactly as on a real box where an admin set a password.
    """
    salt = "$6$" + secrets.token_hex(8) + "$"
    password = secrets.token_hex(16)
    hashed = crypt.crypt(password, salt)
    assert hashed.startswith("$6$"), hashed[:4]
    with open(os.path.join(rootfs, "etc/passwd"), "a") as f:
        f.write("deploy:x:1000:1000:deploy:/home/deploy:/bin/ash\n")
    with open(os.path.join(rootfs, "etc/shadow"), "a") as f:
        f.write(f"deploy:{hashed}:20000:0:99999:7:::\n")
    os.makedirs(os.path.join(rootfs, "home/deploy"), exist_ok=True)
    print(f"deploy user added, hash prefix {hashed.split('$')[1]} ($6$)")


def build_tree(name, apk_paths):
    dest = os.path.join(FIX, name)
    os.system(f"rm -rf {dest}")
    os.makedirs(dest)
    with tarfile.open(FILES_CACHE["minirootfs"], "r:gz") as tf:
        tf.extractall(dest)
    db_path = os.path.join(dest, "lib/apk/db/installed")
    entries = []
    for apk in apk_paths:
        info = pkginfo(apk)
        extract_apk(apk, dest)
        entries.append(apk_db_entry(info))
        print(f"  {name}: installed {info['pkgname']} {info['pkgver']}")
    with open(db_path, "a") as f:
        f.write("\n".join(entries))
    add_salt_donor(dest)
    # Sanity: the shape the tool must see.
    shadow = open(os.path.join(dest, "etc/shadow")).read()
    assert shadow.startswith("root:*:") or "\nroot:*:" in shadow, "root:* missing from real minirootfs shadow"
    assert "$6$" in shadow, "salt donor missing"
    assert os.path.exists(os.path.join(dest, "usr/sbin/sshd"))
    assert os.path.exists(os.path.join(dest, "etc/ssh/sshd_config"))
    assert open(os.path.join(dest, "etc/alpine-release")).read().strip() == "3.18.9"
    return dest


def docker_save_tar(rootfs, tag, out_path):
    """Wrap a rootfs tree in a docker-save-format tarball (gzipped)."""
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as tf:
        for dirpath, dirnames, files in os.walk(rootfs):
            # Keep empty directories too (os.walk order: dirs first).
            for d in sorted(dirnames):
                full = os.path.join(dirpath, d)
                arc = os.path.relpath(full, rootfs)
                ti = tarfile.TarInfo(arc)
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            for fn in sorted(files):
                full = os.path.join(dirpath, fn)
                # Device nodes, fifos and sockets cannot be extracted
                # without root and the tool never reads them: skip.
                if not (os.path.isfile(full) or os.path.islink(full)):
                    continue
                arc = os.path.relpath(full, rootfs)
                tf.add(full, arcname=arc)
    layer_bytes = layer.getvalue()
    config = {"architecture": "x86_64", "os": "linux",
              "config": {"Image": tag}}
    manifest = [{
        "Config": "config.json",
        "RepoTags": [tag],
        "Layers": ["layer.tar"],
    }]
    with tarfile.open(out_path, "w:gz") as tf:
        for name, data in (
            ("layer.tar", layer_bytes),
            ("config.json", json.dumps(config).encode()),
            ("manifest.json", json.dumps(manifest).encode()),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    print(f"wrote {out_path} ({os.path.getsize(out_path)} bytes)")


def main():
    os.makedirs(CACHE, exist_ok=True)
    global FILES_CACHE
    FILES_CACHE = {}
    digests = {}
    for name, (url, sha) in FILES.items():
        path, digest = fetch(name, url, sha)
        FILES_CACHE[name] = path
        digests[name] = (url, digest)
    exposed = build_tree(
        "exposed",
        [FILES_CACHE[k] for k in
         ("openssh-r3", "openssh-server-r3", "openssh-server-common-r3")],
    )
    patched = build_tree(
        "patched",
        [FILES_CACHE[k] for k in
         ("openssh-r4", "openssh-server-r4", "openssh-server-common-r4")],
    )
    docker_save_tar(exposed, "alpinegate-fixture:3.18-exposed",
                    os.path.join(FIX, "alpine-3.18-exposed.tar.gz"))
    docker_save_tar(patched, "alpinegate-fixture:3.18-patched",
                    os.path.join(FIX, "alpine-3.18-patched.tar.gz"))
    lines = ["# Fixture provenance (built 2026-11-06)",
             "",
             "Rootfs trees are the real Alpine 3.18.9 minirootfs plus real",
             "openssh APKs from dl-cdn.alpinelinux.org. Nothing in /etc/shadow",
             "or /etc/ssh was hand-written except the documented items below.",
             ""]
    for name, (url, digest) in digests.items():
        lines.append(f"- {name}: {url}")
        lines.append(f"  sha256={digest}")
    lines += [
        "",
        "## Synthetic parts (labelled, not pretending to be system files)",
        "",
        "- `deploy` user in /etc/passwd + /etc/shadow: a real SHA-512 crypt",
        "  hash (python crypt, random salt, random password never stored) so",
        "  the fixture has a $6$ salt donor like a real deployed box. The",
        "  `root:*` line is untouched from the real minirootfs.",
        "- apk-database entries for openssh / openssh-server /",
        "  openssh-server-common in /lib/apk/db/installed: generated",
        "  mechanically from each APK's real .PKGINFO (fields P/V/A/S/I/T/",
        "  U/L/o/m/t/c/D). The C: checksum and F: file-list lines are omitted;",
        "  alpinegate reads only P: and V: from the database.",
        "- The docker-save wrapper (manifest.json / config.json) around each",
        "  layer tar: the layer itself is the real rootfs tree, except that",
        "  device nodes / fifos / sockets under /dev are omitted (they need",
        "  root to extract and the tool never reads them). Empty directories",
        "  are kept; symlinks are preserved.",
        "",
        "## Expected verdicts",
        "",
        "- fixtures/exposed (openssh 9.3_p2-r3 < fixed 9.3_p2-r4, no PAM,",
        "  PasswordAuthentication default yes, root:* + $6$ donor): EXPOSED",
        "- fixtures/patched (openssh 9.3_p2-r4 = fixed): SAFE",
        "",
        "Rebuild with: python3 scripts/build-fixtures.py (needs network).",
    ]
    with open(os.path.join(FIX, "PROVENANCE.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("fixtures built OK")


if __name__ == "__main__":
    main()
