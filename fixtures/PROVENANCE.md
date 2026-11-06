# Fixture provenance (built 2026-11-06)

Rootfs trees are the real Alpine 3.18.9 minirootfs plus real
openssh APKs from dl-cdn.alpinelinux.org. Nothing in /etc/shadow
or /etc/ssh was hand-written except the documented items below.

- minirootfs: https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.9-x86_64.tar.gz
  sha256=1d90362d504b1846488bda4d9fd11ea8b8f3a567eeba01d3d881a9c98e900c3f
- openssh-r3: https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/openssh-9.3_p2-r3.apk
  sha256=edbe13276bb793ccec81edcb14fe1f5ab0bdbddb75d76875c4598d5ab95e1b0c
- openssh-server-r3: https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/openssh-server-9.3_p2-r3.apk
  sha256=fd696af98b518cdedbd3957c189b08522593d374a8f0b9b06d996a2df7e2acc7
- openssh-server-common-r3: https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/openssh-server-common-9.3_p2-r3.apk
  sha256=e33c7fd3cab98c11ab2c01d0b2d59d3de74baddd36313f18d0872d2c7418274b
- openssh-r4: https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/openssh-9.3_p2-r4.apk
  sha256=3ec61c6a9ddce9dc49243d23ee6ad09068254d34654cec79bc6952d06dcc5c15
- openssh-server-r4: https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/openssh-server-9.3_p2-r4.apk
  sha256=930ca5ca17c07dc035eae5db2905681c42ba60557c1abbe2f1f070d58168190f
- openssh-server-common-r4: https://dl-cdn.alpinelinux.org/alpine/v3.18/main/x86_64/openssh-server-common-9.3_p2-r4.apk
  sha256=ce23c5d0fc2075100ec51e4a336479e76d83b8adde6b8bf2f14c835c70be0135

## Synthetic parts (labelled, not pretending to be system files)

- `deploy` user in /etc/passwd + /etc/shadow: a real SHA-512 crypt
  hash (python crypt, random salt, random password never stored) so
  the fixture has a $6$ salt donor like a real deployed box. The
  `root:*` line is untouched from the real minirootfs.
- apk-database entries for openssh / openssh-server /
  openssh-server-common in /lib/apk/db/installed: generated
  mechanically from each APK's real .PKGINFO (fields P/V/A/S/I/T/
  U/L/o/m/t/c/D). The C: checksum and F: file-list lines are omitted;
  alpinegate reads only P: and V: from the database.
- The docker-save wrapper (manifest.json / config.json) around each
  layer tar: the layer itself is the real rootfs tree, except that
  device nodes / fifos / sockets under /dev are omitted (they need
  root to extract and the tool never reads them). Empty directories
  are kept; symlinks are preserved.

## Expected verdicts

- fixtures/exposed (openssh 9.3_p2-r3 < fixed 9.3_p2-r4, no PAM,
  PasswordAuthentication default yes, root:* + $6$ donor): EXPOSED
- fixtures/patched (openssh 9.3_p2-r4 = fixed): SAFE

Rebuild with: python3 scripts/build-fixtures.py (needs network).
