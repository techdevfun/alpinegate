/**
 * Read-only access to a root filesystem tree, from three sources:
 * a directory on disk, a tarball (plain .tar or .tar.gz, incl.
 * docker-save tarballs), or an in-memory map (used by tests).
 * The detector only ever reads through this interface, so the same
 * checks run unchanged on a live host path, an image tarball, or a
 * fixture tree.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";

export interface Rootfs {
  /** File contents as UTF-8, or null when the path does not exist. */
  readText(path: string): string | null;
  /** Raw bytes, or null when the path does not exist. */
  readBytes(path: string): Buffer | null;
  /** Does the path exist (file, directory, or other)? */
  exists(path: string): boolean;
  /** Names inside a directory, or null when it is not a directory. */
  listDir(path: string): string[] | null;
  /** Human-readable label used in output (path, tarball name, ...). */
  readonly label: string;
}

function norm(p: string): string {
  return p.replace(/^\//, "");
}

/** A directory on the local filesystem. */
export class DirRootfs implements Rootfs {
  readonly label: string;
  /** True when this rootfs IS the live host (target "/"). */
  readonly isLiveHost: boolean;
  constructor(private readonly root: string) {
    this.label = root;
    this.isLiveHost = root === "/";
  }
  private full(p: string): string {
    return join(this.root, norm(p));
  }
  readText(p: string): string | null {
    const b = this.readBytes(p);
    return b === null ? null : b.toString("utf8");
  }
  readBytes(p: string): Buffer | null {
    try {
      const f = this.full(p);
      if (!statSync(f).isFile()) return null;
      return readFileSync(f);
    } catch {
      return null;
    }
  }
  exists(p: string): boolean {
    return existsSync(this.full(p));
  }
  listDir(p: string): string[] | null {
    try {
      const f = this.full(p);
      if (!statSync(f).isDirectory()) return null;
      return readdirSync(f);
    } catch {
      return null;
    }
  }
}

/** An in-memory file map. Keys are absolute paths ("/etc/shadow"). */
export class MemoryRootfs implements Rootfs {
  readonly label: string;
  private readonly files = new Map<string, Buffer>();
  constructor(files: Record<string, string | Buffer>, label = "memory") {
    this.label = label;
    for (const [k, v] of Object.entries(files)) {
      this.files.set(norm(k), Buffer.isBuffer(v) ? v : Buffer.from(v));
    }
  }
  readText(p: string): string | null {
    const b = this.readBytes(p);
    return b === null ? null : b.toString("utf8");
  }
  readBytes(p: string): Buffer | null {
    return this.files.get(norm(p)) ?? null;
  }
  exists(p: string): boolean {
    const n = norm(p);
    if (this.files.has(n)) return true;
    for (const k of this.files.keys()) {
      if (k.startsWith(n + "/")) return true;
    }
    return false;
  }
  listDir(p: string): string[] | null {
    const n = norm(p);
    const prefix = n === "" ? "" : n + "/";
    const names = new Set<string>();
    let found = false;
    for (const k of this.files.keys()) {
      if (!k.startsWith(prefix)) continue;
      const rest = k.slice(prefix.length);
      if (rest === "") continue;
      found = true;
      names.add(rest.split("/")[0]);
    }
    return found ? [...names].sort() : null;
  }
}

/**
 * Minimal tar reader (ustar + GNU longname). Only regular files are
 * kept; directories, symlinks, devices and hardlinks are skipped, so
 * a hostile or odd layer cannot escape the in-memory tree. No
 * external dependency, no shelling out to tar.
 */
export function parseTar(data: Buffer): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  let offset = 0;
  let longName: string | null = null;
  while (offset + 512 <= data.length) {
    const header = data.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break; // end-of-archive marker
    const name = readTarString(header, 0, 100);
    const size = parseOctal(header, 124, 12);
    const typeflag = String.fromCharCode(header[156]);
    const prefix = readTarString(header, 345, 155);
    const fullName = prefix ? `${prefix}/${name}` : name;
    const bodyStart = offset + 512;
    const bodyEnd = bodyStart + size;
    if (typeflag === "L") {
      // GNU longname: body is the real name for the NEXT entry.
      longName = data
        .subarray(bodyStart, bodyEnd)
        .toString("utf8")
        .replace(/\0.*$/s, "");
    } else if (typeflag === "0" || typeflag === "\0" || typeflag === "") {
      const key = (longName ?? fullName).replace(/^\.\//, "");
      files.set(key, Buffer.from(data.subarray(bodyStart, bodyEnd)));
      longName = null;
    } else {
      longName = null; // skip dirs, symlinks, etc.
    }
    offset = bodyStart + Math.ceil(size / 512) * 512;
  }
  return files;
}

function readTarString(header: Buffer, off: number, len: number): string {
  const raw = header.subarray(off, off + len);
  const nul = raw.indexOf(0);
  return raw.subarray(0, nul === -1 ? len : nul).toString("utf8");
}

function parseOctal(header: Buffer, off: number, len: number): number {
  const s = readTarString(header, off, len).trim();
  if (s === "") return 0;
  const n = parseInt(s, 8);
  return Number.isNaN(n) ? 0 : n;
}

/** A tarball on disk: .tar, or .tar.gz / .tgz (gunzipped in memory). */
export class TarRootfs implements Rootfs {
  readonly label: string;
  private readonly files: Map<string, Buffer>;
  constructor(path: string, data?: Buffer) {
    this.label = path;
    const raw = data ?? readFileSync(path);
    const isGz =
      path.endsWith(".tar.gz") ||
      path.endsWith(".tgz") ||
      (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b);
    this.files = parseTar(isGz ? gunzipSync(raw) : raw);
  }
  readText(p: string): string | null {
    const b = this.readBytes(p);
    return b === null ? null : b.toString("utf8");
  }
  readBytes(p: string): Buffer | null {
    return this.files.get(norm(p)) ?? null;
  }
  exists(p: string): boolean {
    const n = norm(p);
    if (this.files.has(n)) return true;
    for (const k of this.files.keys()) {
      if (k.startsWith(n + "/")) return true;
    }
    return false;
  }
  listDir(p: string): string[] | null {
    const n = norm(p);
    const prefix = n === "" ? "" : n + "/";
    const names = new Set<string>();
    let found = false;
    for (const k of this.files.keys()) {
      if (!k.startsWith(prefix)) continue;
      const rest = k.slice(prefix.length);
      if (rest === "") continue;
      found = true;
      names.add(rest.split("/")[0]);
    }
    return found ? [...names].sort() : null;
  }
}

/** Read a docker-save tarball (manifest.json + layer tars) as one rootfs. */
export class DockerSaveRootfs implements Rootfs {
  readonly label: string;
  private readonly files = new Map<string, Buffer>();
  constructor(path: string, data?: Buffer) {
    this.label = path;
    const raw = data ?? readFileSync(path);
    const outerData =
      raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b
        ? gunzipSync(raw)
        : raw;
    const outer = parseTar(outerData);
    const manifestRaw = outer.get("manifest.json");
    if (!manifestRaw) {
      throw new Error(
        `${path}: not a docker-save tarball (no manifest.json)`,
      );
    }
    const manifest = JSON.parse(manifestRaw.toString("utf8")) as Array<{
      Layers?: string[];
    }>;
    const layers = manifest[0]?.Layers ?? [];
    // Later layers win, like a real image build.
    for (const layerName of layers) {
      const layerData = outer.get(layerName);
      if (!layerData) continue;
      for (const [k, v] of parseTar(layerData)) {
        if (k.startsWith(".wh.")) continue; // whiteout marker file itself
        const parts = k.split("/");
        const base = parts[parts.length - 1];
        if (base.startsWith(".wh.")) {
          // Whiteout: remove the file/dir it names.
          const target = [...parts.slice(0, -1), base.slice(4)].join("/");
          for (const key of [...this.files.keys()]) {
            if (key === target || key.startsWith(target + "/")) {
              this.files.delete(key);
            }
          }
          continue;
        }
        this.files.set(k, v);
      }
    }
  }
  readText(p: string): string | null {
    const b = this.readBytes(p);
    return b === null ? null : b.toString("utf8");
  }
  readBytes(p: string): Buffer | null {
    return this.files.get(norm(p)) ?? null;
  }
  exists(p: string): boolean {
    const n = norm(p);
    if (this.files.has(n)) return true;
    for (const k of this.files.keys()) {
      if (k.startsWith(n + "/")) return true;
    }
    return false;
  }
  listDir(p: string): string[] | null {
    const n = norm(p);
    const prefix = n === "" ? "" : n + "/";
    const names = new Set<string>();
    let found = false;
    for (const k of this.files.keys()) {
      if (!k.startsWith(prefix)) continue;
      const rest = k.slice(prefix.length);
      if (rest === "") continue;
      found = true;
      names.add(rest.split("/")[0]);
    }
    return found ? [...names].sort() : null;
  }
}
