/**
 * Local Docker images, read-only, over the Docker Engine API on the
 * default unix socket. No registry pull, no container start, no
 * image mutation: the image is exported as a tarball and scanned
 * exactly like a docker-save file. If no daemon answers, the caller
 * reports the target as unresolvable (exit 2), never as SAFE.
 */
import { request as httpRequest } from "node:http";
import { existsSync } from "node:fs";

export const DEFAULT_SOCKET = "/var/run/docker.sock";

export class DockerError extends Error {}

function socketRequest(
  socketPath: string,
  path: string,
): Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { socketPath, path, method: "GET" },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }),
        );
      },
    );
    req.on("error", reject);
    req.setTimeout(120_000, () => req.destroy(new DockerError("docker request timed out")));
    req.end();
  });
}

/** Export a local image as a docker-save tarball. Throws DockerError. */
export async function exportImage(
  image: string,
  socketPath = process.env.DOCKER_SOCK ?? DEFAULT_SOCKET,
): Promise<Buffer> {
  if (!existsSync(socketPath)) {
    throw new DockerError(
      `no Docker daemon socket at ${socketPath} — is Docker running?`,
    );
  }
  const inspect = await socketRequest(
    socketPath,
    `/images/${encodeURIComponent(image)}/json`,
  );
  if (inspect.status === 404) {
    throw new DockerError(`no such local image: ${image}`);
  }
  if (inspect.status !== 200) {
    throw new DockerError(
      `docker inspect failed for ${image}: HTTP ${inspect.status}`,
    );
  }
  const exported = await socketRequest(
    socketPath,
    `/images/${encodeURIComponent(image)}/get`,
  );
  if (exported.status !== 200) {
    throw new DockerError(
      `docker export failed for ${image}: HTTP ${exported.status}`,
    );
  }
  return exported.body;
}
