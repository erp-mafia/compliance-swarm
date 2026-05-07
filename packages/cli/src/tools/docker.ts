import { exec, type ExecOptions, type ExecResult } from './exec.js';
import { createLogger } from '../util/log.js';
import { os } from './os-shim.js';

const log = createLogger('docker');

const PULLED = new Set<string>();

export interface DockerRunOptions extends ExecOptions {
  image: string;
  args: string[];
  /** Mounts: [{ host, container, readonly? }] */
  mounts?: Array<{ host: string; container: string; readonly?: boolean }>;
  /** Whether to also bind /var/run/docker.sock (e.g. for docker-in-docker scanners). */
  bindDockerSock?: boolean;
  /** Map host UID/GID to avoid root-owned outputs. */
  matchHostUser?: boolean;
}

/**
 * Pull an image once per process.
 */
export async function pullOnce(image: string): Promise<void> {
  if (PULLED.has(image)) return;
  log.info(`docker pull ${image}`);
  const result = await exec('docker', ['pull', image], { timeoutMs: 600_000 });
  if (result.code !== 0) {
    throw new Error(`docker pull ${image} failed (code ${result.code}): ${result.stderr}`);
  }
  PULLED.add(image);
}

export async function dockerRun(opts: DockerRunOptions): Promise<ExecResult> {
  await pullOnce(opts.image);
  const args: string[] = ['run', '--rm', '--init'];

  if (opts.matchHostUser !== false) {
    const uid = os.userInfo().uid;
    const gid = os.userInfo().gid;
    if (uid >= 0 && gid >= 0) args.push('--user', `${uid}:${gid}`);
  }

  for (const m of opts.mounts ?? []) {
    args.push('-v', `${m.host}:${m.container}${m.readonly ? ':ro' : ''}`);
  }

  if (opts.bindDockerSock) {
    args.push('-v', '/var/run/docker.sock:/var/run/docker.sock');
  }

  args.push(opts.image, ...opts.args);

  return exec('docker', args, opts);
}
