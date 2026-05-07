import { spawn } from 'node:child_process';
import { createLogger } from '../util/log.js';

const log = createLogger('exec');

export interface ExecOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  maxStdoutBytes?: number;
  maxStderrBytes?: number;
}

export interface ExecResult {
  stdout: string;
  stderr: string;
  code: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  durationMs: number;
}

const DEFAULT_TIMEOUT_MS = 180_000;
const DEFAULT_STDOUT_CAP = 32 * 1024 * 1024;
const DEFAULT_STDERR_CAP = 4 * 1024 * 1024;

/**
 * Spawn a process with timeout, output caps, and structured result.
 * No shell expansion — args must be a pre-tokenized array. This is intentional
 * so manifest-supplied arguments cannot be exploited via shell metacharacters.
 */
export function exec(command: string, args: string[], options: ExecOptions = {}): Promise<ExecResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const stdoutCap = options.maxStdoutBytes ?? DEFAULT_STDOUT_CAP;
  const stderrCap = options.maxStderrBytes ?? DEFAULT_STDERR_CAP;

  return new Promise((resolve) => {
    const start = Date.now();
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let stdoutTruncated = false;
    let stderrTruncated = false;
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      log.warn(`timeout after ${timeoutMs}ms — sending SIGTERM`, { command, args });
      child.kill('SIGTERM');
      // SIGKILL grace
      setTimeout(() => {
        if (!child.killed) child.kill('SIGKILL');
      }, 5_000);
    }, timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => {
      if (stdoutBytes + chunk.length > stdoutCap) {
        if (!stdoutTruncated) {
          const remaining = stdoutCap - stdoutBytes;
          if (remaining > 0) stdoutChunks.push(chunk.subarray(0, remaining));
          stdoutTruncated = true;
        }
        return;
      }
      stdoutChunks.push(chunk);
      stdoutBytes += chunk.length;
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderrBytes + chunk.length > stderrCap) {
        if (!stderrTruncated) {
          const remaining = stderrCap - stderrBytes;
          if (remaining > 0) stderrChunks.push(chunk.subarray(0, remaining));
          stderrTruncated = true;
        }
        return;
      }
      stderrChunks.push(chunk);
      stderrBytes += chunk.length;
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: `spawn error: ${err.message}\n` + Buffer.concat(stderrChunks).toString('utf8'),
        code: -1,
        signal: null,
        timedOut: false,
        durationMs: Date.now() - start,
      });
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        code,
        signal,
        timedOut,
        durationMs: Date.now() - start,
      });
    });
  });
}
