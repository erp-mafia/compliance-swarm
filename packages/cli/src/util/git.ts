import { exec } from '../tools/exec.js';
import { createLogger } from './log.js';

const log = createLogger('git');

export async function changedFiles(baseRef: string, repoRoot: string): Promise<string[]> {
  const result = await exec('git', ['diff', '--name-only', `${baseRef}...HEAD`], {
    cwd: repoRoot,
    timeoutMs: 30_000,
  });
  if (result.code !== 0) {
    log.warn('git diff failed; falling back to empty changeset', { stderr: result.stderr });
    return [];
  }
  return result.stdout
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export async function isInsideGitRepo(cwd: string): Promise<boolean> {
  const r = await exec('git', ['rev-parse', '--is-inside-work-tree'], { cwd, timeoutMs: 5_000 });
  return r.code === 0 && r.stdout.trim() === 'true';
}
