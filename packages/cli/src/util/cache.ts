import { createHash } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { createLogger } from './log.js';

const log = createLogger('cache');

export interface CacheKey {
  /** Logical artifact name. */
  name: string;
  /** Material that should invalidate the cache when changed. */
  contentInputs: string[];
}

export class ArtifactCache {
  constructor(private readonly cacheDir: string) {
    if (!existsSync(cacheDir)) mkdirSync(cacheDir, { recursive: true });
  }

  pathFor(key: CacheKey): string {
    const hash = createHash('sha256');
    hash.update(key.name);
    hash.update('\0');
    for (const c of key.contentInputs) hash.update(c);
    return join(this.cacheDir, `${key.name}-${hash.digest('hex').slice(0, 12)}.json`);
  }

  async get(key: CacheKey): Promise<string | null> {
    const path = this.pathFor(key);
    if (!existsSync(path)) return null;
    log.debug('cache hit', { path });
    return readFile(path, 'utf8');
  }

  async put(key: CacheKey, content: string): Promise<string> {
    const path = this.pathFor(key);
    await writeFile(path, content, 'utf8');
    log.debug('cache write', { path, bytes: content.length });
    return path;
  }

  /** Mirror an existing artifact file into the cache. */
  async cacheFile(key: CacheKey, sourcePath: string): Promise<string> {
    const dest = this.pathFor(key);
    await copyFile(sourcePath, dest);
    log.debug('cache mirror', { source: sourcePath, dest });
    return dest;
  }

  /** Hash file contents safely for cache-key inputs. */
  static async hashFiles(paths: string[]): Promise<string[]> {
    const out: string[] = [];
    for (const p of paths) {
      try {
        const contents = await readFile(p, 'utf8');
        out.push(createHash('sha256').update(contents).digest('hex'));
      } catch {
        // Missing file → contributes empty string; still differentiates change.
        out.push('');
      }
    }
    return out;
  }
}

export function defaultCacheDir(repoRoot: string): string {
  const fromEnv = process.env.RUNNER_TEMP ?? process.env.COMPLIANCE_CACHE_DIR;
  if (fromEnv) return resolve(fromEnv, '.compliance-cache');
  return resolve(repoRoot, '.compliance-cache');
}
