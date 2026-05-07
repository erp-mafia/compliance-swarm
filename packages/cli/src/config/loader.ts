import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { ConfigSchema, type SwarmConfig } from './schema.js';
import { createLogger } from '../util/log.js';

const log = createLogger('config');

const DEFAULT_RELATIVE_PATHS = ['.compliance/config.yml', '.compliance/config.yaml'];

export async function loadConfig(repoRoot: string, override?: string): Promise<SwarmConfig> {
  const candidate = override
    ? join(repoRoot, override)
    : DEFAULT_RELATIVE_PATHS.map((p) => join(repoRoot, p)).find((p) => existsSync(p));

  if (!candidate || !existsSync(candidate)) {
    log.info('no .compliance/config.yml found — using defaults');
    return ConfigSchema.parse({});
  }

  const raw = await readFile(candidate, 'utf8');
  const parsed: unknown = parseYaml(raw);
  const result = ConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '<root>'}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid config at ${candidate}:\n${issues}`);
  }
  log.info('loaded config', { path: candidate });
  return result.data;
}
