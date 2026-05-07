import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { SkillManifestSchema, type SkillManifest } from './manifest.js';
import { createLogger } from '../util/log.js';

const log = createLogger('skill-loader');

export interface LoadedSkill {
  manifest: SkillManifest;
  rootDir: string;
  manifestPath: string;
}

/**
 * Discover skill manifests. Tries (in order):
 *   1. `COMPLIANCE_SKILLS_ROOT` env override
 *   2. `<orchestratorRoot>/skills/` — npm-published layout (skills bundled inside the package)
 *   3. `<orchestratorRoot>/../skills/` — monorepo layout (packages/cli + packages/skills)
 *   4. `<orchestratorRoot>/..` — legacy co-located layout (.claude/skills/<skill>/ siblings)
 *
 * Returns whichever location yields ≥1 valid manifest.
 */
export async function discoverSkills(orchestratorRoot: string): Promise<LoadedSkill[]> {
  const candidates: string[] = [];
  if (process.env.COMPLIANCE_SKILLS_ROOT) {
    candidates.push(resolve(process.env.COMPLIANCE_SKILLS_ROOT));
  }
  candidates.push(resolve(orchestratorRoot, 'skills'));
  candidates.push(resolve(orchestratorRoot, '..', 'skills'));
  candidates.push(resolve(orchestratorRoot, '..'));

  for (const root of candidates) {
    if (!existsSync(root)) continue;
    const found = await readSkillsFromRoot(root, orchestratorRoot);
    if (found.length > 0) {
      log.debug(`loaded ${found.length} skill(s)`, { from: root });
      return found;
    }
  }
  return [];
}

async function readSkillsFromRoot(skillsRoot: string, excludeOrchestratorRoot: string): Promise<LoadedSkill[]> {
  const entries = await readdir(skillsRoot, { withFileTypes: true });
  const orchestratorBasename = excludeOrchestratorRoot.split('/').pop();

  const dirs = entries
    .filter((e) => e.isDirectory())
    .filter((e) => e.name !== orchestratorBasename && e.name !== 'cli' && e.name !== 'compliance-swarm')
    .map((e) => join(skillsRoot, e.name));

  const loaded: LoadedSkill[] = [];
  for (const dir of dirs) {
    const manifestPath = join(dir, 'manifest.yml');
    if (!existsSync(manifestPath)) continue;
    try {
      loaded.push(await loadManifest(manifestPath));
    } catch (err) {
      log.warn(`failed to load manifest at ${manifestPath}`, {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
  return loaded;
}

export async function loadManifest(manifestPath: string): Promise<LoadedSkill> {
  const raw = await readFile(manifestPath, 'utf8');
  const parsed: unknown = parseYaml(raw);
  const result = SkillManifestSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '<root>'}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid manifest at ${manifestPath}:\n${issues}`);
  }
  return {
    manifest: result.data,
    rootDir: dirname(manifestPath),
    manifestPath,
  };
}

export async function loadOrchestratorRoot(): Promise<string> {
  const fromEnv = process.env.COMPLIANCE_SWARM_ROOT;
  if (fromEnv) return resolve(fromEnv);
  const here = new URL('.', import.meta.url).pathname;
  return resolve(here, '..', '..');
}
