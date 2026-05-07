#!/usr/bin/env node
import { resolve } from 'node:path';
import { discoverSkills, loadOrchestratorRoot } from '../src/skills/loader.js';
import { run } from '../src/orchestrator.js';
import { loadConfig } from '../src/config/loader.js';
import { createLLMClient } from '../src/llm/client.js';
import { createLogger } from '../src/util/log.js';

const log = createLogger('cli');

interface CliArgs {
  command: 'run' | 'validate-config' | 'sbom' | 'explain' | 'list-skills' | 'help';
  mode?: 'pr' | 'swarm';
  base?: string;
  skill?: string;
  noLlm?: boolean;
  findingId?: string;
  configPath?: string;
}

function parseArgs(argv: string[]): CliArgs {
  const [, , command = 'help', ...rest] = argv;
  const args: CliArgs = { command: 'help' };
  switch (command) {
    case 'run':
    case 'validate-config':
    case 'sbom':
    case 'list-skills':
    case 'help':
      args.command = command;
      break;
    case 'explain':
      args.command = 'explain';
      if (rest[0]) args.findingId = rest[0];
      break;
    default:
      throw new Error(`Unknown command: ${command}. Try 'compliancemaxx help'.`);
  }
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const next = rest[i + 1];
    if (a === '--mode' && next) {
      if (next !== 'pr' && next !== 'swarm') throw new Error(`--mode must be 'pr' or 'swarm'`);
      args.mode = next;
      i++;
    } else if (a === '--base' && next) {
      args.base = next;
      i++;
    } else if (a === '--skill' && next) {
      args.skill = next;
      i++;
    } else if (a === '--config' && next) {
      args.configPath = next;
      i++;
    } else if (a === '--no-llm') {
      args.noLlm = true;
    }
  }
  return args;
}

function printHelp(): void {
  process.stdout.write(`compliancemaxx — multi-framework compliance orchestrator

Usage:
  compliancemaxx <command> [flags]

Commands:
  run --mode pr|swarm [--base <sha>] [--skill <id>] [--no-llm] [--config <path>]
                          Execute scans against the current working directory.
  list-skills             Discover and print all loaded skill manifests.
  validate-config         JSON-schema check of .compliance/config.yml + suppression expiry.
  sbom                    Produce SBOM only via the oss-license-compliance skill.
  explain <findingId>     Show the cross-framework mapping path for a finding.
  help                    Show this message.

Exit codes:
  0  clean run
  1  blocking findings or expired suppressions
  2  internal error

Environment:
  COMPLIANCE_SWARM_ROOT   Override orchestrator package location.
  COMPLIANCE_LOG_LEVEL    debug|info|warn|error (default info).
  ANTHROPIC_API_KEY       For Anthropic LLM adapter.
  AWS_REGION              For Bedrock LLM adapter (resolves credentials via standard chain).
`);
}

async function listSkills(): Promise<void> {
  const root = await loadOrchestratorRoot();
  const skills = await discoverSkills(root);
  if (skills.length === 0) {
    log.warn('no skill manifests found', { searched: root });
    return;
  }
  process.stdout.write(`Loaded ${skills.length} skill manifest(s):\n\n`);
  for (const s of skills) {
    process.stdout.write(`  ${s.manifest.id}@${s.manifest.version}\n`);
    process.stdout.write(`    framework:    ${s.manifest.finding_extraction.framework}\n`);
    process.stdout.write(`    static_scan:  ${s.manifest.static_scan.length} step(s)\n`);
    process.stdout.write(`    deep_audit:   ${s.manifest.deep_audit.length} step(s)\n`);
    if (s.manifest.produces.length > 0) {
      const produced = s.manifest.produces.map((p) => p.name).join(', ');
      process.stdout.write(`    produces:     ${produced}\n`);
    }
    if (s.manifest.consumes.length > 0) {
      process.stdout.write(`    consumes:     ${s.manifest.consumes.join(', ')}\n`);
    }
    process.stdout.write(`    path:         ${s.manifestPath}\n\n`);
  }
}

async function runCommand(args: CliArgs): Promise<number> {
  if (!args.mode) {
    log.error("'run' requires --mode pr|swarm");
    return 2;
  }
  const repoRoot = resolve(process.cwd());
  const config = await loadConfig(repoRoot, args.configPath);

  let llm;
  if (args.mode === 'swarm' && !args.noLlm) {
    try {
      llm = await createLLMClient({ provider: config.llm_provider, model: config.llm_model });
    } catch (err) {
      log.warn('LLM unavailable; deep_audit will be skipped', {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const result = await run({
    mode: args.mode,
    repoRoot,
    ...(args.base !== undefined && { baseRef: args.base }),
    ...(args.configPath !== undefined && { configPath: args.configPath }),
    ...(args.skill !== undefined && { onlySkillId: args.skill }),
    ...(args.noLlm !== undefined && { noLlm: args.noLlm }),
    ...(llm && { llm }),
  });

  log.info('run complete', {
    exit: result.exitCode,
    findings: result.findings.length,
    expired: result.expiredSuppressions.length,
    artifacts: result.artifacts,
  });

  return result.exitCode;
}

async function validateConfigCommand(args: CliArgs): Promise<number> {
  const repoRoot = resolve(process.cwd());
  try {
    const config = await loadConfig(repoRoot, args.configPath);
    const today = new Date().toISOString().slice(0, 10);
    const expired = config.suppressions.filter((s) => s.expires && s.expires < today);
    if (expired.length > 0) {
      log.error(`${expired.length} expired suppression(s):`);
      for (const e of expired) {
        process.stderr.write(`  - ${e.control_ref} ${e.path} (expired ${e.expires})\n`);
      }
      return 1;
    }
    log.info('config valid', {
      enabled: config.enabled_skills.length,
      suppressions: config.suppressions.length,
    });
    return 0;
  } catch (err) {
    log.error('invalid config', { error: err instanceof Error ? err.message : String(err) });
    return 1;
  }
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv);
  switch (args.command) {
    case 'help':
      printHelp();
      return 0;
    case 'list-skills':
      await listSkills();
      return 0;
    case 'run':
      return runCommand(args);
    case 'validate-config':
      return validateConfigCommand(args);
    case 'sbom':
      return runCommand({ ...args, mode: 'pr', skill: 'oss-license-compliance' });
    case 'explain':
      log.warn(`'explain' is not yet implemented in this build`);
      return 2;
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    log.error('unhandled error', { error: err instanceof Error ? err.message : String(err) });
    process.exit(2);
  },
);
