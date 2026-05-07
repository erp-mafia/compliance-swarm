type Level = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_RANK: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

const envLevel = (process.env.COMPLIANCE_LOG_LEVEL ?? 'info').toLowerCase() as Level;
const threshold = LEVEL_RANK[envLevel] ?? LEVEL_RANK.info;

function emit(level: Level, prefix: string, msg: string, ctx?: Record<string, unknown>): void {
  if (LEVEL_RANK[level] < threshold) return;
  const line = `[${level}] ${prefix} ${msg}`;
  const stream = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  if (ctx && Object.keys(ctx).length > 0) {
    stream.write(`${line} ${JSON.stringify(ctx)}\n`);
  } else {
    stream.write(`${line}\n`);
  }
}

export interface Logger {
  debug(msg: string, ctx?: Record<string, unknown>): void;
  info(msg: string, ctx?: Record<string, unknown>): void;
  warn(msg: string, ctx?: Record<string, unknown>): void;
  error(msg: string, ctx?: Record<string, unknown>): void;
  child(suffix: string): Logger;
}

export function createLogger(prefix: string): Logger {
  const formatted = `[${prefix}]`;
  return {
    debug: (msg, ctx) => emit('debug', formatted, msg, ctx),
    info: (msg, ctx) => emit('info', formatted, msg, ctx),
    warn: (msg, ctx) => emit('warn', formatted, msg, ctx),
    error: (msg, ctx) => emit('error', formatted, msg, ctx),
    child: (suffix) => createLogger(`${prefix}:${suffix}`),
  };
}
