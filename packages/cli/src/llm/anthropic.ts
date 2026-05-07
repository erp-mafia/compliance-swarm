import Anthropic from '@anthropic-ai/sdk';
import type { LLMClient } from '../skills/interface.js';
import { createLogger } from '../util/log.js';

const log = createLogger('llm:anthropic');

const DEFAULT_MODEL = process.env.COMPLIANCE_ANTHROPIC_MODEL ?? 'claude-sonnet-4-6';
const DEFAULT_MAX_TOKENS = 4096;

export function createAnthropicClient(model = DEFAULT_MODEL): LLMClient {
  if (!process.env.ANTHROPIC_API_KEY) {
    throw new Error('ANTHROPIC_API_KEY is required for the Anthropic adapter');
  }
  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

  return {
    providerName: `anthropic(${model})`,
    async complete({ system, user, maxTokens }) {
      const resp = await retryable(() =>
        client.messages.create({
          model,
          max_tokens: maxTokens ?? DEFAULT_MAX_TOKENS,
          system,
          messages: [{ role: 'user', content: user }],
        }),
      );
      const text = resp.content
        .filter((b: { type: string }) => b.type === 'text')
        .map((b: { type: string; text?: string }) => b.text ?? '')
        .join('\n')
        .trim();
      log.debug('anthropic complete', {
        input_tokens: resp.usage.input_tokens,
        output_tokens: resp.usage.output_tokens,
      });
      return text;
    },
  };
}

async function retryable<T>(fn: () => Promise<T>): Promise<T> {
  const delays = [500, 2_000, 6_000];
  let lastErr: unknown;
  for (let attempt = 0; attempt <= delays.length; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const status = (err as { status?: number }).status;
      if (status !== 429 && status !== 503 && status !== 529) throw err;
      const delay = delays[attempt];
      if (delay === undefined) throw err;
      log.warn(`anthropic ${status}; retry in ${delay}ms`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}
