import AnthropicBedrock from '@anthropic-ai/bedrock-sdk';
import type { LLMClient } from '../skills/interface.js';
import { createLogger } from '../util/log.js';

const log = createLogger('llm:bedrock');

const DEFAULT_MODEL = process.env.COMPLIANCE_BEDROCK_MODEL ?? 'eu.anthropic.claude-sonnet-4-6';
const DEFAULT_MAX_TOKENS = 4096;

export function createBedrockClient(model = DEFAULT_MODEL): LLMClient {
  const region = process.env.AWS_REGION ?? 'eu-north-1';
  const accessKey = process.env.AWS_ACCESS_KEY_ID;
  const secretKey = process.env.AWS_SECRET_ACCESS_KEY;
  const sessionToken = process.env.AWS_SESSION_TOKEN;

  // SDK overloads: explicit-keys, session-token, or env-resolved (default chain).
  // Pick the most specific one that matches the env we have.
  const client =
    accessKey && secretKey
      ? new AnthropicBedrock({
          awsRegion: region,
          awsAccessKey: accessKey,
          awsSecretKey: secretKey,
          ...(sessionToken && { awsSessionToken: sessionToken }),
        })
      : new AnthropicBedrock({ awsRegion: region });

  return {
    providerName: `bedrock(${model})`,
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
      log.debug('bedrock complete', { input_tokens: resp.usage?.input_tokens, output_tokens: resp.usage?.output_tokens });
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
      const status = (err as { status?: number; statusCode?: number }).status ?? (err as { statusCode?: number }).statusCode;
      if (status !== 429 && status !== 503 && status !== 529) throw err;
      const delay = delays[attempt];
      if (delay === undefined) throw err;
      log.warn(`bedrock ${status}; retry in ${delay}ms`);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  throw lastErr;
}
