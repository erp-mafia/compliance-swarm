import type { LLMClient } from '../skills/interface.js';
export type { LLMClient };

export interface LLMOptions {
  provider: 'bedrock' | 'anthropic';
  model?: string;
}

/**
 * Constructs an LLMClient for the given provider. Real adapters are wired
 * in Phase 5; this entry point lets the CLI lazy-load the right module.
 */
export async function createLLMClient(opts: LLMOptions): Promise<LLMClient> {
  if (opts.provider === 'bedrock') {
    const { createBedrockClient } = await import('./bedrock.js');
    return createBedrockClient(opts.model);
  }
  const { createAnthropicClient } = await import('./anthropic.js');
  return createAnthropicClient(opts.model);
}
