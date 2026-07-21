const CHAR_TO_TOKEN_RATIO = 1.5;

export const MODEL_CAPABILITY_MAP = {
  'kimi-2.6':       { maxTokens: 128000 },
  'deepseek-chat':  { maxTokens: 32000 },
  'volc-default':   { maxTokens: 8000 },
  'gpt-4o-mini':    { maxTokens: 128000 },
};

export const FALLBACK_STRATEGY = {
  getSafeCharLimit(modelId) {
    const maxTokens = MODEL_CAPABILITY_MAP[modelId]?.maxTokens || 4000;
    return Math.floor(maxTokens / CHAR_TO_TOKEN_RATIO);
  },
};
