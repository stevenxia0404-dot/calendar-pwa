const CHAR_TO_TOKEN_RATIO = 1.5;

export const MODEL_CAPABILITY_MAP = {
  'deepseek-v4-flash':  { maxTokens: 128000 },
  'deepseek-v4-pro':    { maxTokens: 128000 },
  'kimi-k2.6':          { maxTokens: 128000 },
  'kimi-k2.5':          { maxTokens: 128000 },
  'doubao-pro':         { maxTokens: 128000 },
  'doubao-lite':        { maxTokens: 32000 },
  'qwen-turbo':         { maxTokens: 128000 },
  'qwen-plus':          { maxTokens: 128000 },
  'glm-4-flash':        { maxTokens: 128000 },
};

export const FALLBACK_STRATEGY = {
  getSafeCharLimit(modelId) {
    const maxTokens = MODEL_CAPABILITY_MAP[modelId]?.maxTokens || 4000;
    return Math.floor(maxTokens / CHAR_TO_TOKEN_RATIO);
  },
};
