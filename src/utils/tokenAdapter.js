import { FALLBACK_STRATEGY } from '../config/modelStrategy';

export function adaptPayloadToModel(fullText, currentModelId) {
  const safeCharLimit = FALLBACK_STRATEGY.getSafeCharLimit(currentModelId);
  if (fullText.length <= safeCharLimit) return fullText;
  console.warn(`[架构警告] 文本长度超出 ${currentModelId} 安全水位，已执行物理截断。`);
  return fullText.slice(0, safeCharLimit) + `\n\n[系统强制截断：因当前模型 (${currentModelId}) 容量受限，仅保留前 ${safeCharLimit} 字。需看全文请切换长文本模型]`;
}
