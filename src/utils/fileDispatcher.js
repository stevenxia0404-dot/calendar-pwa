import { FILE_CONFIG } from '../config/fileStrategy';

/**
 * 文件任务调度器 — 根据文件类型分派到不同处理通道
 * 返回 { type, content, image? } 或抛出错误
 */
export async function dispatchFileTask(file) {
  const sizeMB = file.size / (1024 * 1024);

  // 图片 → base64 编码（带大小检查）
  if (file.type.startsWith('image/')) {
    if (sizeMB > FILE_CONFIG.MAX_IMAGE_MB) {
      return { type: 'IMAGE_OVERSIZE', file };
    }
    const base64 = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error('图片读取失败'));
      reader.readAsDataURL(file);
    });
    return {
      type: 'IMAGE',
      content: `[图片: ${file.name}]`,
      image: base64,
    };
  }

  // PDF → 主线程 pdfjs-dist 提取文字
  if (file.type === 'application/pdf' || file.name.endsWith('.pdf')) {
    if (sizeMB > FILE_CONFIG.MAX_PDF_MB) {
      throw new Error(`PDF_TOO_LARGE: 最大支持 ${FILE_CONFIG.MAX_PDF_MB}MB`);
    }
    const text = await extractPdfText(file);
    return {
      type: 'PDF',
      content: `[PDF: ${file.name}]\n${text}`,
    };
  }

  // Excel → 保持原逻辑在调用方
  // 其他文本文件 → 读文本
  throw new Error('PASS_THROUGH');
}

async function extractPdfText(file) {
  const pdfjsLib = await import('pdfjs-dist');
  pdfjsLib.GlobalWorkerOptions.workerSrc = '/pdf.worker.min.mjs';

  const buf = await file.arrayBuffer();
  const doc = await pdfjsLib.getDocument({ data: buf }).promise;
  const pages = [];
  const maxPages = Math.min(doc.numPages, 5);
  const MAX_CHARS = 6000; // 硬上限，防止超长文本撑爆 payload

  for (let i = 1; i <= maxPages; i++) {
    const page = await doc.getPage(i);
    const content = await page.getTextContent();
    pages.push(content.items.map((item) => item.str).join(' '));
    if (pages.join('').length > MAX_CHARS * 1.5) break; // 提前终止，避免无效工作
  }

  let text = pages.join('\n---\n');
  if (text.length > MAX_CHARS) text = text.slice(0, MAX_CHARS) + '\n...(文本过长已截断)';
  return text + (doc.numPages > maxPages ? '\n...(仅展示前5页)' : '');
}
