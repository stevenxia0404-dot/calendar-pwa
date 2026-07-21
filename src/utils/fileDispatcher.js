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

  // PDF → Worker 提取文字
  if (file.type === 'application/pdf' || file.name.endsWith('.pdf')) {
    if (sizeMB > FILE_CONFIG.MAX_PDF_MB) {
      throw new Error(`PDF_TOO_LARGE: 最大支持 ${FILE_CONFIG.MAX_PDF_MB}MB`);
    }
    const text = await executePdfWorker(file);
    return {
      type: 'PDF',
      content: `[PDF: ${file.name}]\n${text}`,
    };
  }

  // Excel → 保持原逻辑在调用方
  // 其他文本文件 → 读文本
  throw new Error('PASS_THROUGH');
}

function executePdfWorker(file) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('/pdfExtractor.worker.js');
    const reader = new FileReader();
    reader.onload = () => {
      worker.postMessage({
        arrayBuffer: reader.result,
        pdfJsVersion: FILE_CONFIG.PDF_JS_VERSION,
      });
    };
    reader.onerror = () => { worker.terminate(); reject(new Error('PDF文件读取失败')); };
    reader.readAsArrayBuffer(file);

    worker.onmessage = (e) => {
      worker.terminate();
      if (e.data.error) reject(new Error(e.data.error));
      else resolve(e.data.text + (e.data.truncated ? '\n...(仅展示前5页)' : ''));
    };
    worker.onerror = (err) => { worker.terminate(); reject(err); };
  });
}
