export const FILE_CONFIG = {
  MAX_IMAGE_MB: 5,
  MAX_PDF_MB: 20,
  PDF_JS_VERSION: '3.11.174',
  get pdfWorkerUrl() { return `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${this.PDF_JS_VERSION}/pdf.worker.min.js`; }
};

export const PARSE_STATUS = { IDLE: 'IDLE', PROCESSING: 'PROCESSING', SUCCESS: 'SUCCESS', FAILED: 'FAILED' };
