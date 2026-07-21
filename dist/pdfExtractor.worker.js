// PDF Text Extractor Worker (classic worker, loaded from public/)
// 使用 importScripts 加载 pdf.js CDN，在独立线程中提取文字

var _pdfjsReady = false;

self.onmessage = function(e) {
  var data = e.data;
  var version = data.pdfJsVersion || '3.11.174';
  var arrayBuffer = data.arrayBuffer;

  if (!_pdfjsReady) {
    importScripts('https://cdnjs.cloudflare.com/ajax/libs/pdf.js/' + version + '/pdf.min.js');
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/' + version + '/pdf.worker.min.js';
    _pdfjsReady = true;
  }

  pdfjsLib.getDocument({ data: arrayBuffer }).promise.then(function(doc) {
    var pages = [];
    var maxPages = Math.min(doc.numPages, 5);
    var chain = Promise.resolve();

    for (var i = 1; i <= maxPages; i++) {
      (function(pageNum) {
        chain = chain.then(function() {
          return doc.getPage(pageNum).then(function(page) {
            return page.getTextContent().then(function(content) {
              pages.push(content.items.map(function(item) { return item.str; }).join(' '));
            });
          });
        });
      })(i);
    }

    chain.then(function() {
      self.postMessage({
        text: pages.join('\n---\n'),
        numPages: doc.numPages,
        truncated: doc.numPages > maxPages
      });
    }).catch(function(err) {
      self.postMessage({ error: err.message || 'PDF extraction failed' });
    });
  }).catch(function(err) {
    self.postMessage({ error: err.message || 'PDF loading failed' });
  });
};
