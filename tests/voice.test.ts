// 语音三层降级模块的单元测试
//
// 重点测纯逻辑：断句、能力探测、格式选择、错误码提取。
// 浏览器 API（MediaRecorder / Web Speech）无法在 Node 里测，
// 那部分靠浏览器实跑验证。

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  splitSentences,
  hasWebSpeech,
  hasMediaRecorder,
  detectCapability,
  pickMimeType,
  extractErrorCode,
  describeError,
  transcribeOnServer,
} from '../src/lib/voice.ts';

describe('断句 —— 靠 Whisper 的标点切段', () => {
  test('一句话说两件事 → 切成两条', () => {
    // 这是最典型的场景：走路时一口气说两件事
    const r = splitSentences('今天下午改检查表。明天发给王教员。');
    assert.deepEqual(r, ['今天下午改检查表。', '明天发给王教员。']);
  });

  test('句末标点后切', () => {
    assert.deepEqual(splitSentences('第一件事。第二件事！第三件事？'), [
      '第一件事。', '第二件事！', '第三件事？',
    ]);
  });

  test('分号后切（并列的安排）', () => {
    const r = splitSentences('上午模拟机训练；下午整理材料');
    assert.equal(r.length, 2);
    assert.ok(r[0].includes('模拟机'));
    assert.ok(r[1].includes('整理材料'));
  });

  test('逗号不切（同一件事的状语）', () => {
    const r = splitSentences('带学员看了客舱，又讲了安全设备');
    assert.equal(r.length, 1);
    assert.ok(r[0].includes('又讲了'));
  });

  test('空文本返回空数组', () => {
    assert.deepEqual(splitSentences(''), []);
    assert.deepEqual(splitSentences('   '), []);
  });

  test('没有标点就是一段', () => {
    assert.deepEqual(splitSentences('改完了乘务应急检查表'), ['改完了乘务应急检查表']);
  });

  test('纯标点不产生空段', () => {
    const r = splitSentences('好的。');
    assert.equal(r.length, 1);
    assert.equal(r[0], '好的。');
  });

  test('换行也算分隔', () => {
    const r = splitSentences('第一件事。\n第二件事。');
    assert.equal(r.length, 2);
  });
});

describe('能力探测 —— 决定首选层与降级路径', () => {
  test('Node 环境没有浏览器 API', () => {
    assert.equal(hasWebSpeech(), false);
    assert.equal(hasMediaRecorder(), false);
  });

  test('都没有 → preferred 为 unavailable', () => {
    const cap = detectCapability();
    assert.equal(cap.canRecord, false);
    assert.equal(canBeServer(cap), false);
    assert.equal(cap.preferred, 'unavailable');
  });
});

// 小工具：把 canRecord 映射成「能否走服务端」
function canBeServer(cap: { canRecord: boolean }) {
  return cap.canRecord;
}

describe('音频格式选择 —— Safari 只支持 mp4', () => {
  test('Node 环境返回 undefined（无 MediaRecorder）', () => {
    assert.equal(pickMimeType(), undefined);
  });
});

describe('错误码提取 —— 决定用户看到什么提示', () => {
  test('服务端返回了 code 就用它', () => {
    assert.equal(extractErrorCode(429, { code: 'ASR_QUOTA_EXCEEDED' }), 'ASR_QUOTA_EXCEEDED');
    assert.equal(extractErrorCode(503, { code: 'ASR_UNAVAILABLE' }), 'ASR_UNAVAILABLE');
    assert.equal(extractErrorCode(413, { code: 'ASR_TOO_LARGE' }), 'ASR_TOO_LARGE');
  });

  test('没有 code 但状态码 0 → 网络问题', () => {
    assert.equal(extractErrorCode(0, null), 'NETWORK');
  });

  test('兜底为 ASR_FAILED', () => {
    assert.equal(extractErrorCode(500, {}), 'ASR_FAILED');
  });

  test('错误码都能映射到用户可读提示', () => {
    const codes = [
      'ASR_QUOTA_EXCEEDED', 'ASR_UNAVAILABLE', 'ASR_FAILED',
      'ASR_TOO_LARGE', 'ASR_EMPTY', 'ASR_BAD_REQUEST', 'NETWORK', 'NO_MIC',
    ];
    for (const c of codes) {
      const msg = describeError(c);
      assert.ok(msg && msg.length > 0, `${c} 应有提示`);
      assert.ok(!/undefined|NaN/.test(msg), `${c} 的提示不应含 undefined`);
    }
  });
});

describe('服务端转写 —— 失败不抛，降级由调用方决定', () => {
  test('没有 token 直接失败，不发请求', async () => {
    const r = await transcribeOnServer(new Blob(['x']), {
      token: null,
      apiBase: 'http://localhost:8787',
    });
    assert.equal(r.ok, false);
    assert.equal(r.layer, 'server');
    assert.equal(r.code, 'NO_TOKEN');
  });

  test('空音频失败', async () => {
    const r = await transcribeOnServer(new Blob([]), {
      token: 't',
      apiBase: 'http://localhost:8787',
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'ASR_EMPTY');
  });

  test('超大音频在本地就拦下，不浪费请求', async () => {
    const big = new Blob([new Uint8Array(1024)]);
    const r = await transcribeOnServer(big, {
      token: 't',
      apiBase: 'http://localhost:8787',
      maxBytes: 512,
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'ASR_TOO_LARGE');
  });

  test('网络不通 → NETWORK', async () => {
    const r = await transcribeOnServer(new Blob(['x']), {
      token: 't',
      // 指向一个不存在的端口
      apiBase: 'http://127.0.0.1:59999',
    });
    assert.equal(r.ok, false);
    assert.equal(r.code, 'NETWORK');
  });
});
