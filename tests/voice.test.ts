// 语音三层降级模块的单元测试
//
// 重点测纯逻辑：断句、能力探测、格式选择、错误码提取。
// 浏览器 API（MediaRecorder / Web Speech）无法在 Node 里测，
// 那部分靠浏览器实跑验证。

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  splitSentences,
  hasWebSpeech,
  hasMediaRecorder,
  detectCapability,
  pickMimeType,
  extractErrorCode,
  describeError,
  transcribeOnServer,
  isIOS,
  isSafari,
  voiceHint,
  createLevelMeter,
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

// ==================== 平台提示（iOS 只有 Safari 能用麦克风） ====================
//
// 这组测试锁住「用户看到什么提示」。
// 背景：iOS 规定只有 Safari 能用麦克风，Chrome/Firefox/Edge 的 iOS 版
// 一律被系统挡掉，报出来是 not-allowed —— 显示成「没有麦克风权限」，
// 但用户在浏览器设置里根本找不到麦克风开关，只能干瞪眼。
// 所以提示必须说清楚「换 Safari」。

describe('voiceHint —— 说清楚为什么不行、怎么办', () => {
  // 模拟 UA
  function withUA(ua: string, platform: string, maxTouchPoints: number, fn: () => void) {
    const orig = {
      ua: globalThis.navigator?.userAgent,
      platform: globalThis.navigator?.platform,
      maxTouchPoints: globalThis.navigator?.maxTouchPoints,
    };
    Object.defineProperty(globalThis.navigator, 'userAgent', { value: ua, configurable: true });
    Object.defineProperty(globalThis.navigator, 'platform', { value: platform, configurable: true });
    Object.defineProperty(globalThis.navigator, 'maxTouchPoints', { value: maxTouchPoints, configurable: true });
    try { fn(); } finally {
      Object.defineProperty(globalThis.navigator, 'userAgent', { value: orig.ua, configurable: true });
      Object.defineProperty(globalThis.navigator, 'platform', { value: orig.platform, configurable: true });
      Object.defineProperty(globalThis.navigator, 'maxTouchPoints', { value: orig.maxTouchPoints, configurable: true });
    }
  }

  const IOS_CHROME = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0 Mobile/15E148 Safari/604.1';
  const IOS_SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';
  const ANDROID_CHROME = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36';
  const MAC_SAFARI = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';

  test('iOS + Chrome → 明确让用户改用 Safari', () => {
    withUA(IOS_CHROME, 'iPhone', 5, () => {
      assert.equal(isIOS(), true);
      assert.equal(isSafari(), false);
      const hint = voiceHint('NO_MIC');
      assert.match(hint, /Safari/, `提示里要点明 Safari：${hint}`);
    });
  });

  test('iOS + Safari → 不甩锅给浏览器，说权限怎么开', () => {
    withUA(IOS_SAFARI, 'iPhone', 5, () => {
      assert.equal(isIOS(), true);
      assert.equal(isSafari(), true);
      const hint = voiceHint('NO_MIC');
      assert.match(hint, /锁图标|允许麦克风/, `要说清怎么授权：${hint}`);
      assert.doesNotMatch(hint, /Safari 打开/, 'Safari 本身不该被要求换浏览器');
    });
  });

  test('安卓 Chrome → 说权限怎么开', () => {
    withUA(ANDROID_CHROME, 'Linux armv8l', 5, () => {
      assert.equal(isIOS(), false);
      assert.equal(isSafari(), false);
      const hint = voiceHint('NO_MIC');
      assert.match(hint, /允许麦克风/, hint);
    });
  });

  test('桌面 Safari 不误判成 iOS', () => {
    withUA(MAC_SAFARI, 'MacIntel', 0, () => {
      assert.equal(isIOS(), false, 'Mac 桌面不能被当成 iOS');
      assert.equal(isSafari(), true);
    });
  });

  test('iPadOS 伪装成 Mac（有触摸点）仍算 iOS', () => {
    withUA(MAC_SAFARI, 'MacIntel', 5, () => {
      assert.equal(isIOS(), true, 'iPadOS 13+ 会伪装成 Mac，要靠触摸点区分');
    });
  });

  test('非语音类错误码仍走原提示', () => {
    const hint = voiceHint('ASR_QUOTA_EXCEEDED');
    assert.match(hint, /额度/, hint);
  });
});

// ==================== 实时音量（画波形） ====================
//
// 波形是「看得见的反馈」的核心：用户按下麦克风后能看到声音在动，
// 就知道设备真的在听。所以这条链路不能是「拿不到就空白」——
// 空白会被误解成坏了。拿不到时必须是一条平线。

describe('createLevelMeter —— 实时音量', () => {
  test('Node 环境（没有 AudioContext）返回 null，不炸', () => {
    // Node 里 window 不存在，必须优雅降级
    assert.equal(createLevelMeter(), null);
  });

  test('RecorderHandle 约定 getLevel 存在', () => {
    // 类型层面的约定：RecorderHandle 必须暴露 getLevel，
    // 否则调用方要到处写 optional chaining，忘了就静默画不出波形
    const src = readFileSync(new URL('../src/lib/voice.ts', import.meta.url), 'utf8');
    assert.match(src, /getLevel: \(\) => number/, 'RecorderHandle 必须有 getLevel');
    assert.match(src, /getLevel: \(\) => meter\?\.getLevel\(\) \?\? 0/, '拿不到 meter 时返回 0（平线），不是 undefined');
  });

  test('AudioContext 必须在 await getUserMedia 之前创建', () => {
    // Safari 的硬限制：AudioContext 必须在用户手势的同步部分创建，
    // 放到 await 之后就废了（context 一直是 suspended，音量恒为 0）。
    const src = readFileSync(new URL('../src/lib/voice.ts', import.meta.url), 'utf8');
    const fn = src.slice(src.indexOf('export async function startRecordingDetailed'));
    // 用语义匹配而不是写死代码写法 ——
    // 写死的话，代码一改写法测试就断，而断的是「规则没变」的情况
    const meterIdx = fn.search(/const meter = [^;]*createLevelMeter\(\)/);
    const gumIdx = fn.indexOf('navigator.mediaDevices.getUserMedia');
    assert.ok(meterIdx > -1 && gumIdx > -1, '两个调用都要存在');
    assert.ok(meterIdx < gumIdx, 'meter 必须先于 getUserMedia 创建');
  });

  test('预热过的麦克风不再重复申请', () => {
    // 长按说话的延迟全靠这个：进入语音态就申请好，
    // 长按时直接用。如果这里又申请一次，延迟就白费了。
    const src = readFileSync(new URL('../src/lib/voice.ts', import.meta.url), 'utf8');
    assert.match(src, /export async function prewarmMicrophone/, '要有预热函数');
    const fn = src.slice(src.indexOf('export async function startRecordingDetailed'));
    assert.match(fn, /if \(pre\?\.stream\)/, '有预热流时要走预热分支');
    assert.match(fn, /pre\?\.meter \?\? createLevelMeter\(\)/, 'meter 优先复用预热的');
  });

  test('预热了没用上的麦克风会被释放', () => {
    // 不释放的话系统录音指示灯一直亮着，用户会以为应用在偷录。
    // hook 在单独的 useVoiceRecorder.ts，别读错文件
    const src = readFileSync(new URL('../src/lib/useVoiceRecorder.ts', import.meta.url), 'utf8');
    const fn = src.slice(src.indexOf('export function useVoiceRecorder'));
    assert.match(fn, /getTracks\(\)\.forEach\(t => t\.stop\(\)\)/, '预热的流要能停掉');
  });

  test('startWebSpeech 支持实时中间结果回调', () => {
    const src = readFileSync(new URL('../src/lib/voice.ts', import.meta.url), 'utf8');
    assert.match(src, /onInterim\?: \(text: string\) => void/, '回调要声明为可选，不能破坏现有调用方');
    assert.match(src, /callbacks\.onInterim\?\./, '中间结果要真的回调出去');
  });
});

describe('voiceHint —— 浏览器语音的具体失败原因', () => {
  // Web Speech API 的标准 error 值。不给对应文案的话，
  // 用户只会看到「语音识别出错」，不知道该换浏览器还是该检查设备。
  test('连不上识别服务 → 说清怎么办', () => {
    const hint = voiceHint('WEB_SPEECH_network');
    assert.match(hint, /Safari|输入文字/, hint);
  });

  test('没听到声音 → 说清是静音', () => {
    assert.match(voiceHint('WEB_SPEECH_no-speech'), /没听到声音/, voiceHint('WEB_SPEECH_no-speech'));
  });

  test('找不到麦克风 → 说清是设备问题', () => {
    assert.match(voiceHint('WEB_SPEECH_audio-capture'), /麦克风/, voiceHint('WEB_SPEECH_audio-capture'));
  });

  test('未知错误码也要有话可说，不能是空', () => {
    const hint = voiceHint('WEB_SPEECH_???');
    assert.ok(hint.length > 0, '不能返回空串');
    assert.match(hint, /语音/, hint);
  });
});

describe('voiceHint —— 浏览器语音的具体失败原因', () => {
  // Web Speech API 的标准 error 值。不给对应文案的话，
  // 用户只会看到「语音识别出错」，不知道该换浏览器还是该检查设备。
  test('连不上识别服务 → 说清怎么办', () => {
    const hint = voiceHint('WEB_SPEECH_network');
    assert.match(hint, /Safari|输入文字/, hint);
  });

  test('没听到声音 → 说清是静音', () => {
    assert.match(voiceHint('WEB_SPEECH_no-speech'), /没听到声音/, voiceHint('WEB_SPEECH_no-speech'));
  });

  test('找不到麦克风 → 说清是设备问题', () => {
    assert.match(voiceHint('WEB_SPEECH_audio-capture'), /麦克风/, voiceHint('WEB_SPEECH_audio-capture'));
  });

  test('未知错误码也要有话可说，不能是空', () => {
    const hint = voiceHint('WEB_SPEECH_???');
    assert.ok(hint.length > 0, '不能返回空串');
    assert.match(hint, /语音/, hint);
  });
});
