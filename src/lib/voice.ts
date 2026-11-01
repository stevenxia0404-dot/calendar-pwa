// 语音三层降级模块
//
// v4.0 文档第七章。三层：
//   1. 服务端转写 —— MediaRecorder 录音 → 上传 → Workers AI Whisper
//   2. 浏览器语音识别 —— Web Speech API
//   3. 纯打字 —— 由调用方处理，本模块只报告「前两层都不可用」
//
// 设计要点
//
// 1. 第 1 层是默认层，因为它在所有设备上行为一致。浏览器自带能力在
//    2026 年的实际状况：Firefox 发布版不支持、微信内置浏览器不支持、
//    国产 ROM 定制浏览器静默失败。
//
// 2. 断句靠 Whisper 的标点，不自己写。Whisper 输出带标点和分句，
//    「今天下午改检查表。明天发给王教员。」直接按标点切就是两条记录。
//    浏览器语音（第 2 层）没有标点，才需要靠静音间隔切。
//
// 3. 任何一层失败都不能挡住主流程。失败就降级，不抛给用户。
//
// 4. 音频不上第三方的转写服务。服务端转写走自己的 Worker → Cloudflare 边缘。

// ==================== 类型 ====================

export type VoiceLayer = 'server' | 'browser' | 'unavailable';

export interface VoiceCapability {
  /** 能否录音并上传（MediaRecorder + getUserMedia） */
  canRecord: boolean;
  /** 能否用浏览器语音识别 */
  canWebSpeech: boolean;
  /** 首选层 */
  preferred: VoiceLayer;
}

export interface TranscribeResult {
  ok: boolean;
  /** 转写文本（已按标点切成多段） */
  segments: string[];
  /** 实际生效的层 */
  layer: VoiceLayer;
  /** 失败原因（仅失败时有） */
  code?: string;
  message?: string;
}

/** 服务端返回的错误码 → 用户可读提示 */
const ERROR_MESSAGES: Record<string, string> = {
  ASR_QUOTA_EXCEEDED: '今日语音额度已用完，已切到浏览器语音',
  ASR_UNAVAILABLE: '服务端语音不可用，已切到浏览器语音',
  ASR_FAILED: '语音转写失败，已切到浏览器语音',
  ASR_TOO_LARGE: '录音太长，请短一点',
  ASR_EMPTY: '没有录到声音',
  ASR_BAD_REQUEST: '录音格式不支持',
  NETWORK: '网络不通，已切到浏览器语音',
  NO_MIC: '没有麦克风权限',
  NO_WEB_SPEECH: '浏览器不支持语音识别',
  WEB_SPEECH_START_FAILED: '无法启动语音识别',
};

/**
 * 是不是 iOS / iPadOS。
 *
 * 为什么专门判这个：iOS 规定**只有 Safari 能用麦克风**。
 * Chrome / Firefox / Edge 的 iOS 版虽然都基于 WebKit，
 * 但 getUserMedia 与 SpeechRecognition 一律被系统挡掉，
 * 表现是 `not-allowed` —— 报出来就是「没有麦克风权限」，
 * 而用户在浏览器设置里根本找不到麦克风开关。
 * 与其让人自己撞墙，不如直接告诉他该用 Safari。
 */
export function isIOS(): boolean {
  if (typeof navigator === 'undefined') return false;
  const ua = navigator.userAgent || '';
  // iPadOS 13+ 会把自己伪装成 Mac，用「有触摸点」区分
  return /iPad|iPhone|iPod/.test(ua)
    || ((navigator.platform === 'MacIntel' || /Macintosh/.test(ua)) && (navigator.maxTouchPoints || 0) > 1);
}

/** 是不是 Safari（要排除 iOS 上的 Chrome/Firefox/Edge，它们的 UA 里也带 Safari） */
export function isSafari(): boolean {
  if (typeof navigator === 'undefined') return false;
  const ua = navigator.userAgent || '';
  return /Safari/.test(ua) && !/Chrome|Chromium|CriOS|FxiOS|EdgiOS|Edg\//.test(ua);
}

/**
 * 语音不可用时给一句能照着做的提示。
 *
 * 原则：说清楚「为什么不行」和「怎么办」，
 * 而不是只丢一句「没有麦克风权限」让人自己猜。
 */
export function voiceHint(code: string): string {
  if (code === 'NO_MIC' || code === 'NO_WEB_SPEECH' || code === 'WEB_SPEECH_START_FAILED') {
    if (isIOS() && !isSafari()) {
      return 'iPhone 上语音只能用 Safari：请复制网址到 Safari 打开';
    }
    if (code === 'NO_MIC') {
      return '没有麦克风权限：点地址栏左侧的锁图标，允许麦克风';
    }
    return '这个浏览器不支持语音识别，请直接输入文字';
  }
  return ERROR_MESSAGES[code] || '语音识别出错';
}

// ==================== 纯逻辑部分（可单测） ====================

/**
 * 按标点把转写文本切成多段。
 *
 * Whisper 输出带标点，所以「今天下午改检查表。明天发给王教员。」
 * 切成两条 —— 第一条落今天，第二条落明天。这正是想要的：
 * 一口气说两件事，自动变成两条记录。
 *
 * 规则：
 *   - 句末标点（。！？!?）后切
 *   - 分号；后切（并列的安排）
 *   - 逗号不切（「带学员看了客舱，又讲了安全设备」是一件事）
 *   - 空白与换行不产生空段
 */
export function splitSentences(text: string): string[] {
  if (!text) return [];
  // 句末标点后切，标点保留在句尾
  const parts = text
    .split(/(?<=[。！？!?；;])\s*/)
    .map(s => s.trim())
    .filter(s => s.length > 0);
  return parts.length ? parts : [text.trim()].filter(Boolean);
}

/**
 * 判断浏览器是否支持 Web Speech API。
 * 注意：Firefox 发布版不支持（被实验开关挡着），
 * 微信内置浏览器里对象为 undefined，国产 ROM 可能存在但静默失败。
 */
export function hasWebSpeech(): boolean {
  if (typeof window === 'undefined') return false;
  return !!(window.SpeechRecognition || window.webkitSpeechRecognition);
}

/** 判断能否录音 */
export function hasMediaRecorder(): boolean {
  if (typeof window === 'undefined') return false;
  return typeof MediaRecorder !== 'undefined'
    && !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
}

/** 综合判断能力，决定首选层 */
export function detectCapability(): VoiceCapability {
  const canRecord = hasMediaRecorder();
  const canWebSpeech = hasWebSpeech();
  let preferred: VoiceLayer = 'unavailable';
  if (canRecord) preferred = 'server';
  else if (canWebSpeech) preferred = 'browser';
  return { canRecord, canWebSpeech, preferred };
}

/**
 * 选一个 MediaRecorder 支持的音频格式。
 * Chrome/Edge 支持 webm，Safari 只支持 mp4 —— 不指定会拿到不兼容的默认格式。
 */
export function pickMimeType(): string | undefined {
  if (typeof MediaRecorder === 'undefined') return undefined;
  const candidates = [
    'audio/webm;codecs=opus',
    'audio/webm',
    'audio/mp4',
    'audio/ogg;codecs=opus',
  ];
  for (const c of candidates) {
    try {
      if (MediaRecorder.isTypeSupported(c)) return c;
    } catch { /* 某些环境没有 isTypeSupported */ }
  }
  return undefined;
}

/** 服务端返回的错误体 */
interface AsrErrorBody {
  code?: string;
  error?: string;
}

/** 从服务端错误响应里提取错误码 */
export function extractErrorCode(status: number, body: AsrErrorBody | null): string {
  if (body && typeof body.code === 'string') return body.code;
  if (status === 0) return 'NETWORK';
  return 'ASR_FAILED';
}

// ==================== 服务端转写（第 1 层） ====================

export interface TranscribeOptions {
  token: string | null;
  apiBase: string;
  /** 单次录音最长时长（毫秒），超过自动停止 */
  maxDurationMs?: number;
  /** 上传体积上限 */
  maxBytes?: number;
}

/**
 * 第 1 层：录音 → 上传 → Whisper 转写 → 按标点切段。
 * 失败不抛，返回 ok:false 与错误码，由调用方决定降级。
 */
export async function transcribeOnServer(
  blob: Blob,
  options: TranscribeOptions
): Promise<TranscribeResult> {
  const { token, apiBase } = options;
  const maxBytes = options.maxBytes ?? 5 * 1024 * 1024;

  if (!token) {
    return { ok: false, segments: [], layer: 'server', code: 'NO_TOKEN', message: '未登录' };
  }
  if (blob.size === 0) {
    return { ok: false, segments: [], layer: 'server', code: 'ASR_EMPTY', message: '没有录到声音' };
  }
  if (blob.size > maxBytes) {
    return { ok: false, segments: [], layer: 'server', code: 'ASR_TOO_LARGE', message: '录音太长' };
  }

  try {
    const res = await fetch(`${apiBase}/asr`, {
      method: 'POST',
      headers: {
        'Content-Type': blob.type || 'audio/webm',
        'Authorization': `Bearer ${token}`,
      },
      body: blob,
    });

    let body: AsrErrorBody & { text?: string } = {};
    try { body = await res.json(); } catch { /* 非 JSON 响应 */ }

    if (!res.ok) {
      const code = extractErrorCode(res.status, body);
      return {
        ok: false,
        segments: [],
        layer: 'server',
        code,
        message: body?.error || ERROR_MESSAGES[code] || '语音转写失败',
      };
    }

    const text = (body?.text || '').trim();
    if (!text) {
      return { ok: false, segments: [], layer: 'server', code: 'ASR_EMPTY', message: '没有识别到内容' };
    }

    return { ok: true, segments: splitSentences(text), layer: 'server' };
  } catch {
    return {
      ok: false,
      segments: [],
      layer: 'server',
      code: 'NETWORK',
      message: '网络不通',
    };
  }
}

// ==================== 浏览器语音识别（第 2 层） ====================

export interface WebSpeechCallbacks {
  /** 识别到一段最终文本 */
  onSegment: (text: string) => void;
  /** 出错 */
  onError: (code: string, message: string) => void;
  /** 结束 */
  onEnd: () => void;
  /**
   * 实时中间结果 —— 还没定稿、但已经识别出来的部分。
   * 用来显示「正在说什么」的实时字幕。
   *
   * 只有第 2 层（浏览器语音）有这个能力：
   * 第 1 层的服务端 Whisper 是整段返回，录音期间拿不到任何文字。
   */
  onInterim?: (text: string) => void;
}

/**
 * 第 2 层：Web Speech API。
 *
 * 与第 1 层的关键差异：浏览器语音**不输出标点**，
 * 所以断句要靠静音间隔（连续 1.5 秒无新词就切一段）。
 * 这是它不如第 1 层的地方，也是第 1 层作默认层的理由之一。
 */
export function startWebSpeech(
  lang: string,
  silenceMs: number,
  callbacks: WebSpeechCallbacks
): { stop: () => void } | null {
  if (typeof window === 'undefined') return null;
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) {
    callbacks.onError('NO_WEB_SPEECH', '浏览器不支持语音识别');
    callbacks.onEnd();
    return null;
  }

  const r = new SR();
  r.lang = lang;
  r.interimResults = true;
  r.continuous = true;

  let finalText = '';
  let silenceTimer: ReturnType<typeof setTimeout> | null = null;
  let stopped = false;

  const flush = () => {
    if (finalText.trim()) {
      callbacks.onSegment(finalText.trim());
      finalText = '';
    }
  };

  const resetSilenceTimer = () => {
    if (silenceTimer) clearTimeout(silenceTimer);
    silenceTimer = setTimeout(() => {
      // 静音超过阈值 → 切一段
      flush();
    }, silenceMs);
  };

  r.onresult = (e: SpeechRecognitionEvent) => {
    let interim = '';
    for (let i = e.resultIndex; i < e.results.length; i++) {
      const result = e.results[i];
      if (result.isFinal) {
        finalText += result[0].transcript;
      } else {
        // 中间结果：既用来判断「还在说话」，也拿来显示实时字幕
        interim += result[0].transcript;
        resetSilenceTimer();
        continue;
      }
    }
    // 实时字幕 = 已定稿的 + 还没定稿的
    callbacks.onInterim?.((finalText + interim).trim());
    resetSilenceTimer();
  };

  r.onerror = (e: SpeechRecognitionErrorEvent) => {
    const code = e?.error === 'not-allowed' ? 'NO_MIC' : `WEB_SPEECH_${e?.error || 'ERROR'}`;
    callbacks.onError(code, ERROR_MESSAGES.NO_MIC || '语音识别出错');
  };

  r.onend = () => {
    if (stopped) { callbacks.onEnd(); return; }
    // 有些实现会自己断开（如超时），重连续上
    flush();
    try { r.start(); } catch { callbacks.onEnd(); }
  };

  try {
    r.start();
  } catch {
    callbacks.onError('WEB_SPEECH_START_FAILED', '无法启动语音识别');
    callbacks.onEnd();
    return null;
  }

  resetSilenceTimer();

  return {
    stop: () => {
      stopped = true;
      if (silenceTimer) clearTimeout(silenceTimer);
      flush();
      try { r.stop(); } catch { /* 已经停了 */ }
      callbacks.onEnd();
    },
  };
}

// ==================== 录音封装 ====================

export interface RecorderHandle {
  stop: () => Promise<Blob>;
  cancel: () => void;
  /**
   * 当前音量（0~1 的 RMS）。
   * 拿不到 Analyser 时恒为 0 —— 波形会保持一条平线，
   * 而不是变成空白（空白会被误解成「坏了」）。
   */
  getLevel: () => number;
}

// ==================== 实时音量（画波形用） ====================

export interface LevelMeter {
  /** 接到麦克风流上开始取数 */
  attach: (stream: MediaStream) => void;
  /** 当前音量（0~1 的 RMS） */
  getLevel: () => number;
  /** 释放 AudioContext */
  dispose: () => void;
}

/**
 * 建一个实时音量表。
 *
 * 为什么用 Web Audio 的 Analyser 而不是自己算：
 * Analyser 走的是硬件/系统已处理好的音频路径，
 * 拿到的是真实波形；自己从 MediaRecorder 的 chunk 解码既慢又不同步。
 *
 * 注意 AudioContext 必须在**用户手势的同步部分**创建（Safari 限制），
 * 所以这个函数要在 await getUserMedia 之前调用。
 */
export function createLevelMeter(): LevelMeter | null {
  if (typeof window === 'undefined') return null;
  const Ctor = window.AudioContext
    || (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;

  let ctx: AudioContext;
  try {
    ctx = new Ctor();
  } catch {
    return null;
  }

  let analyser: AnalyserNode | null = null;
  let source: MediaStreamAudioSourceNode | null = null;
  let buf: Uint8Array<ArrayBuffer> | null = null;

  return {
    attach: (stream: MediaStream) => {
      try {
        source = ctx.createMediaStreamSource(stream);
        analyser = ctx.createAnalyser();
        // 1024 点：约 20~40ms 的窗口，够灵敏又不抖
        analyser.fftSize = 1024;
        source.connect(analyser);
        buf = new Uint8Array(analyser.fftSize);
      } catch {
        analyser = null;
        source = null;
      }
    },
    getLevel: () => {
      if (!analyser || !buf) return 0;
      try {
        analyser.getByteTimeDomainData(buf as Uint8Array<ArrayBuffer>);
      } catch {
        return 0;
      }
      // RMS：整段波形的均方根，比峰值更能反映「有多大声音」
      let sum = 0;
      for (let i = 0; i < buf.length; i++) {
        const v = (buf[i] - 128) / 128;
        sum += v * v;
      }
      const rms = Math.sqrt(sum / buf.length);
      // 人声 RMS 大约在 0.05~0.4，映射到 0~1 更符合直觉
      return Math.min(1, rms * 3.2);
    },
    dispose: () => {
      try { source?.disconnect(); } catch { /* ignore */ }
      try { analyser?.disconnect(); } catch { /* ignore */ }
      try { void ctx.close(); } catch { /* ignore */ }
    },
  };
}

/**
 * 开始录音。返回一个句柄，调用 stop() 拿到音频 Blob。
 *
 * 注意 Safari 的 MediaRecorder 支持不完整：
 * 不能用 timeslice 连续产出数据，只能全程录完再取。
 */
export async function startRecording(maxDurationMs = 60000): Promise<RecorderHandle | null> {
  if (!hasMediaRecorder()) return null;

  // AudioContext 必须在用户手势的同步部分创建（Safari 限制），
  // 所以要在 await getUserMedia 之前建好 meter。
  const meter = createLevelMeter();

  let stream: MediaStream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch {
    meter?.dispose();
    return null; // 用户拒绝授权或没有麦克风
  }

  // Analyser 与 MediaRecorder 共用同一个流，互不干扰
  meter?.attach(stream);

  const mimeType = pickMimeType();
  let recorder: MediaRecorder;
  try {
    recorder = mimeType ? new MediaRecorder(stream, { mimeType }) : new MediaRecorder(stream);
  } catch {
    stream.getTracks().forEach(t => t.stop());
    meter?.dispose();
    return null;
  }

  const chunks: BlobPart[] = [];
  recorder.ondataavailable = (e) => {
    if (e.data && e.data.size > 0) chunks.push(e.data);
  };

  recorder.start();

  // 超时自动停
  const timer = setTimeout(() => {
    try { if (recorder.state !== 'inactive') recorder.stop(); } catch { /* ignore */ }
  }, maxDurationMs);

  const cleanup = () => {
    clearTimeout(timer);
    stream.getTracks().forEach(t => t.stop());
    meter?.dispose();
  };

  return {
    stop: () => new Promise<Blob>((resolve) => {
      recorder.onstop = () => {
        cleanup();
        resolve(new Blob(chunks, { type: recorder.mimeType || 'audio/webm' }));
      };
      try {
        if (recorder.state !== 'inactive') recorder.stop();
        else { cleanup(); resolve(new Blob(chunks, { type: recorder.mimeType || 'audio/webm' })); }
      } catch {
        cleanup();
        resolve(new Blob(chunks, { type: recorder.mimeType || 'audio/webm' }));
      }
    }),
    cancel: () => {
      clearTimeout(timer);
      try { if (recorder.state !== 'inactive') recorder.stop(); } catch { /* ignore */ }
      cleanup();
    },
    getLevel: () => meter?.getLevel() ?? 0,
  };
}

/** 用户可读的失败提示 */
export function describeError(code: string): string {
  return ERROR_MESSAGES[code] || '语音识别失败';
}
