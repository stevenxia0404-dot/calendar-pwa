'use client';

// 语音录制的状态机 —— 从 VoicePanel 抽出来的逻辑层。
//
// 为什么抽出来：之前 VoicePanel 里同时塞了状态机和手势，
// 现在手势要按输入方式分（移动端长按 + 上滑取消，桌面端点击），
// 逻辑不该跟着 UI 一起重写。
//
// 三层降级（文档第七章）在这层统一处理：
//   1. 服务端 Whisper —— 默认，唯一在所有设备上行为一致的一层
//   2. 浏览器语音识别 —— 第 1 层不可用或超额时
//   3. 纯打字 —— 前两层都不行时，文本框永远可用
//
// 失败原因要分开，因为提示和后续动作完全不同：
//   权限被拒 → 浏览器语音也没用（它也要麦克风），只能让用户去授权
//   不支持 MediaRecorder → 还能降级到浏览器语音

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  startRecordingDetailed,
  prewarmMicrophone,
  transcribeOnServer,
  startWebSpeech,
  voiceHint,
  type RecorderHandle,
  type PrewarmedMic,
} from '@/lib/voice';

/** 连续这么多秒没听到声音就算「没说话」 */
export const SILENCE_TIMEOUT_MS = 8000;
/** 单次录音最长时长 */
export const MAX_RECORD_MS = 60000;
/** 判定「有声音」的音量阈值 */
export const SILENCE_THRESHOLD = 0.02;

export type VoicePhase = 'idle' | 'ready' | 'recording' | 'transcribing' | 'error';

export interface UseVoiceRecorderOptions {
  token: string | null;
  apiBase: string;
  /** 转写成功 —— 文本交出去（直接落库） */
  onText: (text: string) => void;
  /** 转写完成或失败后回到 idle */
  onDone?: () => void;
}

export interface VoiceRecorder {
  phase: VoicePhase;
  /** 第 1 层服务端转写 / 第 2 层浏览器语音 */
  source: 'server' | 'browser';
  /** 当前音量（0~1），波形取数用 */
  getLevel: () => number;
  /** 浏览器语音的实时字幕 */
  interim: string;
  /** 失败提示 */
  error: string;
  /** 已录秒数 */
  elapsed: number;
  /** 进入语音态但还没开始录（移动端等长按） */
  prepare: () => void;
  /** 开始录音（进入 recording） */
  begin: () => Promise<void>;
  /** 结束录音。discard=true 表示丢弃（用户上滑取消了） */
  end: (discard?: boolean) => Promise<void>;
  /** 放弃一切，回到 idle */
  reset: () => void;
}

export function useVoiceRecorder({
  token, apiBase, onText, onDone,
}: UseVoiceRecorderOptions): VoiceRecorder {
  const [phase, setPhase] = useState<VoicePhase>('idle');
  const [source, setSource] = useState<'server' | 'browser'>('server');
  const [interim, setInterim] = useState('');
  const [error, setError] = useState('');
  const [elapsed, setElapsed] = useState(0);

  const recorderRef = useRef<RecorderHandle | null>(null);
  const webSpeechRef = useRef<{ stop: () => void } | null>(null);
  const browserTextRef = useRef('');
  const lastSoundRef = useRef(0);
  const startedAtRef = useRef(0);
  const silenceTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const tickTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const mountedRef = useRef(true);
  /** 预热好的麦克风 */
  const prewarmPromiseRef = useRef<Promise<PrewarmedMic | null> | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const teardown = useCallback(() => {
    if (silenceTimerRef.current) { clearInterval(silenceTimerRef.current); silenceTimerRef.current = null; }
    if (tickTimerRef.current) { clearInterval(tickTimerRef.current); tickTimerRef.current = null; }
    recorderRef.current?.cancel();
    recorderRef.current = null;
    webSpeechRef.current?.stop();
    webSpeechRef.current = null;
    // 预热了但没用上的麦克风要释放 —— 否则系统的录音指示灯会一直亮着，
    // 用户会以为应用在偷录。
    const pre = prewarmPromiseRef.current;
    prewarmPromiseRef.current = null;
    if (pre) {
      void pre
        .then(p => { if (p) p.stream.getTracks().forEach(t => t.stop()); })
        .catch(() => { /* ignore */ });
    }
  }, []);

  const getLevel = useCallback(() => recorderRef.current?.getLevel() ?? 0, []);

  // ---------- 计时与无声检测 ----------
  const startTimers = useCallback(() => {
    startedAtRef.current = Date.now();
    lastSoundRef.current = Date.now();
    setElapsed(0);

    if (tickTimerRef.current) clearInterval(tickTimerRef.current);
    tickTimerRef.current = setInterval(() => {
      if (!mountedRef.current) return;
      setElapsed(Math.floor((Date.now() - startedAtRef.current) / 1000));
    }, 250);

    if (silenceTimerRef.current) clearInterval(silenceTimerRef.current);
    silenceTimerRef.current = setInterval(() => {
      const rec = recorderRef.current;
      if (!rec) return;
      if (rec.getLevel() > SILENCE_THRESHOLD) {
        lastSoundRef.current = Date.now();
        return;
      }
      // 连续 SILENCE_TIMEOUT_MS 没声音 → 当作没说话
      if (Date.now() - lastSoundRef.current > SILENCE_TIMEOUT_MS) {
        teardown();
        setError('没听到声音，再试一次吧');
        setPhase('error');
      }
    }, 500);
  }, [teardown]);

  // ---------- 第 2 层：浏览器语音 ----------
  const startBrowserLayer = useCallback(() => {
    const handle = startWebSpeech('zh-CN', 1500, {
      onSegment: (seg) => {
        browserTextRef.current += (browserTextRef.current ? ' ' : '') + seg;
        setInterim(browserTextRef.current);
      },
      onInterim: (text) => {
        setInterim(text || browserTextRef.current);
      },
      onError: (code) => {
        teardown();
        setError(voiceHint(code));
        setPhase('error');
      },
      onEnd: () => { webSpeechRef.current = null; },
    });

    if (!handle) {
      teardown();
      setError(voiceHint('NO_WEB_SPEECH'));
      setPhase('error');
      return;
    }

    webSpeechRef.current = handle;
    setSource('browser');
    setPhase('recording');
    startedAtRef.current = Date.now();
    if (tickTimerRef.current) clearInterval(tickTimerRef.current);
    tickTimerRef.current = setInterval(() => {
      if (!mountedRef.current) return;
      setElapsed(Math.floor((Date.now() - startedAtRef.current) / 1000));
    }, 250);
  }, [teardown]);

  const prepare = useCallback(() => {
    setError('');
    setInterim('');
    setElapsed(0);
    browserTextRef.current = '';
    setPhase('ready');
    // 提前把麦克风拿到手 —— 长按时就不用等 getUserMedia 了。
    // 「点语音图标」本身就是用户手势，满足 Safari 的要求。
    prewarmPromiseRef.current = prewarmMicrophone();
  }, []);

  // ---------- 开始 ----------
  const begin = useCallback(async () => {
    setError('');
    setInterim('');
    browserTextRef.current = '';

    // 未激活时服务端转写用不了（第 1 层要 token）。
    // 这时候直接走第 2 层浏览器语音 —— 别让用户先录完 60 秒
    // 再告诉他「登录后才能用」，那是把用户的时间浪费掉。
    if (!token) {
      startBrowserLayer();
      return;
    }

    // 等预热完成（一般已经好了）
    const pre = prewarmPromiseRef.current ? await prewarmPromiseRef.current : null;
    prewarmPromiseRef.current = null;

    const r = await startRecordingDetailed(MAX_RECORD_MS, pre);
    if (!mountedRef.current) { r.handle?.cancel(); return; }

    if (!r.ok) {
      if (r.reason === 'UNSUPPORTED') {
        startBrowserLayer();
        return;
      }
      setError(r.reason === 'NO_PERMISSION' ? voiceHint('NO_MIC') : '麦克风打不开，请重试');
      setPhase('error');
      return;
    }

    recorderRef.current = r.handle!;
    setSource('server');
    setPhase('recording');
    startTimers();
  }, [token, startBrowserLayer, startTimers]);

  // ---------- 结束 ----------
  const end = useCallback(async (discard = false) => {
    if (phase !== 'recording') return;

    // 第 2 层：浏览器语音，文字已经在手上了
    if (source === 'browser') {
      const text = browserTextRef.current.trim();
      webSpeechRef.current?.stop();
      webSpeechRef.current = null;
      if (silenceTimerRef.current) { clearInterval(silenceTimerRef.current); silenceTimerRef.current = null; }
      if (tickTimerRef.current) { clearInterval(tickTimerRef.current); tickTimerRef.current = null; }
      if (discard || !text) {
        setInterim('');
        setPhase('idle');
        onDone?.();
        return;
      }
      setPhase('idle');
      onText(text);
      onDone?.();
      return;
    }

    // 第 1 层：服务端转写
    const rec = recorderRef.current;
    if (!rec) return;
    if (silenceTimerRef.current) { clearInterval(silenceTimerRef.current); silenceTimerRef.current = null; }
    if (tickTimerRef.current) { clearInterval(tickTimerRef.current); tickTimerRef.current = null; }

    if (discard) {
      rec.cancel();
      recorderRef.current = null;
      setPhase('idle');
      onDone?.();
      return;
    }

    setPhase('transcribing');
    const blob = await rec.stop();
    recorderRef.current = null;

    const result = await transcribeOnServer(blob, { token, apiBase });
    if (!mountedRef.current) return;

    if (result.ok) {
      const text = result.segments.join(' ');
      setPhase('idle');
      onText(text);
      onDone?.();
      return;
    }

    // 第 1 层失败 → 降级到第 2 层
    if (result.code === 'ASR_QUOTA_EXCEEDED' || result.code === 'ASR_UNAVAILABLE' || result.code === 'NETWORK') {
      startBrowserLayer();
      return;
    }

    setError(voiceHint(result.code || 'ASR_FAILED'));
    setPhase('error');
  }, [phase, source, token, apiBase, onText, onDone, startBrowserLayer]);

  const reset = useCallback(() => {
    teardown();
    setPhase('idle');
    setError('');
    setInterim('');
    setElapsed(0);
    setSource('server');
    browserTextRef.current = '';
  }, [teardown]);

  // 卸载时清干净
  useEffect(() => teardown, [teardown]);

  return {
    phase, source, getLevel, interim, error, elapsed,
    prepare, begin, end, reset,
  };
}
