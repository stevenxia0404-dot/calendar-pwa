'use client';

// 语音输入面板 —— 录音时看得见
//
// 为什么要有这个面板：
// 原来按下麦克风只有按钮变红，用户不知道设备在不在听、有没有声音、
// 录到了没有。语音是这个产品的核心，不能让人对着一个不知道状态的
// 按钮说话。
//
// 面板的布局（从下往上）：
//   预览文字  ← 结果。最上面
//   波形      ← 状态。中间
//   大按钮    ← 操作。最下面，拇指够得着
// 这个顺序和 iOS 语音备忘录一致：操作压在底部，状态在中间，结果在最上面。
//
// 两条不可让步的规矩：
//   1. 说完就存，不做二次确认（产品说明第四章）。转写完直接交出去。
//   2. 复用 voice.ts 的三层降级，不自己重写一套 ASR。

import { useCallback, useEffect, useRef, useState } from 'react';
import { Mic, Square, X, Loader2, AlertCircle, RotateCcw } from 'lucide-react';
import Waveform from '@/components/Waveform';
import {
  startRecordingDetailed,
  transcribeOnServer,
  startWebSpeech,
  voiceHint,
  type RecorderHandle,
} from '@/lib/voice';

export type VoicePanelState = 'requesting' | 'recording' | 'transcribing' | 'error';

export interface VoicePanelProps {
  open: boolean;
  /** 关闭面板（取消 / Esc / 点遮罩） */
  onClose: () => void;
  /** 转写成功 —— 文本直接交出去落库 */
  onTranscript: (text: string) => void;
  token: string | null;
  apiBase: string;
  /** 窄屏用底部 Sheet，宽屏用居中浮层 */
  isNarrow: boolean;
}

/** 连续这么多秒没听到声音就算「没说话」 */
const SILENCE_TIMEOUT_MS = 8000;
/** 单次录音最长时长 */
const MAX_RECORD_MS = 60000;
/** 判定「有声音」的音量阈值（低于它算静音） */
const SILENCE_THRESHOLD = 0.02;

export default function VoicePanel({
  open, onClose, onTranscript, token, apiBase, isNarrow,
}: VoicePanelProps) {
  const [state, setState] = useState<VoicePanelState>('requesting');
  const [error, setError] = useState('');
  const [interim, setInterim] = useState('');
  const [elapsed, setElapsed] = useState(0);
  /** 第 1 层服务端转写 / 第 2 层浏览器语音 */
  const [source, setSource] = useState<'server' | 'browser'>('server');

  const recorderRef = useRef<RecorderHandle | null>(null);
  const webSpeechRef = useRef<{ stop: () => void } | null>(null);
  /** 浏览器语音攒下的文本 */
  const browserTextRef = useRef('');
  /** 最后一次听到声音的时刻 */
  const lastSoundRef = useRef(0);
  const startedAtRef = useRef(0);
  /** 正在跑的无声检测定时器 */
  const silenceTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const tickTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const closeBtnRef = useRef<HTMLButtonElement>(null);
  const micBtnRef = useRef<HTMLButtonElement>(null);

  // ---------- 清理 ----------
  const teardown = useCallback(() => {
    if (silenceTimerRef.current) { clearInterval(silenceTimerRef.current); silenceTimerRef.current = null; }
    if (tickTimerRef.current) { clearInterval(tickTimerRef.current); tickTimerRef.current = null; }
    recorderRef.current?.cancel();
    recorderRef.current = null;
    webSpeechRef.current?.stop();
    webSpeechRef.current = null;
  }, []);

  // ---------- 计时与无声检测 ----------
  const startTimers = useCallback(() => {
    startedAtRef.current = Date.now();
    lastSoundRef.current = Date.now();

    if (tickTimerRef.current) clearInterval(tickTimerRef.current);
    tickTimerRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAtRef.current) / 1000));
    }, 250);

    if (silenceTimerRef.current) clearInterval(silenceTimerRef.current);
    silenceTimerRef.current = setInterval(() => {
      const rec = recorderRef.current;
      if (!rec) return;
      const lvl = rec.getLevel();
      if (lvl > SILENCE_THRESHOLD) {
        lastSoundRef.current = Date.now();
        return;
      }
      // 连续 SILENCE_TIMEOUT_MS 没声音 → 当作没说话
      if (Date.now() - lastSoundRef.current > SILENCE_TIMEOUT_MS) {
        teardown();
        setError('没听到声音，再试一次吧');
        setState('error');
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
        // 实时字幕：已定稿的 + 还在识别的
        setInterim(text || browserTextRef.current);
      },
      onError: (code) => {
        teardown();
        setError(voiceHint(code));
        setState('error');
      },
      onEnd: () => {
        webSpeechRef.current = null;
      },
    });

    if (!handle) {
      teardown();
      setError(voiceHint('NO_WEB_SPEECH'));
      setState('error');
      return;
    }

    webSpeechRef.current = handle;
    setSource('browser');
    setState('recording');
    // 浏览器语音没有音量表，计时照样走
    startedAtRef.current = Date.now();
    if (tickTimerRef.current) clearInterval(tickTimerRef.current);
    tickTimerRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startedAtRef.current) / 1000));
    }, 250);
  }, [teardown]);

  // ---------- 打开面板：立刻开录 ----------
  useEffect(() => {
    if (!open) {
      teardown();
      setState('requesting');
      setError('');
      setInterim('');
      setElapsed(0);
      setSource('server');
      return;
    }

    let cancelled = false;

    (async () => {
      setState('requesting');

      // 未激活时服务端转写用不了（第 1 层要 token）。
      // 这时候直接走第 2 层浏览器语音 —— 别让用户先录完 60 秒
      // 再告诉他「登录后才能用」，那是把用户的时间浪费掉。
      if (!token) {
        startBrowserLayer();
        return;
      }

      const r = await startRecordingDetailed(MAX_RECORD_MS);
      if (cancelled) { r.handle?.cancel(); return; }

      if (!r.ok) {
        // 没权限就没辙了 —— 浏览器语音同样要麦克风。
        // 不支持 MediaRecorder 才有降级的余地。
        if (r.reason === 'UNSUPPORTED') {
          startBrowserLayer();
          return;
        }
        setError(
          r.reason === 'NO_PERMISSION'
            ? voiceHint('NO_MIC')
            : '麦克风打不开，请重试',
        );
        setState('error');
        return;
      }

      recorderRef.current = r.handle!;
      setState('recording');
      startTimers();
    })();

    // 焦点移进面板
    const t = setTimeout(() => closeBtnRef.current?.focus(), 60);

    return () => {
      cancelled = true;
      clearTimeout(t);
    };
  }, [open, startBrowserLayer, startTimers, teardown, token]);

  // ---------- 关闭 ----------
  const handleClose = useCallback(() => {
    teardown();
    onClose();
  }, [teardown, onClose]);

  // ---------- Esc 关闭 ----------
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); handleClose(); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, handleClose]);

  // ---------- 停止并转写 ----------
  const handleStop = useCallback(async () => {
    if (state !== 'recording') return;

    // 第 2 层：浏览器语音，文字已经在手上了
    if (source === 'browser') {
      const text = browserTextRef.current.trim();
      webSpeechRef.current?.stop();
      webSpeechRef.current = null;
      if (silenceTimerRef.current) { clearInterval(silenceTimerRef.current); silenceTimerRef.current = null; }
      if (tickTimerRef.current) { clearInterval(tickTimerRef.current); tickTimerRef.current = null; }
      if (!text) {
        setError('没听到内容，再试一次吧');
        setState('error');
        return;
      }
      handleClose();
      onTranscript(text);
      return;
    }

    // 第 1 层：服务端转写
    const rec = recorderRef.current;
    if (!rec) return;
    setState('transcribing');
    if (silenceTimerRef.current) { clearInterval(silenceTimerRef.current); silenceTimerRef.current = null; }
    if (tickTimerRef.current) { clearInterval(tickTimerRef.current); tickTimerRef.current = null; }

    const blob = await rec.stop();
    recorderRef.current = null;

    const result = await transcribeOnServer(blob, { token, apiBase });

    if (result.ok) {
      const text = result.segments.join(' ');
      handleClose();
      onTranscript(text);
      return;
    }

    // 第 1 层失败 → 降级到第 2 层
    if (result.code === 'ASR_QUOTA_EXCEEDED' || result.code === 'ASR_UNAVAILABLE' || result.code === 'NETWORK') {
      startBrowserLayer();
      return;
    }

    setError(voiceHint(result.code || 'ASR_FAILED'));
    setState('error');
  }, [state, source, token, apiBase, handleClose, onTranscript, startBrowserLayer]);

  // ---------- 重试 ----------
  const handleRetry = useCallback(() => {
    teardown();
    setError('');
    setInterim('');
    setElapsed(0);
    setSource('server');
    setState('requesting');
    const r = startRecordingDetailed(MAX_RECORD_MS);
    void r.then((res) => {
      if (!res.ok) {
        if (res.reason === 'UNSUPPORTED') { startBrowserLayer(); return; }
        setError(res.reason === 'NO_PERMISSION' ? voiceHint('NO_MIC') : '麦克风打不开，请重试');
        setState('error');
        return;
      }
      recorderRef.current = res.handle!;
      setState('recording');
      startTimers();
    });
  }, [teardown, startBrowserLayer, startTimers]);

  if (!open) return null;

  const recording = state === 'recording';
  const busy = state === 'requesting' || state === 'transcribing';

  const mmss = `${String(Math.floor(elapsed / 60)).padStart(2, '0')}:${String(elapsed % 60).padStart(2, '0')}`;

  // 状态播报给屏幕阅读器
  const liveText = state === 'requesting' ? '正在打开麦克风'
    : state === 'recording' ? `正在录音 ${mmss}`
    : state === 'transcribing' ? '正在转写'
    : error || '语音输入出错';

  const bigButton = (
    <button
      ref={micBtnRef}
      onClick={recording ? handleStop : state === 'error' ? handleRetry : undefined}
      disabled={busy}
      aria-label={recording ? '停止录音' : state === 'error' ? '重试' : '正在准备'}
      className={`w-[88px] h-[88px] rounded-full flex items-center justify-center shrink-0 transition-all disabled:opacity-50 ${
        recording
          ? 'bg-[#EF4444] text-white shadow-[0_0_0_8px_rgba(239,68,68,0.15)]'
          : state === 'error'
          ? 'bg-[#F3F1ED] text-[#EF4444] border-2 border-[#EF4444]'
          : 'bg-[#F3F1ED] text-[#A0A0A0]'
      }`}
    >
      {state === 'requesting' ? <Loader2 className="w-8 h-8 animate-spin" />
        : state === 'transcribing' ? <Loader2 className="w-8 h-8 animate-spin" />
        : state === 'error' ? <RotateCcw className="w-8 h-8" />
        : recording ? <Square className="w-7 h-7 fill-white" />
        : <Mic className="w-8 h-8" />}
    </button>
  );

  const panelBody = (
    <>
      {/* 顶部：转写预览（最上面） */}
      <div className="px-5 pt-4 min-h-[72px]">
        {interim ? (
          <p className="text-[15px] leading-relaxed text-[#1C1C1C] max-h-24 overflow-y-auto">
            {interim}
          </p>
        ) : state === 'error' ? (
          <p className="text-[15px] leading-relaxed text-[#EF4444] flex items-start gap-2">
            <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{error}</span>
          </p>
        ) : state === 'transcribing' ? (
          <p className="text-[15px] text-[#A0A0A0]">正在转写…</p>
        ) : (
          <p className="text-[15px] text-[#A0A0A0]">
            {recording
              ? (source === 'browser' ? '正在听（浏览器语音）…' : '正在听…')
              : state === 'requesting' ? '正在打开麦克风…' : '说点什么吧'}
          </p>
        )}
      </div>

      {/* 中间：波形 */}
      <div className="px-5 py-3">
        <Waveform
          getLevel={() => recorderRef.current?.getLevel() ?? 0}
          active={recording && source === 'server'}
          color={recording ? '#EF4444' : '#D9D4CF'}
          className="w-full h-16"
        />
        <div className="flex items-center justify-center gap-2 mt-2 h-4">
          {recording && (
            <>
              <span className="w-1.5 h-1.5 rounded-full bg-[#EF4444] animate-pulse" />
              <span className="text-[11px] text-[#A0A0A0]">正在录音 · {mmss}</span>
            </>
          )}
        </div>
      </div>

      {/* 底部：大按钮（最下面，拇指区） */}
      <div className="px-5 pb-6 pt-1 flex justify-center">
        {bigButton}
      </div>
    </>
  );

  return (
    <div
      className={`fixed inset-0 z-[80] flex ${isNarrow ? 'items-end' : 'items-center justify-center'} bg-black/40 backdrop-blur-sm`}
      onClick={handleClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="语音输入"
        onClick={e => e.stopPropagation()}
        className={`bg-white flex flex-col ${
          isNarrow
            ? 'w-full rounded-t-3xl max-h-[76vh] pb-[env(safe-area-inset-bottom)] animate-slide-up'
            : 'w-[440px] rounded-3xl max-h-[86vh] animate-panel-in'
        }`}
      >
        {/* 关闭按钮 */}
        <div className="flex justify-end px-4 pt-3">
          <button
            ref={closeBtnRef}
            onClick={handleClose}
            aria-label="关闭语音输入"
            className="w-8 h-8 rounded-full flex items-center justify-center text-[#A0A0A0] hover:bg-[#F3F1ED] transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {panelBody}

        {/* 状态播报给屏幕阅读器。
            语音面板的状态变化全靠视觉传达（按钮变色、波形跳动），
            屏幕阅读器用户看不到 —— 这里把同样的信息念出来。 */}
        <div className="sr-only" role="status" aria-live="polite">{liveText}</div>
      </div>
    </div>
  );
}
