// 输入区 —— v4.0 的唯一输入入口
//
// 「说话就记」：麦克风按钮在一伸手就够得着的地方，按下去说，
// 说完它就在那儿了。不弹确认卡片，不跳转到别的地方。
//
// 文本框是同一件事的另一个入口，不是聊天框 —— 没有对话历史，
// 没有「创建/查询」两步，就是一句话进一条记录。
//
// 语音三层降级（文档第七章）：
//   1. 服务端 Whisper —— 默认，唯一在所有设备上行为一致的一层
//   2. 浏览器语音识别 —— 第 1 层不可用或超额时
//   3. 纯打字 —— 前两层都不行时，文本框永远可用
//
// 解析走纯规则（第八章）：算出日期 + 干净描述，解不出就落今天 + 标待确认。

'use client';

import { useEffect, useRef, useState } from 'react';
import { Mic, Send } from 'lucide-react';
import { parseText, ParsedResult } from '@/lib/dateParser';
import {
  detectCapability,
  transcribeOnServer,
  startWebSpeech,
  startRecording,
  describeError,
  VoiceCapability,
} from '@/lib/voice';

export interface InputAreaProps {
  /** API 基址 */
  apiBase: string;
  /** 登录令牌，未登录时语音走不了服务端 */
  token: string | null;
  /** 一句话进来 → 返回解析结果与原话 */
  onSubmit: (parsed: ParsedResult) => void;
  /** 同步状态 */
  syncState: 'syncing' | 'synced' | 'offline';
  /** 窄屏 */
  isNarrow: boolean;
}

type VoiceState = 'idle' | 'recording' | 'transcribing' | 'browser';

export default function InputArea({
  apiBase, token, onSubmit, syncState, isNarrow,
}: InputAreaProps) {
  const [text, setText] = useState('');
  const [voiceState, setVoiceState] = useState<VoiceState>('idle');
  const [notice, setNotice] = useState('');
  const [capability, setCapability] = useState<VoiceCapability | null>(null);

  const recorderRef = useRef<{ stop: () => Promise<Blob>; cancel: () => void } | null>(null);
  const webSpeechRef = useRef<{ stop: () => void } | null>(null);

  useEffect(() => {
    setCapability(detectCapability());
    return () => {
      recorderRef.current?.cancel();
      webSpeechRef.current?.stop();
    };
  }, []);

  // 提示 3 秒后自动消失
  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(''), 3000);
    return () => clearTimeout(t);
  }, [notice]);

  // ==================== 提交 ====================

  const submitText = (raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed) return;
    onSubmit(parseText(trimmed));
    setText('');
  };

  const handleSubmit = () => {
    if (!text.trim()) return;
    submitText(text);
  };

  // ==================== 语音：第 1 层（服务端） ====================

  const startServerVoice = async () => {
    if (!token) {
      setNotice('登录后才能用语音记录');
      return;
    }
    setVoiceState('recording');
    const rec = await startRecording(60000);
    if (!rec) {
      // 拿不到麦克风 → 降级到浏览器语音，再不行就是打字
      setNotice('没有麦克风权限');
      startBrowserVoice();
      return;
    }
    recorderRef.current = rec;
  };

  const stopServerVoice = async () => {
    const rec = recorderRef.current;
    recorderRef.current = null;
    if (!rec) return;

    setVoiceState('transcribing');
    const blob = await rec.stop();
    const result = await transcribeOnServer(blob, { token, apiBase });

    if (result.ok) {
      // 一句话可能包含多件事，逐段入库
      for (const seg of result.segments) {
        submitText(seg);
      }
      setVoiceState('idle');
      return;
    }

    // 第 1 层失败 → 降级
    const msg = describeError(result.code || 'ASR_FAILED');
    setNotice(msg);
    setVoiceState('idle');
    // 额度耗尽或服务端不可用 → 试第 2 层
    if (result.code === 'ASR_QUOTA_EXCEEDED' || result.code === 'ASR_UNAVAILABLE' || result.code === 'NETWORK') {
      startBrowserVoice();
    }
  };

  // ==================== 语音：第 2 层（浏览器） ====================

  const startBrowserVoice = () => {
    const handle = startWebSpeech('zh-CN', 1500, {
      onSegment: (seg) => {
        submitText(seg);
      },
      onError: (code) => {
        setNotice(code === 'NO_MIC' ? '没有麦克风权限，请直接输入文字' : describeError(code));
      },
      onEnd: () => {
        setVoiceState('idle');
      },
    });
    if (handle) {
      webSpeechRef.current = handle;
      setVoiceState('browser');
      setNotice('已切到浏览器语音');
    } else {
      setVoiceState('idle');
      setNotice('这个浏览器不支持语音，请直接输入文字');
    }
  };

  // ==================== 麦克风按钮 ====================

  const toggleVoice = () => {
    if (voiceState === 'recording') {
      void stopServerVoice();
      return;
    }
    if (voiceState === 'browser') {
      webSpeechRef.current?.stop();
      webSpeechRef.current = null;
      setVoiceState('idle');
      return;
    }
    if (voiceState === 'transcribing') return;

    // 第 1 层优先
    if (capability?.canRecord) {
      void startServerVoice();
    } else if (capability?.canWebSpeech) {
      startBrowserVoice();
    } else {
      setNotice('这个设备不支持语音，请直接输入文字');
    }
  };

  // ==================== 同步状态 ====================

  const syncLabel = {
    syncing: '同步中',
    synced: '已同步',
    offline: '离线待同步',
  }[syncState];
  const syncColor = {
    syncing: 'bg-[#ED6A3B]',
    synced: 'bg-[#059669]',
    offline: 'bg-[#D9D4CF]',
  }[syncState];

  const micLabel = {
    idle: '语音记录',
    recording: '说完点这里',
    transcribing: '识别中',
    browser: '浏览器语音中',
  }[voiceState];

  return (
    <div className="shrink-0 border-t border-[#E8E4DF] bg-white/90 backdrop-blur-md">
      {/* 提示条 */}
      {notice && (
        <div className="px-4 pt-2">
          <p className="text-xs text-[#ED6A3B] bg-[#FFF5F0] rounded-lg px-3 py-1.5 inline-block">
            {notice}
          </p>
        </div>
      )}

      <div className="px-4 py-3">
        <div className="flex items-center gap-2 bg-[#F3F1ED] p-1.5 rounded-2xl">
          {/* 麦克风 */}
          <button
            onClick={toggleVoice}
            disabled={voiceState === 'transcribing'}
            title={micLabel}
            aria-label={micLabel}
            className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 transition-all disabled:opacity-40 ${
              voiceState === 'recording'
                ? 'bg-red-500 text-white animate-pulse'
                : voiceState === 'browser'
                ? 'bg-[#ED6A3B] text-white'
                : 'hover:bg-[#E8E4DF] text-[#5C5C5C]'
            }`}
          >
            <Mic className="w-5 h-5" />
          </button>

          {/* 文本框 —— 与麦克风是同一件事的两个入口 */}
          <input
            type="text"
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.nativeEvent.isComposing) handleSubmit();
            }}
            placeholder={isNarrow ? '说一句…' : '说一句就记下来…'}
            className="flex-1 bg-transparent px-2 py-2.5 text-[#1C1C1C] outline-none text-sm placeholder:text-[#A0A0A0] min-w-0"
          />

          <button
            onClick={handleSubmit}
            disabled={!text.trim()}
            aria-label="记下来"
            className="w-10 h-10 bg-[#ED6A3B] hover:bg-[#D45D2E] disabled:opacity-40 rounded-xl text-white flex items-center justify-center shrink-0 transition-all"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>

        {/* 同步状态 —— 常驻，不需要点进去看 */}
        <div className="flex items-center gap-1.5 mt-2 px-1">
          <span className={`w-1.5 h-1.5 rounded-full ${syncColor} ${syncState === 'syncing' ? 'animate-pulse' : ''}`} />
          <span className="text-[10px] text-[#A0A0A0]">{syncLabel}</span>
        </div>
      </div>
    </div>
  );
}
