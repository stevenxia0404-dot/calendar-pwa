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
  isIOS,
  isSafari,
  VoiceCapability,
} from '@/lib/voice';
import VoicePanel from '@/components/VoicePanel';

export interface InputAreaProps {
  /** API 基址 */
  apiBase: string;
  /** 登录令牌，未登录时语音走不了服务端 */
  token: string | null;
  /** 一句话进来 → 返回解析结果与原话 */
  onSubmit: (parsed: ParsedResult) => void;
  /** 同步状态 */
  syncState: 'syncing' | 'synced' | 'offline';
  /** 队列里还有几条没传上去 */
  pendingCount?: number;
  /** 窄屏 */
  isNarrow: boolean;
  /** 点「去激活」→ 打开激活弹窗 */
  onActivate?: () => void;
}

export default function InputArea({
  apiBase, token, onSubmit, syncState, pendingCount = 0, isNarrow, onActivate,
}: InputAreaProps) {
  const [text, setText] = useState('');
  const [notice, setNotice] = useState('');
  const [capability, setCapability] = useState<VoiceCapability | null>(null);
  /** 平台级限制提示（如 iOS 上只有 Safari 能用麦克风）—— 常驻，不自动消失 */
  const [platformHint, setPlatformHint] = useState('');
  /** 语音面板是否打开 */
  const [voiceOpen, setVoiceOpen] = useState(false);

  const micBtnRef = useRef<HTMLButtonElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    setCapability(detectCapability());
    // iOS 上只有 Safari 能用麦克风，Chrome/Firefox/Edge 的 iOS 版一律被系统挡掉。
    // 与其让人点了麦克风才撞墙（报「没有麦克风权限」，但设置里根本找不到开关），
    // 不如一进来就告诉他该用哪个浏览器。
    if (isIOS() && !isSafari()) {
      setPlatformHint('iPhone 上语音只能用 Safari 打开 —— 复制网址到 Safari 就能用');
    }
  }, []);

  // 输入框自增高：1 行到 4 行封顶，超出内部滚动
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 96)}px`;
  }, [text]);

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

  // ==================== 语音：打开面板 ====================
  //
  // 三层降级（服务端 Whisper → 浏览器语音 → 打字）现在都在
  // VoicePanel 里面。这里只负责把面板叫出来。
  //
  // 为什么要面板：原来按下麦克风只有按钮变红，用户不知道设备在不在听、
  // 有没有声音。面板里能看到实时波形，录音这件��才有反馈。

  const openVoicePanel = () => {
    if (!capability?.canRecord && !capability?.canWebSpeech) {
      setNotice('这个设备不支持语音，请直接输入文字');
      return;
    }
    setVoiceOpen(true);
  };

  // 面板关掉后，焦点回到麦克风按钮 —— 别让焦点掉到 body 上，
  // 键盘用户会「丢失位置」。
  const handlePanelClose = () => {
    setVoiceOpen(false);
    setTimeout(() => micBtnRef.current?.focus(), 60);
  };

  // ==================== 同步状态 ====================

  // 队列非空时把条数显示出来 —— 「离线待同步」这四个字
  // 让人知道东西还在，但不知道有多少、是不是真在等。
  //
  // 没激活时不能说「已同步」—— 根本没同步过。
  // 绿点 + 已同步 会让人以为东西在云端，换台设备却看不到。
  const syncLabel = !token
    ? '未激活 · 只在这台设备'
    : pendingCount > 0
    ? `${syncState === 'offline' ? '离线待同步' : '待同步'} ${pendingCount}`
    : {
        syncing: '同步中',
        synced: '已同步',
        offline: '离线待同步',
      }[syncState];
  const syncColor = !token
    ? 'bg-[#D9D4CF]'
    : {
        syncing: 'bg-[#ED6A3B]',
        synced: 'bg-[#059669]',
        offline: 'bg-[#D9D4CF]',
      }[syncState];

  return (
    <div className="shrink-0 border-t border-[#E8E4DF] bg-white/90 backdrop-blur-md">
      {/* 语音面板 —— 录音时看得见波形 */}
      <VoicePanel
        open={voiceOpen}
        onClose={handlePanelClose}
        onTranscript={(text) => submitText(text)}
        token={token}
        apiBase={apiBase}
        isNarrow={isNarrow}
      />
      {/* 未激活提示 —— 这是最容易被忽略、后果最重的一种状态：
          没激活时记下的事只在这台设备上，换台设备看不见。
          顶栏那个小圆点太不起眼，用户会以为一切正常，
          直到发现「手机上看不到」才发现问题。这里给一句明话。 */}
      {!token && (
        <div className="px-4 pt-2">
          <button
            onClick={onActivate}
            className="w-full flex items-center justify-between gap-3 text-left text-[11px] text-[#8A6D3B] bg-[#FFF9EC] border border-[#F0E2C0] rounded-lg px-3 py-2 hover:bg-[#FFF4DC] transition-colors"
          >
            <span className="min-w-0">未激活 · 记下的事只存在这台设备上，手机电脑看不到</span>
            <span className="shrink-0 font-medium text-[#B8860B]">去激活 →</span>
          </button>
        </div>
      )}

      {/* 平台级限制提示 —— 语音是这个产品的核心，
          但 iOS 上只有 Safari 能用麦克风。与其让人点了才知道，
          不如一进来就说清楚。 */}
      {platformHint && (
        <div className="px-4 pt-2">
          <p className="text-xs text-[#8A6D3B] bg-[#FFF9EC] border border-[#F0E2C0] rounded-lg px-3 py-2">
            {platformHint}
          </p>
        </div>
      )}

      {/* 提示条 */}
      {notice && (
        <div className="px-4 pt-2">
          <p className="text-xs text-[#ED6A3B] bg-[#FFF5F0] rounded-lg px-3 py-1.5 inline-block">
            {notice}
          </p>
        </div>
      )}

      <div className="px-4 py-3">
        <div className="flex items-end gap-2 bg-[#F3F1ED] p-1.5 rounded-2xl">
          {/* 麦克风 —— 打开语音面板 */}
          <button
            ref={micBtnRef}
            onClick={openVoicePanel}
            title="语音记录"
            aria-label="语音记录"
            className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 transition-all hover:bg-[#E8E4DF] text-[#5C5C5C]"
          >
            <Mic className="w-5 h-5" />
          </button>

          {/* 文本框 —— 与麦克风是同一件事的两个入口。
              用 textarea 而不是 input：一句话可能很长（「明天下午三点在 C 楼 201
              开组会，顺便把上次的检查表带过去」），单行 input 只能看到尾巴。
              自增高 1~4 行封顶。 */}
          <textarea
            ref={textareaRef}
            value={text}
            onChange={e => setText(e.target.value)}
            onKeyDown={e => {
              // Enter 发送，Shift+Enter 换行。
              // 中文输入法打字时 Enter 是选词，不能当发送 —— 用 isComposing 区分。
              if (e.key === 'Enter' && !e.nativeEvent.isComposing && !e.shiftKey) {
                e.preventDefault();
                handleSubmit();
              }
            }}
            rows={1}
            placeholder={isNarrow ? '说一句…' : '说一句就记下来…'}
            className="flex-1 bg-transparent px-2 py-2.5 text-[#1C1C1C] outline-none text-sm placeholder:text-[#A0A0A0] min-w-0 resize-none max-h-24 overflow-y-auto"
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
