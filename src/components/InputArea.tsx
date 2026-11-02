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
//
// 形态（借鉴了聊天类 App 的输入区，但按我们的场景改过）：
//   文字态  胶囊内上下两层 —— 上面是文字区，下面左语音右发送。
//           文字多了胶囊向上长高（底边不动）。
//   语音态  胶囊原地变形。移动端按住说话、松手发送、上滑取消；
//           桌面端点一下开始、再点一下停止。
//           录音中胶囊外面洇开一层光斑 —— 让人看得见设备在听。

'use client';

import { useEffect, useRef, useState } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';
import { parseText, ParsedResult } from '@/lib/dateParser';
import {
  detectCapability,
  isIOS,
  isSafari,
  VoiceCapability,
} from '@/lib/voice';
import { useVoiceRecorder } from '@/lib/useVoiceRecorder';
import VoiceCapsule from '@/components/VoiceCapsule';

/* ==================== 图标 ==================== */

/** 声波图标 —— 语音输入的入口。
    画成三条递增的波，比麦克风更像「正在听」，也更像参考图里那种样式。 */
function AudioWaveIcon() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" viewBox="0 0 24 24">
      <path d="M7 10v4" />
      <path d="M12 6v12" />
      <path d="M17 9v6" />
    </svg>
  );
}

/** 纸飞机 —— 发送。
    不用 lucide 的 Send（那个是直箭头），纸飞机更符合「发消息」的直觉。 */
function SendPlaneIcon() {
  return (
    <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" viewBox="0 0 24 24">
      <path d="M21.5 2.5L11 13" />
      <path d="M21.5 2.5l-6.7 19-3.8-8.5-8.5-3.8 19-6.7z" />
    </svg>
  );
}

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

/** 手指上滑多少算「进取消区」 */
const CANCEL_THRESHOLD_PX = 56;
/** 按住多久算「在说话」（短于此视为误触） */
const HOLD_THRESHOLD_MS = 250;

export default function InputArea({
  apiBase, token, onSubmit, syncState, pendingCount = 0, isNarrow, onActivate,
}: InputAreaProps) {
  const [text, setText] = useState('');
  const [notice, setNotice] = useState('');
  const [capability, setCapability] = useState<VoiceCapability | null>(null);
  /** 平台级限制提示（如 iOS 上只有 Safari 能用麦克风）—— 常驻，不自动消失 */
  const [platformHint, setPlatformHint] = useState('');
  /** 是否在语音态（胶囊已变形） */
  const [voiceMode, setVoiceMode] = useState(false);
  /** 手指已上滑到取消区 */
  const [cancelArmed, setCancelArmed] = useState(false);

  const micBtnRef = useRef<HTMLButtonElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  /** 输入区外壳 —— 用来测高度 */
  const wrapRef = useRef<HTMLDivElement>(null);
  /** 长按计时器 */
  const holdTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** 按下时的纵坐标，用来算上滑距离 */
  const startYRef = useRef(0);
  /** 当前是否真的在录音（长按已过阈值） */
  const holdingRef = useRef(false);
  const cancelArmedRef = useRef(false);

  // 输入区是 fixed 钉在屏幕底部的（文字变多时向上长，而不是把页面往下撑），
  // 所以要把自己的高度写进 CSS 变量，文档流里的占位块据此让出空间。
  // 用 ResizeObserver 而不是只测一次 —— 提示条出现/消失、
  // 进入语音态，高度都会变。
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const publish = () => {
      document.documentElement.style.setProperty('--input-area-h', `${el.offsetHeight}px`);
    };
    publish();
    const ro = new ResizeObserver(publish);
    ro.observe(el);
    return () => {
      ro.disconnect();
      document.documentElement.style.removeProperty('--input-area-h');
    };
  }, []);

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

  const voice = useVoiceRecorder({
    token,
    apiBase,
    onText: (t) => {
      const trimmed = t.trim();
      if (!trimmed) return;
      onSubmit(parseText(trimmed));
    },
    onDone: () => {
      setVoiceMode(false);
      setCancelArmed(false);
    },
  });

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

  // ==================== 语音：进入 / 退出 ====================

  const exitVoiceMode = () => {
    voice.reset();
    setVoiceMode(false);
    setCancelArmed(false);
    cancelArmedRef.current = false;
  };

  const enterVoiceMode = () => {
    if (!capability?.canRecord && !capability?.canWebSpeech) {
      setNotice('这个设备不支持语音，请直接输入文字');
      return;
    }
    setVoiceMode(true);
    setCancelArmed(false);
    cancelArmedRef.current = false;
    voice.prepare();
    // 宽屏：点一下就开始录（保持原来的交互方式）
    if (!isNarrow) {
      void voice.begin();
    }
  };

  // 触感反馈。有就用，没有就跳过 —— 不能依赖它。
  // 注意：Chrome 要求用户激活，长按超过 5 秒后 vibrate 会被静默忽略。
  const buzz = (ms: number) => {
    try {
      if (typeof navigator !== 'undefined' && typeof navigator.vibrate === 'function') {
        navigator.vibrate(ms);
      }
    } catch { /* 不支持就算了 */ }
  };

  // ==================== 语音：移动端长按手势 ====================

  const onVoicePointerDown = (e: ReactPointerEvent) => {
    if (!isNarrow) return;
    try { e.currentTarget.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    startYRef.current = e.clientY;
    holdingRef.current = false;
    if (holdTimerRef.current) clearTimeout(holdTimerRef.current);
    holdTimerRef.current = setTimeout(() => {
      holdingRef.current = true;
      void voice.begin();
      buzz(12);
    }, HOLD_THRESHOLD_MS);
  };

  const onVoicePointerMove = (e: ReactPointerEvent) => {
    if (!isNarrow || !holdingRef.current) return;
    const dy = startYRef.current - e.clientY;
    const armed = dy > CANCEL_THRESHOLD_PX;
    if (armed === cancelArmedRef.current) return;
    cancelArmedRef.current = armed;
    setCancelArmed(armed);
    // 进/出取消区都震一下，让用户不看屏幕也知道状态变了
    buzz(12);
  };

  const onVoicePointerUp = () => {
    if (holdTimerRef.current) { clearTimeout(holdTimerRef.current); holdTimerRef.current = null; }
    if (!holdingRef.current) {
      // 没到长按阈值就松手 = 误触/想退出，退回文字输入
      exitVoiceMode();
      return;
    }
    holdingRef.current = false;
    void voice.end(cancelArmedRef.current);
    setCancelArmed(false);
    cancelArmedRef.current = false;
  };

  const onVoicePointerCancel = () => {
    if (holdTimerRef.current) { clearTimeout(holdTimerRef.current); holdTimerRef.current = null; }
    holdingRef.current = false;
    cancelArmedRef.current = false;
    setCancelArmed(false);
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
    <>
      {/* 占位：把输入区的高度让出来。
          输入区是 fixed 钉在屏幕底部的（这样文字变多时它往上长，
          而不是把页面往下撑），所以文档流里要有个等高的空位，
          否则最后一条记录会被压在输入区底下。 */}
      <div aria-hidden style={{ height: 'var(--input-area-h, 96px)' }} className="shrink-0" />

      <div
        ref={wrapRef}
        // z-[100]：必须高于所有浮层（z-[60]）。
        // 浮层打开时下面的内容全模糊，但输入框永远在最上层、永远清晰可输入 ——
        // 它是「当前编辑目标」的输入框，浮层打开时依然能用。
        className="fixed bottom-0 left-0 right-0 z-[100] shrink-0 pb-[var(--sab)]"
      >
        {/* 未激活提示 —— 这是最容易被忽略、后果最重的一种状态：
            没激活时记下的事只在这台设备上，换台设备看不见。
            顶栏那个小圆点太不起眼，用户会以为一切正常，
            直到发现「手机上看不到」才发现问题。这里给一句明话。

            做成一行小字而不是一块横幅：横幅太占地方，
            而输入区是 fixed 钉在底部的，一块横幅就把壁纸挡掉一大片。 */}
        {!token && (
          <div className="px-4 pt-2">
            <button
              onClick={onActivate}
              className="w-full flex items-center justify-between gap-3 text-left text-[11px] text-[#8A6D3B] hover:text-[#B8860B] transition-colors"
            >
              <span className="min-w-0 truncate">未激活 · 只在这台设备</span>
              <span className="shrink-0 font-medium">去激活 →</span>
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

        <div className="px-3 py-2.5 sm:px-4">
          {voiceMode ? (
            <VoiceCapsule
              phase={voice.phase}
              isNarrow={isNarrow}
              cancelArmed={cancelArmed}
              getLevel={voice.getLevel}
              interim={voice.interim}
              error={voice.error}
              elapsed={voice.elapsed}
              onPointerDown={onVoicePointerDown}
              onPointerMove={onVoicePointerMove}
              onPointerUp={onVoicePointerUp}
              onPointerCancel={onVoicePointerCancel}
              onClick={isNarrow ? undefined : () => {
                if (voice.phase === 'recording') void voice.end(false);
              }}
              onExit={exitVoiceMode}
            />
          ) : (
            /* 横排一行：声波图标 · 文字 · 纸飞机。
               文字多了整颗胶囊向上长高（底边钉在屏幕底部不动）。 */
            <div className="rounded-2xl bg-white/72 backdrop-blur-md border border-white/60 shadow-[0_2px_16px_rgba(28,28,28,0.06)] flex items-end gap-2 px-2 py-2">
              {/* 左：语音图标。点它切到语音态，图标会变成键盘。 */}
              <button
                ref={micBtnRef}
                onClick={enterVoiceMode}
                title="语音记录"
                aria-label="语音记录"
                className="w-9 h-9 rounded-full flex items-center justify-center shrink-0 transition-all hover:bg-white/70 text-[#5C5C5C]"
              >
                <AudioWaveIcon />
              </button>

              {/* 中：文字区 */}
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
                placeholder="发信息或按住说话"
                className="flex-1 min-w-0 bg-transparent px-1 py-1.5 text-[#1C1C1C] outline-none text-sm placeholder:text-[#B4B2A9] resize-none max-h-24 overflow-y-auto block"
              />

              {/* 右：纸飞机 = 发送 */}
              <button
                onClick={handleSubmit}
                disabled={!text.trim()}
                aria-label="记下来"
                className="w-9 h-9 rounded-full bg-[#ED6A3B] hover:bg-[#D45D2E] disabled:opacity-35 text-white flex items-center justify-center shrink-0 transition-all"
              >
                <SendPlaneIcon />
              </button>
            </div>
          )}

          {/* 同步状态 —— 常驻，不需要点进去看。语音态时收起（胶囊里空间紧张）。
              颜色要够深：半透明卡片 + 浅色壁纸的背景下，
              #A0A0A0 的浅灰几乎看不见。 */}
          {!voiceMode && (
            <div className="flex items-center gap-1.5 mt-1.5 px-2">
              <span className={`w-1.5 h-1.5 rounded-full ${syncColor} ${syncState === 'syncing' ? 'animate-pulse' : ''}`} />
              <span className="text-[10px] text-[#6B6B6B]">{syncLabel}</span>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
