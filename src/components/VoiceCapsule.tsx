'use client';

// 语音态的胶囊 —— 原地变形，不弹层
//
// 形态（v4.2）：
//   单行，跟文字态的输入胶囊**一样高**（54px）。
//   左=收起键盘   中=状态文案（+计时/实时字幕）   右=停止/关闭
//
// 三个决定：
//
// 1. **跟文字态一样高**
//    以前语音态是「波形一行 + 文案一行」，整颗胶囊长高一倍。
//    底部输入区是 fixed 钉在屏幕底部的，它一长高，文档流里的占位块
//    也跟着长，月历就被顶掉一截 —— 切换输入方式时整个页面在动。
//    现在两种形态共用一张卡（.capsule-bar），只换内容，不换尺寸。
//
// 2. **不画波纹线**
//    那排绿色圆点占了整整一行高度，而且跟弥散光斑抢同一份注意力。
//    状态识别交给光斑：录音时整颗卡片洇开一层绿，上滑取消时转砖红。
//
// 3. **光斑随音量呼吸**
//    波纹线拿掉后，用户唯一能看到的「我正在说话」的反馈就是光斑强弱。
//    跟着麦克风音量起伏 —— 静默时暗、说话时亮，
//    一眼能分出「没录上」和「在录」。
//
// 光斑在浅色底上不是「发光」，是「洇开」——
// 像水彩渗在纸上。低透明度的径向渐变，中心浓边缘淡。
// 深色底上那种荧光发光搬过来会刺眼，而且在米白底上根本看不见。

import { useEffect, useRef } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';
import { Keyboard, Square, X } from 'lucide-react';
import type { VoicePhase } from '@/lib/useVoiceRecorder';

/** 录音中（松手就发送）—— 雾青绿 */
const GLOW_RECORD = '76,152,118';
/** 上滑取消 —— 暖砖红 */
const GLOW_CANCEL = '186,98,80';

/**
 * 外层光斑：胶囊外围的大范围洇开。
 *
 * 范围要够大、衰减要够慢 —— 浅色底上低饱和色的光斑很吃范围，
 * 范围一小就什么都看不见。
 *
 * 光心放在卡片**下缘**（at 50% 62%），不放在正中间：
 * 卡片是半透明的，光心在正中间时最浓的部分整个被卡片挡住，
 * 外面只剩一圈几乎看不见的余光。挪到下缘，光就是从卡片底下
 * 往上洇、往两边溢 —— 那才是「设备在听」该有的样子。
 *
 * 注意两个颜色的浓度不一样：绿在米白底上的对比天然弱于红
 * （人眼对红绿的光感受不对称，红在浅底上更跳）。
 * 如果两边用同一个浓度，结果就是「取消态很醒目、录音态没变化」，
 * 用户会以为没录上。所以绿这边加浓一点，让两种状态的视觉强度对齐。
 */
function outerGlow(rgb: string, alpha: number): string {
  return `radial-gradient(ellipse 78% 78% at 50% 62%, rgba(${rgb},${alpha}) 0%, rgba(${rgb},${alpha * 0.42}) 42%, rgba(${rgb},${alpha * 0.12}) 68%, transparent 88%)`;
}

/**
 * 内层染色：盖在胶囊自己身上的一层薄色。
 *
 * 为什么需要它：光斑在胶囊**后面**，而卡片是半透明的 ——
 * 光斑最浓的中心会被糊掉一层，只剩衰减后的边缘透出来。
 * 所以胶囊内部再单独染一层，「发光」的感觉才出得来。
 */
function innerGlow(rgb: string, alpha: number): string {
  return `radial-gradient(ellipse 92% 84% at 50% 50%, rgba(${rgb},${alpha}) 0%, transparent 74%)`;
}

export interface VoiceCapsuleProps {
  phase: VoicePhase;
  /** 窄屏用长按 + 上滑取消，宽屏用点击 */
  isNarrow: boolean;
  /** 手指已上滑到取消区 */
  cancelArmed: boolean;
  /** 当前音量 */
  getLevel: () => number;
  /** 浏览器语音的实时字幕 */
  interim: string;
  /** 失败提示 */
  error: string;
  /** 已录秒数 */
  elapsed: number;
  onPointerDown?: (e: ReactPointerEvent) => void;
  onPointerMove?: (e: ReactPointerEvent) => void;
  onPointerUp?: () => void;
  onPointerCancel?: () => void;
  /** 宽屏点一下开始 / 再点一下停止 */
  onClick?: () => void;
  /** 退出语音态 */
  onExit: () => void;
}

function mmss(sec: number): string {
  return `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`;
}

export default function VoiceCapsule({
  phase, isNarrow, cancelArmed, getLevel, interim, error, elapsed,
  onPointerDown, onPointerMove, onPointerUp, onPointerCancel, onClick, onExit,
}: VoiceCapsuleProps) {
  const recording = phase === 'recording';
  // 绿加浓、红用常规浓度 —— 让两种状态的视觉强度对齐
  const isCancel = cancelArmed;
  const glowColor = isCancel ? GLOW_CANCEL : GLOW_RECORD;

  // 光斑强弱分三档：
  //   ready      只微微泛绿 —— 说明「现在是语音态」，但还没在录
  //   recording  洇开 —— 正在听
  //   cancel     转砖红
  const glowAlpha = isCancel ? 0.72 : phase === 'ready' ? 0.30 : 0.85;
  const innerAlpha = isCancel ? 0.28 : phase === 'ready' ? 0.10 : 0.34;

  const showGlow = phase === 'ready' || recording || phase === 'transcribing';

  const outerRef = useRef<HTMLDivElement>(null);
  const innerRef = useRef<HTMLDivElement>(null);

  // 光斑随音量呼吸 —— 波形线取消后，这是用户唯一能看到的「在说话」的反馈。
  // 直接改 style 而不是 setState：每帧 setState 会把整棵树重渲染一遍。
  useEffect(() => {
    if (!recording) return;
    // 把节点抓在手里：cleanup 里再读 ref.current 拿到的是**卸载后**的节点，
    // 复位会打在错的元素上。
    const outer = outerRef.current;
    const inner = innerRef.current;
    let raf = 0;
    let smoothed = 0;
    const tick = () => {
      const raw = getLevel();
      const level = Number.isFinite(raw) ? Math.max(0, Math.min(1, raw)) : 0;
      // 上升快、回落慢 —— 跟声音包络的形状一致
      smoothed += (level - smoothed) * (level > smoothed ? 0.5 : 0.12);
      const outerOpacity = Math.min(1, 0.70 + smoothed * 0.5);
      const innerOpacity = Math.min(1, 0.75 + smoothed * 0.6);
      if (outer) outer.style.opacity = String(outerOpacity);
      if (inner) inner.style.opacity = String(innerOpacity);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      // 复位：录音结束回到待命/关闭时，光斑不该留着上一轮的亮度
      if (outer) outer.style.opacity = '1';
      if (inner) inner.style.opacity = '1';
    };
  }, [recording, getLevel]);

  // 中间那行显示什么 —— 有实时字幕就显示字幕（那才是用户想看的），
  // 取消态永远显示「松手取消」，红色优先。
  const showInterim = recording && !isCancel && !!interim;
  const middleText = isCancel ? '松手取消'
    : phase === 'transcribing' ? '正在转写…'
    : phase === 'error' ? (error || '出了点问题，再试一次')
    : phase === 'ready' ? (isNarrow ? '按住说话' : '点一下说话')
    : showInterim ? interim
    : isNarrow ? '松手发送，上移取消'
    : '点一下结束';

  const middleColor = isCancel || phase === 'error' ? 'text-[#A65C48]'
    : showInterim ? 'text-[#3A3A3A]'
    : 'text-[#5C5C5C]';

  return (
    <div className="relative" data-testid="voice-capsule">
      {/* 外层光斑 —— 胶囊外围的大范围洇开。
          在胶囊下面（z-0），胶囊在 z-10，所以最浓的部分被卡片糊住是故意的：
          外面那圈才是要给人看的「光晕」。胶囊内部另有薄薄一层染色。 */}
      {showGlow && (
        <div
          ref={outerRef}
          aria-hidden="true"
          data-testid="voice-glow"
          className="absolute pointer-events-none z-0"
          style={{
            inset: '-140px -90px',
            background: outerGlow(glowColor, glowAlpha),
          }}
        />
      )}

      <div
        // h-[54px]：跟文字态的胶囊一模一样高，切换输入方式时尺寸不变。
        className="capsule-bar relative z-10 h-[54px] px-2 flex items-center gap-2"
        style={{
          touchAction: 'none',
          // 长按会触发浏览器原生的选词与浮动工具条 ——
          // 那是「我要选中这段字」的行为，不是「我要按住说话」的行为。
          // touch-action: none 只挡滚动和缩放，挡不住选词，得单独关。
          userSelect: 'none',
          WebkitUserSelect: 'none',
          // iOS 长按还会弹「复制/粘贴/查找」的原生菜单
          WebkitTouchCallout: 'none',
        } as React.CSSProperties}
        onContextMenu={e => e.preventDefault()}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerCancel}
        onClick={onClick}
      >
        {/* 内层染色 —— 给卡片染一点环境色。
            内容在它之上（z-10），文字和按钮不会被染。 */}
        {showGlow && (
          <div
            ref={innerRef}
            aria-hidden="true"
            data-testid="voice-glow-inner"
            className="absolute inset-0 rounded-2xl pointer-events-none z-0"
            style={{ background: innerGlow(glowColor, innerAlpha) }}
          />
        )}

        {/* 左：收起键盘，回到文字输入 */}
        <button
          onPointerDown={e => e.stopPropagation()}
          onClick={(e) => { e.stopPropagation(); onExit(); }}
          aria-label="收起语音输入，回到文字输入"
          className="relative z-10 w-9 h-9 rounded-lg flex items-center justify-center text-[#6E6E6E] hover:bg-white/70 transition-colors shrink-0"
        >
          <Keyboard className="w-4 h-4" />
        </button>

        {/* 中：状态文案 + 计时 */}
        <div className="relative z-10 flex-1 min-w-0 flex items-center justify-center gap-2">
          <p
            className={`text-[13px] font-medium truncate ${middleColor}`}
            aria-live="polite"
          >
            {middleText}
          </p>
          {recording && (
            <span className="text-[11px] text-[#8A8A8A] tabular-nums shrink-0">{mmss(elapsed)}</span>
          )}
        </div>

        {/* 右：停止 / 关闭。
            移动端录音中不显示停止按钮（松手就发），留一个同尺寸的占位，
            这样「有没有按钮」不会让中间那行左右跳。 */}
        {recording && !isNarrow ? (
          <button
            onPointerDown={e => e.stopPropagation()}
            onClick={(e) => { e.stopPropagation(); onClick?.(); }}
            aria-label="停止录音"
            className="relative z-10 w-9 h-9 rounded-lg flex items-center justify-center text-[#A65C48] hover:bg-white/70 transition-colors shrink-0"
          >
            <Square className="w-3.5 h-3.5 fill-current" />
          </button>
        ) : recording ? (
          <span className="w-9 h-9 shrink-0" aria-hidden="true" />
        ) : (
          <button
            onPointerDown={e => e.stopPropagation()}
            onClick={(e) => { e.stopPropagation(); onExit(); }}
            aria-label="关闭语音输入"
            className="relative z-10 w-9 h-9 rounded-lg flex items-center justify-center text-[#6E6E6E] hover:bg-white/70 transition-colors shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}
