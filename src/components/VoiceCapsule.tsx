'use client';

// 语音态的胶囊 —— 原地变形，不弹层
//
// 形态（从截图借来的，但改成我们的浅色 + 我们的配色）：
//   ready      左=收起键盘  中=「按住说话」  右=×
//   recording  一排圆点 + 文案 + 计时，外面洇开一层光斑
//   cancel     手指上滑后的样子：光斑转砖红，文案变「松手取消」
//
// 光斑在浅色底上不是「发光」，是「洇开」——
// 像水彩渗在纸上。低透明度的径向渐变，中心浓边缘淡。
// 深色底上那种荧光发光搬过来会刺眼，而且在米白底上根本看不见。

import type { PointerEvent as ReactPointerEvent } from 'react';
import { Keyboard, Square, X } from 'lucide-react';
import Waveform from '@/components/Waveform';
import type { VoicePhase } from '@/lib/useVoiceRecorder';

/** 录音中（松手就发送）—— 雾青绿 */
const GLOW_RECORD = '76,152,118';
/** 上滑取消 —— 暖砖红 */
const GLOW_CANCEL = '186,98,80';
const DOT_RECORD = '#3E6B57';
const DOT_CANCEL = '#A65C48';

/**
 * 外层光斑：胶囊外围的大范围洇开。
 *
 * 范围要够大、衰减要够慢 —— 浅色底上低饱和色的光斑很吃范围，
 * 范围一小就什么都看不见。
 *
 * 注意两个颜色的浓度不一样：绿在米白底上的对比天然弱于红
 * （人眼对红绿的光感受不对称，红在浅底上更跳）。
 * 如果两边用同一个浓度，结果就是「取消态很醒目、录音态没变化」，
 * 用户会以为没录上。所以绿这边加浓一点，让两种状态的视觉强度对齐。
 */
function outerGlow(rgb: string, alpha: number): string {
  return `radial-gradient(ellipse 74% 66% at 50% 56%, rgba(${rgb},${alpha}) 0%, rgba(${rgb},${alpha * 0.3}) 46%, transparent 82%)`;
}

/**
 * 内层染色：盖在胶囊自己身上的一层薄色。
 *
 * 为什么需要它：光斑在胶囊**后面**，而胶囊是不透明的 ——
 * 光斑最浓的中心会被整个挡住，只有衰减后的边缘透出来。
 * 所以胶囊内部要单独染一层，否则「发光」的感觉出不来。
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
  onPointerUp?: (e: ReactPointerEvent) => void;
  onPointerCancel?: (e: ReactPointerEvent) => void;
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
  const glowAlpha = isCancel ? 0.44 : 0.56;
  const dotColor = isCancel ? DOT_CANCEL : DOT_RECORD;

  // 录音中才洇光斑 —— 光斑是「正在听」的信号，不该常亮
  const showGlow = recording || phase === 'transcribing';

  const statusText = phase === 'transcribing' ? '正在转写…'
    : phase === 'error' ? error
    : cancelArmed ? '松手取消'
    : isNarrow ? '松手发送，上移取消'
    : '点一下结束';

  return (
    <div className="relative" data-testid="voice-capsule">
      {/* 外层光斑 —— 胶囊外围的大范围洇开。
          在胶囊下面（z-0），胶囊在 z-10，所以最浓的部分被胶囊挡住是故意的：
          外面那圈才是要给人看的「光晕」。胶囊内部另有薄薄一层染色。 */}
      {showGlow && (
        <div
          aria-hidden="true"
          data-testid="voice-glow"
          className="absolute pointer-events-none z-0"
          style={{
            inset: '-120px -70px',
            background: outerGlow(glowColor, glowAlpha),
          }}
        />
      )}

      <div
        className="relative z-10 rounded-2xl bg-[#F3F1ED] px-3 py-2.5 flex flex-col gap-2"
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
        {/* 内层染色 —— 给胶囊染一点环境色。
            内容在它之上（z-30），文字和点阵不会被染。 */}
        {showGlow && (
          <div
            aria-hidden="true"
            data-testid="voice-glow-inner"
            className="absolute inset-0 rounded-2xl pointer-events-none z-20"
            style={{ background: innerGlow(glowColor, isCancel ? 0.24 : 0.30) }}
          />
        )}

        {/* 顶部：圆点阵 + 计时 */}
        <div className="relative z-30 flex items-center gap-3">
          <Waveform
            getLevel={getLevel}
            active={recording}
            color={dotColor}
            variant="dots"
            bars={34}
            className="flex-1 h-7"
          />
          {recording && (
            <span className="text-[11px] text-[#A0A0A0] tabular-nums shrink-0">{mmss(elapsed)}</span>
          )}
        </div>

        {/* 底部：文案 + 控件 */}
        <div className="relative z-30 flex items-center gap-2">
          <button
            onClick={(e) => { e.stopPropagation(); onExit(); }}
            aria-label="收起语音输入，回到文字输入"
            className="w-8 h-8 rounded-lg flex items-center justify-center text-[#A0A0A0] hover:bg-[#E8E4DF] transition-colors shrink-0"
          >
            <Keyboard className="w-4 h-4" />
          </button>

          <p
            className={`flex-1 text-center text-[13px] font-medium truncate ${
              phase === 'error' ? 'text-[#A65C48]'
                : cancelArmed ? 'text-[#A65C48]'
                : 'text-[#5C5C5C]'
            }`}
            aria-live="polite"
          >
            {phase === 'ready'
              ? (isNarrow ? '按住说话' : '点一下说话')
              : statusText}
          </p>

          {recording && isNarrow ? (
            <span className="w-8 h-8 flex items-center justify-center shrink-0" aria-hidden="true">
              <span className="w-2.5 h-2.5 rounded-full bg-[#5E9D85] animate-pulse" />
            </span>
          ) : recording ? (
            <button
              onClick={(e) => { e.stopPropagation(); onClick?.(); }}
              aria-label="停止录音"
              className="w-8 h-8 rounded-lg flex items-center justify-center text-[#A65C48] hover:bg-[#E8E4DF] transition-colors shrink-0"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
            </button>
          ) : (
            <button
              onClick={(e) => { e.stopPropagation(); onExit(); }}
              aria-label="关闭语音输入"
              className="w-8 h-8 rounded-lg flex items-center justify-center text-[#A0A0A0] hover:bg-[#E8E4DF] transition-colors shrink-0"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* 实时字幕（第 2 层浏览器语音才有） */}
        {interim && (
          <p className="relative z-30 text-[12px] text-[#5C5C5C] leading-relaxed max-h-16 overflow-y-auto">
            {interim}
          </p>
        )}
      </div>
    </div>
  );
}
