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
const GLOW_RECORD = 'rgba(94,157,133,0.46)';
const DOT_RECORD = '#4E7D6C';
/** 上滑取消 —— 暖砖红 */
const GLOW_CANCEL = 'rgba(190,106,88,0.46)';
const DOT_CANCEL = '#A65C48';

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
  const glowColor = cancelArmed ? GLOW_CANCEL : GLOW_RECORD;
  const dotColor = cancelArmed ? DOT_CANCEL : DOT_RECORD;

  // 录音中才洇光斑 —— 光斑是「正在听」的信号，不该常亮
  const showGlow = recording || phase === 'transcribing';

  const statusText = phase === 'transcribing' ? '正在转写…'
    : phase === 'error' ? error
    : cancelArmed ? '松手取消'
    : isNarrow ? '松手发送，上移取消'
    : '点一下结束';

  return (
    <div className="relative" data-testid="voice-capsule">
      {/* 洇开的光斑 —— 比胶囊大一点，不盖全屏 */}
      {showGlow && (
        <div
          aria-hidden="true"
          data-testid="voice-glow"
          className="absolute pointer-events-none"
          style={{
            inset: '-72px -44px',
            background: `radial-gradient(ellipse 62% 58% at 50% 62%, ${glowColor} 0%, ${glowColor.replace(/[\d.]+\)$/, '0.14)')} 42%, transparent 72%)`,
          }}
        />
      )}

      <div
        className="relative rounded-2xl bg-[#F3F1ED] px-3 py-2.5 flex flex-col gap-2 touch-none"
        style={{ touchAction: 'none' }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerCancel}
        onClick={onClick}
      >
        {/* 顶部：圆点阵 + 计时 */}
        <div className="flex items-center gap-3">
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
        <div className="flex items-center gap-2">
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
          <p className="text-[12px] text-[#5C5C5C] leading-relaxed max-h-16 overflow-y-auto">
            {interim}
          </p>
        )}
      </div>
    </div>
  );
}
