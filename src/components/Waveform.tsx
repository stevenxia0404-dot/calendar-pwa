'use client';

// 录音波形 —— 让「正在听」这件事看得见
//
// 三个决定：
//
// 1. **画历史轨迹，不画单根跳动**
//    单根柱随音量上下跳，看着像坏了。保留最近 N 帧、左右滚动，
//    才有「声音的形状」的感觉 —— 说话时的抑扬顿挫会变成起伏的曲线。
//
// 2. **静音时保底一条平线**
//    拿不到音量（没权限 / 不支持 Analyser）时如果什么都不画，
//    用户会以为设备坏了。画一条 2px 的线，意思是「在听，但没声音」。
//
// 3. **上下对称**
//    以中轴为基准上下镜像，是声音波形最经典的样子。
//
// 取数用 Analyser 的 RMS（真实振幅），不是 FFT 频谱 ——
// 频谱好看但那是「音色」，录音波形要的是「有多大声音」。

import { useEffect, useRef } from 'react';

export interface WaveformProps {
  /** 取当前音量（0~1）。由 RecorderHandle.getLevel 提供 */
  getLevel: () => number;
  /** 是否在录音。不录音时画平线 */
  active: boolean;
  /** 柱颜色 */
  color?: string;
  /** 柱数量 */
  bars?: number;
  /**
   * 渲染方式：
   *   bars —— 上下对称的竖条
   *   dots —— 一排圆点，每个点对应最近一帧的时刻
   *
   * 两种共用同一份历史轨迹数据，所以「声音的形状」是一样的，
   * 只是表达方式不同。dots 更轻、更像「一排跳动的点」，
   * 放在胶囊里不喧宾夺主。
   */
  variant?: 'bars' | 'dots';
  className?: string;
}

/** 圆角矩形路径（老的 Safari 不支持 ctx.roundRect） */
function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
  const rr = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + rr, y);
  ctx.lineTo(x + w - rr, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + rr);
  ctx.lineTo(x + w, y + h - rr);
  ctx.quadraticCurveTo(x + w, y + h, x + w - rr, y + h);
  ctx.lineTo(x + rr, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - rr);
  ctx.lineTo(x, y + rr);
  ctx.quadraticCurveTo(x, y, x + rr, y);
  ctx.closePath();
}

export default function Waveform({
  getLevel,
  active,
  color = '#ED6A3B',
  bars = 42,
  variant = 'bars',
  className = '',
}: WaveformProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // 所有会变的参数都走 ref —— effect 只跑一次，
  // 否则每次父组件重渲染都会重建循环、丢掉历史轨迹（波形会闪一下重来）
  const optsRef = useRef({ getLevel, active, color, bars, variant });
  optsRef.current = { getLevel, active, color, bars, variant };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const history: number[] = [];
    let smoothed = 0;
    let raf = 0;

    const draw = () => {
      const { getLevel: get, active: on, color: c, bars: n, variant: kind } = optsRef.current;
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;

      if (w > 0 && h > 0) {
        const pw = Math.round(w * dpr);
        const ph = Math.round(h * dpr);
        if (canvas.width !== pw || canvas.height !== ph) {
          canvas.width = pw;
          canvas.height = ph;
        }
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        ctx.clearRect(0, 0, w, h);

        // 取音量并平滑：上升快、回落慢 —— 声音包络本就是这个形状
        const raw = on ? get() : 0;
        const k = raw > smoothed ? 0.55 : 0.15;
        smoothed += (raw - smoothed) * k;

        history.push(smoothed);
        while (history.length > n) history.shift();

        const mid = h / 2;
        ctx.fillStyle = c;

        if (kind === 'dots') {
          // 一排圆点：每个点对应最近一帧的时刻。
          // 点的大小 = 那一刻的音量，于是说话的高低起伏看得见。
          const gap = 13;
          const count = Math.max(8, Math.min(n, Math.floor(w / gap)));
          const step = w / count;
          const base = Math.min(3.2, step / 2 - 1.5);
          const maxR = Math.max(base + 1, Math.min(step / 2 - 1, base * 2.6));
          const start = history.length - count;
          for (let i = 0; i < count; i++) {
            const v = history[start + i] ?? 0;
            const r = base + v * (maxR - base);
            const x = step * i + step / 2;
            ctx.beginPath();
            ctx.arc(x, mid, r, 0, Math.PI * 2);
            ctx.fill();
          }
        } else {
          const gap = 2;
          const barW = Math.max(1.5, (w - gap * (n - 1)) / n);
          const maxH = Math.max(2, h / 2 - 2);
          for (let i = 0; i < history.length; i++) {
            // 保底 2px：静音时是一条线，不是空白
            const barH = Math.max(2, history[i] * maxH);
            const x = i * (barW + gap);
            roundRect(ctx, x, mid - barH, barW, barH * 2, Math.min(barW / 2, 2));
            ctx.fill();
          }
        }
      }

      raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, []);

  // 波形是纯装饰，交给屏幕阅读器只会变成噪音。
  // min-w-0 必须带上：canvas 的固有宽度（默认 300px）在 flex 容器里
  // 会成为 min-width 下限，不加这一句它会把旁边的计时挤出去胶囊。
  return <canvas ref={canvasRef} className={`min-w-0 ${className}`} aria-hidden="true" />;
}
