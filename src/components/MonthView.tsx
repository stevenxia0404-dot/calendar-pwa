// 月历卡片 + 四宫格 —— v4.1 的主视图
//
// 结构（从上到下）：
//   月历卡片：十一月（右上角年份）+ 7×6 网格
//              今天用彩色圆圈圈出，日期数字照常显示
//              每天下面挂横线 —— 一件事一条，按类型分颜色
//   四宫格：日程 / 任务 / 项目 / 完成
//
// 为什么不再有周视图：
//   想知道这周每天有什么，点日历里的某一天就够了。
//   一周一屏的时间轴看着清楚，但它只覆盖 7 天；
//   月历能一眼看到整个月，反而更接近日常看日程表的感觉。

'use client';

import { useMemo } from 'react';
import {
  MonthEvent, MonthCell, buildMonthGrid, monthLabel, lineColor, monthStats,
} from '@/lib/monthLogic';

export interface MonthViewProps {
  /** 当前显示的月份 */
  year: number;
  month: number;
  /** 全部记录 */
  events: MonthEvent[];
  today: Date;
  /** 翻月 */
  onPrevMonth?: () => void;
  onNextMonth?: () => void;
  /** 点某一天 */
  onDateClick?: (date: string) => void;
  /** 点四宫格某一格 */
  onStatClick?: (kind: 'event' | 'task' | 'project' | 'completed') => void;
}

const WEEK_HEAD = ['一', '二', '三', '四', '五', '六', '日'];

export default function MonthView({
  year, month, events, today, onPrevMonth, onNextMonth, onDateClick, onStatClick,
}: MonthViewProps) {
  const grid = useMemo(
    () => buildMonthGrid(year, month, events, today),
    [year, month, events, today],
  );
  const stats = useMemo(() => monthStats(events, year, month), [events, year, month]);

  const statItems: { kind: 'event' | 'task' | 'project' | 'completed'; label: string; n: number; color: string }[] = [
    { kind: 'event', label: '日程', n: stats.event, color: '#ED6A3B' },
    { kind: 'task', label: '任务', n: stats.task, color: '#4E7D6C' },
    { kind: 'project', label: '项目', n: stats.project, color: '#7F77DD' },
    { kind: 'completed', label: '完成', n: stats.completed, color: '#888780' },
  ];

  return (
    <>
      {/* ==================== 月历卡片 ====================
          flex-1：卡片自己撑满剩余高度。
          下面四宫格是固定高度的，所以月历有多余空间就往下长 ——
          这样屏幕下半部分不会被壁纸空着。 */}
      <div className="card-glass flex-1 min-h-0 rounded-2xl border border-white/60 shadow-[0_2px_16px_rgba(28,28,28,0.06)] px-3 pt-2.5 pb-2.5 flex flex-col">
        {/* 标题行：左「十一月」，中间翻月箭头，右年份 */}
        <div className="flex items-center justify-between px-1 mb-1">
          <div className="flex items-center gap-1">
            <button onClick={onPrevMonth}
              className="w-7 h-7 rounded-full flex items-center justify-center text-[#5C5C5C] hover:bg-white/70 transition-colors"
              aria-label="上个月">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" /></svg>
            </button>
            <h2 className="text-base font-semibold text-[#1C1C1C] px-1">{monthLabel(month)}</h2>
            <button onClick={onNextMonth}
              className="w-7 h-7 rounded-full flex items-center justify-center text-[#5C5C5C] hover:bg-white/70 transition-colors"
              aria-label="下个月">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
            </button>
          </div>
          <span className="text-xs text-[#A0A0A0] tabular-nums">{year}</span>
        </div>

        {/* 星期表头 */}
        <div className="grid grid-cols-7 gap-1 mb-0.5">
          {WEEK_HEAD.map(w => (
            <div key={w} className="text-center text-[10px] text-[#A0A0A0] font-medium py-0.5">{w}</div>
          ))}
        </div>

        {/* 日期网格 —— flex-1 让 6 行平分卡片剩余高度。
            格子高度跟着变，所以下面的空白被吃掉，壁纸不会空一大块。
            overflow-hidden：空间不够时宁可裁掉一点，也不能把卡片撑破。 */}
        <div className="grid grid-cols-7 gap-1 flex-1 min-h-0 overflow-hidden">
          {grid.cells.map((cell, i) => (
            <MonthCellView key={i} cell={cell} onClick={onDateClick} />
          ))}
        </div>
      </div>

      {/* ==================== 四宫格 ====================
          aspect-[3/2]：每块宽:高 = 3:2。
          4:3 在手机上太夸张（单块 187×140，两排加起来 290px，
          会把月历压得只剩 4 行），3:2 是「明显加大但不挤」的平衡点。
          shrink-0：高度固定，不跟月历抢空间。 */}
      <div className="grid grid-cols-2 gap-2.5 shrink-0">
        {statItems.map(s => (
          <button
            key={s.kind}
            onClick={() => onStatClick?.(s.kind)}
            className="card-glass aspect-[3/2] rounded-2xl border border-white/60 shadow-[0_2px_16px_rgba(28,28,28,0.06)] px-3.5 py-3 flex flex-col justify-between text-left transition-all hover:bg-white/75 active:scale-[0.98]"
          >
            <span className="text-xs text-[#A0A0A0]">{s.label}</span>
            <span className="text-3xl font-medium tabular-nums self-end leading-none" style={{ color: s.color }}>{s.n}</span>
          </button>
        ))}
      </div>
    </>
  );
}

/* ==================== 单个日期格 ==================== */

function MonthCellView({ cell, onClick }: { cell: MonthCell; onClick?: (date: string) => void }) {
  // 今天：彩色圆圈圈出，数字照常显示。
  // 圈不能太大 —— 格里还要放下面的事件横线。
  const isToday = cell.isToday;

  return (
    <button
      onClick={() => cell.date && onClick?.(cell.date)}
      disabled={!cell.date}
      className={`relative flex flex-col items-center justify-start rounded-lg py-1 h-full transition-colors ${
        cell.inMonth ? 'hover:bg-white/60' : ''
      }`}
      aria-label={cell.date ? `${cell.date}` : undefined}
    >
      {/* 今天的圆圈 —— 必须画在数字**底下**。
          顺序很关键：圆圈先画（无 z-index），数字后画（z-10），
          这样数字压在圆上，白字看得清。 */}
      {isToday && (
        <span
          aria-hidden="true"
          className="absolute left-1/2 -translate-x-1/2 top-1 w-[21px] h-[21px] rounded-full bg-[#ED6A3B] shadow-[0_1px_4px_rgba(237,106,59,0.35)]"
        />
      )}

      {/* 日期数字 */}
      <span
        className={`relative z-10 text-[12px] leading-6 tabular-nums ${
          !cell.inMonth ? 'text-[#C0BDB8]' : isToday ? 'text-white font-medium' : 'text-[#1C1C1C]'
        }`}
      >
        {cell.day}
      </span>

      {/* 事件横线 —— 一件事一条，按类型分颜色。
          最多画 4 条：格子高度有限，再多就挤到下一行去了。
          超过 4 条显示 +N。 */}
      <span className="flex flex-col items-center gap-[2px] mt-[2px] w-full px-[3px]">
        {cell.lines.slice(0, 4).map(l => (
          <span
            key={l.id}
            className="block w-full max-w-[26px] h-[2.5px] rounded-full"
            style={{ background: lineColor(l.type, l.completed) }}
            title={l.title}
          />
        ))}
        {cell.lines.length > 4 && (
          <span className="text-[9px] text-[#A0A0A0] leading-none">+{cell.lines.length - 4}</span>
        )}
      </span>
    </button>
  );
}
