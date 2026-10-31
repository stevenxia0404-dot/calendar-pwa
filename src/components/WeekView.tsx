// 周视图 —— v4.0 的主视图
//
// 一屏两区（文档 5.1）：
//   上：七天时间轴，回答「我什么时候在哪、和谁」
//   下：本周流水，回答「我这周做了什么」
//
// 这两块放同一屏是有理由的：课表按周排，周报按周写。
// 月视图把一周摊进三十个格子，反而看不清。
//
// 手机上周视图太挤（每列只有 50px 左右），所以窄屏降级为
// 「今天这一天的竖向时间轴 + 当天流水」，平板和电脑才显示完整一周。

'use client';

import { useMemo } from 'react';
import {
  WeekEvent,
  toDateString,
  weekDates,
  timeToMinutes,
  weekDayLabel,
  groupByDate,
  AXIS_START,
  AXIS_HOURS,
  PX_PER_HOUR,
  eventBlockGeometry,
} from '@/lib/weekLogic';

export type { WeekEvent };

export interface WeekViewProps {
  /** 周内任意一天（用它确定这一周） */
  anchor: Date;
  /** 本周的全部记录 */
  events: WeekEvent[];
  /** 今天（用于高亮） */
  today: Date;
  /** 窄屏降级时显示哪一天 */
  narrowDate: string;
  /** 是否窄屏 */
  isNarrow: boolean;
  onEventClick?: (e: WeekEvent) => void;
}

// ==================== 组件 ====================

export default function WeekView({
  anchor, events, today, narrowDate, isNarrow, onEventClick,
}: WeekViewProps) {
  const dates = useMemo(() => weekDates(anchor), [anchor]);
  const todayStr = toDateString(today);

  const byDate = useMemo(() => groupByDate(events), [events]);

  // 窄屏：只显示一天
  if (isNarrow) {
    const dayEvents = byDate.get(narrowDate) || [];
    const timed = dayEvents.filter(e => timeToMinutes(e.time) !== null);
    const untimed = dayEvents.filter(e => timeToMinutes(e.time) === null);

    // 这一周的全部记录，按天分组。
    // 手机上没有七列时间轴，但「这一周」这段不能省 ——
    // 写周报时要看的就是这一屏。按天分组比按时间轴更适合窄屏。
    const weekFlow = dates.map(ds => ({
      date: ds,
      list: (byDate.get(ds) || []).slice().sort((a, b) => {
        const at = timeToMinutes(a.time);
        const bt = timeToMinutes(b.time);
        if (at !== null && bt !== null) return at - bt;
        if (at !== null) return -1;
        if (bt !== null) return 1;
        return a.title.localeCompare(b.title);
      }),
    })).filter(d => d.list.length > 0);

    return (
      <div className="flex flex-col gap-3">
        {/* 竖向时间轴：今天这一天 */}
        <div className="bg-white/94 backdrop-blur-md rounded-2xl p-4 shadow-sm border border-[#E8E4DF]">
          <h3 className="text-sm font-semibold text-[#1C1C1C] mb-3">
            {narrowDate} 的安排
          </h3>
          {timed.length === 0 && untimed.length === 0 ? (
            <p className="text-sm text-[#A0A0A0] py-6 text-center">这一天还没有安排</p>
          ) : (
            <div className="space-y-2">
              {timed.map(e => (
                <button key={e.id} onClick={() => onEventClick?.(e)}
                  className="w-full text-left px-3 py-2 rounded-xl bg-[#F7F5F2] border border-[#E8E4DF] hover:bg-[#F3F1ED] transition-colors">
                  <div className="text-xs text-[#ED6A3B] font-semibold">
                    {e.time}{e.endTime ? ` - ${e.endTime}` : ''}
                  </div>
                  <div className="text-sm text-[#1C1C1C] font-medium mt-0.5">{e.title}</div>
                  {(e.location || e.people) && (
                    <div className="text-xs text-[#A0A0A0] mt-0.5">
                      {[e.location, e.people].filter(Boolean).join(' · ')}
                    </div>
                  )}
                </button>
              ))}
              {untimed.map(e => (
                <button key={e.id} onClick={() => onEventClick?.(e)}
                  className="w-full text-left px-3 py-2 rounded-xl bg-[#F7F5F2] border border-[#E8E4DF] hover:bg-[#F3F1ED] transition-colors">
                  <div className="text-sm text-[#1C1C1C] font-medium">{e.title}</div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* —— 下区：这一周，按天分组 —— */}
        <div className="bg-white/94 backdrop-blur-md rounded-2xl p-4 shadow-sm border border-[#E8E4DF]">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-sm font-semibold text-[#1C1C1C]">这一周</h3>
            <span className="text-xs text-[#A0A0A0]">{dates[0]} ~ {dates[6]}</span>
          </div>
          {weekFlow.length === 0 ? (
            <p className="text-sm text-[#A0A0A0] py-4 text-center">这一周还没有记录</p>
          ) : (
            <div className="space-y-3">
              {weekFlow.map(d => (
                <div key={d.date}>
                  <div className="text-xs font-semibold text-[#ED6A3B] mb-1.5">{d.date}</div>
                  <div className="space-y-1.5">
                    {d.list.map(e => (
                      <button key={e.id} onClick={() => onEventClick?.(e)}
                        className="w-full text-left px-3 py-2 rounded-xl bg-[#F7F5F2] border border-[#E8E4DF] hover:bg-[#F3F1ED] transition-colors">
                        <div className="text-sm text-[#1C1C1C]">
                          {e.time && <span className="text-[#ED6A3B] font-semibold mr-1.5">{e.time}</span>}
                          {e.title}
                        </div>
                        {(e.location || e.people) && (
                          <div className="text-xs text-[#A0A0A0] mt-0.5">
                            {[e.location, e.people].filter(Boolean).join(' · ')}
                          </div>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    );
  }

  // 宽屏：七列时间轴 + 本周流水
  const weekLabel = `${dates[0]} ~ ${dates[6]}`;
  const flowEvents = events
    .filter(e => timeToMinutes(e.time) === null)
    .sort((a, b) => a.date.localeCompare(b.date));

  return (
    <div className="flex flex-col gap-3">
      {/* —— 上区：七天时间轴 —— */}
      <div className="bg-white/94 backdrop-blur-md rounded-2xl p-4 shadow-sm border border-[#E8E4DF]">
        <div className="flex justify-between items-center mb-3">
          <h3 className="text-sm font-semibold text-[#1C1C1C]">这一周</h3>
          <span className="text-xs text-[#A0A0A0]">{weekLabel}</span>
        </div>

        <div className="flex">
          {/* 时间刻度列 */}
          <div className="w-11 shrink-0">
            {Array.from({ length: AXIS_HOURS + 1 }, (_, i) => (
              <div key={i} className="h-[44px] text-[10px] text-[#C0BDB8] text-right pr-1.5 -mt-1.5 first:mt-0">
                {AXIS_START + i}
              </div>
            ))}
          </div>

          {/* 七天 */}
          <div className="grid grid-cols-7 gap-1 flex-1 min-w-0">
            {dates.map(ds => {
              const dayEvents = byDate.get(ds) || [];
              const timed = dayEvents.filter(e => timeToMinutes(e.time) !== null);
              const isToday = ds === todayStr;
              return (
                <div key={ds}
                  className={`relative rounded-lg ${isToday ? 'bg-[#FFF5F0]' : 'bg-white/55'}`}
                  style={{ height: `${AXIS_HOURS * PX_PER_HOUR}px` }}>
                  {/* 星期头 */}
                  <div className="absolute -top-6 left-0 right-0 text-center">
                    <div className={`text-[10px] font-medium ${isToday ? 'text-[#ED6A3B]' : 'text-[#A0A0A0]'}`}>
                      {weekDayLabel(ds)}
                    </div>
                    <div className={`text-xs font-semibold ${isToday ? 'text-[#ED6A3B]' : 'text-[#5C5C5C]'}`}>
                      {Number(ds.slice(8))}
                    </div>
                  </div>

                  {/* 时间刻度线 */}
                  {Array.from({ length: AXIS_HOURS }, (_, i) => (
                    <div key={i} className="absolute left-0 right-0 border-t border-[#E8E4DF]/60"
                      style={{ top: `${i * PX_PER_HOUR}px` }} />
                  ))}

                  {/* 事件块 */}
                  {timed.map(e => {
                    const geo = eventBlockGeometry(e.time, e.endTime || '');
                    if (!geo) return null;
                    return (
                      <button key={e.id} onClick={() => onEventClick?.(e)}
                        title={`${e.time} ${e.title}`}
                        className="absolute left-0.5 right-0.5 rounded-md bg-[#ED6A3B]/90 text-white text-[10px] leading-tight px-1 py-0.5 overflow-hidden text-left hover:bg-[#D45D2E] transition-colors"
                        style={{ top: `${geo.top}px`, height: `${geo.height}px` }}>
                        <div className="font-semibold truncate">{e.time} {e.title}</div>
                        {e.location && <div className="truncate opacity-90">{e.location}</div>}
                      </button>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* —— 下区：本周流水（没时间的记录）—— */}
      <div className="bg-white/94 backdrop-blur-md rounded-2xl p-4 shadow-sm border border-[#E8E4DF]">
        <h3 className="text-sm font-semibold text-[#1C1C1C] mb-3">这一周</h3>
        {flowEvents.length === 0 ? (
          <p className="text-sm text-[#A0A0A0] py-4 text-center">这一周还没有记录</p>
        ) : (
          <div className="space-y-1.5">
            {flowEvents.map(e => (
              <button key={e.id} onClick={() => onEventClick?.(e)}
                className="w-full flex items-baseline gap-3 text-left px-3 py-2 rounded-lg hover:bg-[#F3F1ED] transition-colors">
                <span className="text-xs text-[#A0A0A0] shrink-0 w-24">{e.date.slice(5)}</span>
                <span className="text-sm text-[#1C1C1C]">{e.title}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

