// 周视图的纯逻辑 —— 独立成 .ts 以便单测
//
// 组件里只做渲染，日期计算与时间定位全在这里。
// 这样 Node 的类型剥离能直接跑（tsx 不行），也便于复用。

export interface WeekEvent {
  id: string;
  title: string;
  date: string;
  time: string;
  endTime: string;
  location: string;
  people: string;
}

export function toDateString(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/** 周一为一周之首 */
export function startOfWeek(d: Date): Date {
  const x = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const dow = (x.getDay() + 6) % 7;
  x.setDate(x.getDate() - dow);
  return x;
}

/** 取一周七天的日期串 */
export function weekDates(anchor: Date): string[] {
  const start = startOfWeek(anchor);
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(start);
    d.setDate(start.getDate() + i);
    return toDateString(d);
  });
}

/** 分钟数，用于在时间轴上定位。空串（无时间）返回 null */
export function timeToMinutes(t: string): number | null {
  if (!t) return null;
  const m = t.match(/^(\d{1,2}):(\d{2})$/);
  if (!m) return null;
  const h = parseInt(m[1], 10);
  const mm = parseInt(m[2], 10);
  if (h > 23 || mm > 59) return null;
  return h * 60 + mm;
}

/** 星期标签 */
export function weekDayLabel(dateStr: string): string {
  const [y, m, d] = dateStr.split('-').map(Number);
  const dow = new Date(y, m - 1, d).getDay();
  return ['日', '一', '二', '三', '四', '五', '六'][dow];
}

/** 按日期分组，并把有时间的排前面 */
export function groupByDate(events: WeekEvent[]): Map<string, WeekEvent[]> {
  const map = new Map<string, WeekEvent[]>();
  for (const e of events) {
    const list = map.get(e.date) || [];
    list.push(e);
    map.set(e.date, list);
  }
  // 用 forEach 而非 for...of —— tsconfig 没设 target（默认 ES5），
  // Map 的迭代器无法直接 for...of。
  map.forEach((list) => {
    list.sort((a, b) => {
      const at = timeToMinutes(a.time);
      const bt = timeToMinutes(b.time);
      if (at !== null && bt !== null) return at - bt;
      if (at !== null) return -1;
      if (bt !== null) return 1;
      return a.title.localeCompare(b.title);
    });
  });
  return map;
}

/** 时间轴刻度范围 */
export const AXIS_START = 7;
export const AXIS_END = 21;
export const AXIS_HOURS = AXIS_END - AXIS_START;
export const PX_PER_HOUR = 44;

/**
 * 算出事件块在时间轴上的位置与高度。
 * 返回 null 表示落在刻度范围外（早于 7:00 或晚于 21:00），不画。
 */
export function eventBlockGeometry(
  time: string,
  endTime: string,
): { top: number; height: number } | null {
  const start = timeToMinutes(time);
  if (start === null) return null;

  const top = ((start - AXIS_START * 60) / 60) * PX_PER_HOUR;
  // 早于刻度起点（7:00）的不画 —— 画了会被容器裁掉，留下一半露在外面反而更乱。
  if (top < 0) return null;
  // 晚于刻度终点（21:00）的不画。21:00 恰好在终点刻度线上，能画。
  if (top > AXIS_HOURS * PX_PER_HOUR) return null;

  const end = timeToMinutes(endTime || '');
  const height = end && end > start
    ? Math.max(((end - start) / 60) * PX_PER_HOUR, 18)
    : 18;

  return { top: Math.max(top, 0), height };
}
