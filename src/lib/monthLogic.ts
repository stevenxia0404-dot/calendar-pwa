// 月历的纯逻辑 —— 独立成 .ts 以便单测
//
// 为什么单独一个模块：月历的网格计算（哪一天落在第几格、
// 上个月/下个月的尾巴要不要补）很容易算错，
// 埋在组件里就没法单测 —— 而周视图当年就是因为
// 逻辑埋在 page.tsx 里，才让一个 Excel 时间的小 bug 活了好几个月。

export interface MonthEvent {
  id: string;
  title: string;
  date: string;
  time: string;
  endTime: string;
  location: string;
  people: string;
  /** 类型：日程（有时间的）、任务（没时间的）、项目 */
  type: string;
  completed: boolean;
}

/** 月历格子里的一条 —— 一件事一行 */
export interface MonthLine {
  id: string;
  title: string;
  type: string;
  completed: boolean;
}

export interface MonthCell {
  /** 日期串 YYYY-MM-DD；上下月的补位格为 null */
  date: string | null;
  /** 格子里显示的数字；补位格为 null */
  day: number | null;
  /** 是否是今天 */
  isToday: boolean;
  /** 是否属于当前月份（补位格为 false） */
  inMonth: boolean;
  /** 这天的事，按类型排序 */
  lines: MonthLine[];
}

export interface MonthGrid {
  year: number;
  month: number; // 1-12
  /** 6 行 × 7 列 */
  cells: MonthCell[];
}

/**
 * 生成月历网格。
 *
 * 周一为一周之首（跟周视图一致）。
 * 铺满 6 行 42 格 —— 有些月份需要 6 行才放得下
 * （2026年11月：1号是周日，需要补1天 + 30天 = 31天，正好5行；
 * 但 2027年8月：1号是周日，31天，5行也够；
 * 而 2026年2月：1号是周日，28天 = 4行）。
 * 固定 6 行会让每个月的高度一致 —— 月历卡片不会因为换月就跳高度，
 * 这在固定底部的布局里很重要。
 */
export function buildMonthGrid(year: number, month: number, events: MonthEvent[], today: Date): MonthGrid {
  // 1. 先按日期分组
  const byDate = new Map<string, MonthEvent[]>();
  for (const e of events) {
    const list = byDate.get(e.date) || [];
    list.push(e);
    byDate.set(e.date, list);
  }

  // 2. 这个月 1 号是周几（0=周一 … 6=周日）
  const firstDow = (new Date(year, month - 1, 1).getDay() + 6) % 7;
  const daysInMonth = new Date(year, month, 0).getDate();
  const daysInPrevMonth = new Date(year, month - 1, 0).getDate();

  const cells: MonthCell[] = [];
  const todayStr = toDateStr(today);

  // 3. 上个月的尾巴
  for (let i = firstDow - 1; i >= 0; i--) {
    cells.push({
      date: null, day: daysInPrevMonth - i, isToday: false, inMonth: false, lines: [],
    });
  }

  // 4. 本月
  for (let d = 1; d <= daysInMonth; d++) {
    const ds = `${year}-${String(month).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    const list = byDate.get(ds) || [];
    cells.push({
      date: ds,
      day: d,
      isToday: ds === todayStr,
      inMonth: true,
      lines: list.map(e => ({
        id: e.id, title: e.title, type: e.type, completed: e.completed,
      })),
    });
  }

  // 5. 补到 6 行
  while (cells.length < 42) {
    const n = cells.length - (firstDow + daysInMonth) + 1;
    cells.push({
      date: null, day: n, isToday: false, inMonth: false, lines: [],
    });
  }

  return { year, month, cells };
}

/** 日期 → YYYY-MM-DD */
export function toDateStr(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/** 月份的中文名（不带年份） */
export function monthLabel(month: number): string {
  return `${month}月`;
}

/** 按类型给事件条上色。
 *
 * 类型 → 颜色。这里定了三类的色，第四类（备注/其他）用中性灰。
 * 色相要与产品主色（橙 #ED6A3B）区分开，
 * 又要低饱和 —— 满屏小横线太鲜艳会很吵。
 */
export function lineColor(type: string, completed: boolean): string {
  if (completed) return '#B4B2A9';           // 已完成 → 灰
  switch (type) {
    case 'event': return '#ED6A3B';           // 日程 → 橙（主色）
    case 'task': return '#4E7D6C';            // 任务 → 雾青绿
    case 'project': return '#7F77DD';         // 项目 → 紫
    default: return '#888780';                // 其他/备注 → 中性灰
  }
}

/**
 * 四宫格的统计。
 *
 * 「日程 / 任务 / 项目」数的是**当前这个月**的（跟月历看到的一致）；
 * 「完成」数的是**过往累计**已完成的 —— 所以它可以远大于前三个。
 */
export function monthStats(
  events: MonthEvent[],
  year: number,
  month: number,
) {
  const prefix = `${year}-${String(month).padStart(2, '0')}-`;
  const inMonth = events.filter(e => e.date.startsWith(prefix));
  const done = events.filter(e => e.completed);

  return {
    event: inMonth.filter(e => e.type !== 'task' && e.type !== 'project').length,
    task: inMonth.filter(e => e.type === 'task').length,
    project: inMonth.filter(e => e.type === 'project').length,
    completed: done.length,
  };
}
