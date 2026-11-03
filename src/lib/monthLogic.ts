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
  /** 跨日事件的结束日期（含当天，YYYY-MM-DD）；空 = 不跨日 */
  endDate?: string;
  /** 归属的项目 id；空 = 不属于任何项目 */
  projectId?: string;
  location: string;
  people: string;
  /** 类型：日程（有时间的）、任务（没时间的）、项目 */
  type: string;
  completed: boolean;
}

/**
 * 跨日事件在某一天的**位置**。
 *
 * 为什么要分位置：一条线画在 21 号和画在 23 号，形状不一样 ——
 * 开始那天左端是圆头（左边没有延续），中间两端都是方头，
 * 最后那天右端是圆头。拼起来才是一条完整的事。
 */
export type SpanPos = 'single' | 'start' | 'mid' | 'end';

/** 月历格子里的一条 —— 一件事一行 */
export interface MonthLine {
  id: string;
  title: string;
  type: string;
  completed: boolean;
  /** 这条线在跨日事件里处于第几天 */
  span: SpanPos;
  /** 这件事的开始日期（跨日排序用） */
  startDate: string;
  /** 归属的项目 id；空 = 不属于任何项目 */
  projectId?: string;
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
 * 类型在格子里的排列次序：日程 → 任务 → 项目。
 *
 * 为什么固定次序：一天里可能同时有四五件事，全靠颜色区分不够 ——
 * 固定次序让「日程」永远在最上面（最该被看见的），
 * 「任务」其次，「项目」垫底。整月所有格子一个规律，扫一眼就懂。
 *
 * 同类型内部保持原有相对顺序（sort 是稳定的），
 * 不去按时间重排 —— 日程之间谁先谁后是用户自己定的顺序，不该由程序改。
 */
const TYPE_RANK: Record<string, number> = {
  event: 0,    // 日程
  task: 1,     // 任务
  project: 2,  // 项目
};
/** 没见过的类型（旧数据、以后新增的类型）排最后，不跟前三类抢位置 */
const TYPE_RANK_FALLBACK = 3;

function typeRank(type: string): number {
  const r = TYPE_RANK[type];
  return r === undefined ? TYPE_RANK_FALLBACK : r;
}

/**
 * 格子里划线的排序规则。
 *
 * 五个档位，从上到下：
 *   0  跨日 · 不属于项目
 *   1  跨日 · 属于项目   ← 跨日里项目相关排后面
 *   2  单日 · 日程（橙）
 *   3  单日 · 任务（绿）
 *   4  单日 · 属于项目（紫）← 项目在日程任务之后
 *
 * 为什么跨日最前：它横跨好几天，连起来的那条线是格子里最该被看见的东西；
 * 压到日程下面去就白连了。
 *
 * 为什么跨日项目排在跨日非项目后面：项目的线连着好几格，
 * 让它压在别人上面会挡住别的线。
 *
 * 同档内：跨日的按开始日期排；同类型的单日返回 0 ——
 * 靠 sort 的稳定性保持用户自己的输入顺序，不替用户重排。
 */
function compareLines(a: MonthLine, b: MonthLine): number {
  const tierA = lineTier(a);
  const tierB = lineTier(b);
  if (tierA !== tierB) return tierA - tierB;

  // 同一档里再按类型排（跨日档里可能混着日程和任务）
  const tA = typeRank(a.type);
  const tB = typeRank(b.type);
  if (tA !== tB) return tA - tB;

  // 两个都是跨日 → 按开始日期
  if (a.span !== 'single') return a.startDate.localeCompare(b.startDate);

  // 同类型的单日 → 0，保持原有相对顺序
  return 0;
}

/** 划线的档位 —— 数字越小越靠上 */
function lineTier(line: MonthLine): number {
  const isSpan = line.span !== 'single';
  const isProject = !!line.projectId;
  if (isSpan) return isProject ? 1 : 0;
  if (isProject) return 4;
  return typeRank(line.type) === 0 ? 2 : 3;
}

/**
 * 一个事件占哪几天。
 *
 * 跨日事件要占**从开始日到结束日的每一天** —— 月历上每天画一段，
 * 段与段之间接起来，才是「一件事连着好几天」的样子。
 *
 * 位置（start/mid/end）是按**整个跨度**算的，不是按当前月算：
 * 一个 10/28 到 11/3 的事，在 11 月视图里 11/1 那段是 'mid'（左端方头，
 * 表示「从上月延续过来」），切到 10 月看 10/28 那段才是 'start'。
 *
 * 上限 60 天：end_date 是用户填的，写错了不能让月历无限画线。
 */
const MAX_SPAN_DAYS = 60;

export function spanDays(start: string, end?: string): string[] {
  if (!end || end <= start) return [start];
  const out: string[] = [];
  const d = new Date(start + 'T00:00:00');
  const last = new Date(end + 'T00:00:00');
  if (Number.isNaN(d.getTime()) || Number.isNaN(last.getTime())) return [start];
  while (d.getTime() <= last.getTime() && out.length < MAX_SPAN_DAYS) {
    out.push(toDateStr(d));
    d.setDate(d.getDate() + 1);
  }
  return out;
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
  // 1. 先按日期分组。
  //    跨日事件会落进它占的**每一天** —— 不然它只在开始那天出现，
  //    后面几天就断了，连不成一条线。
  const byDate = new Map<string, { e: MonthEvent; span: SpanPos }[]>();
  for (const e of events) {
    // 项目实体不进月历 —— 它是容器（「这些事属于它」），不是某天发生的事。
    if (e.type === 'project') continue;
    const days = spanDays(e.date, e.endDate);
    const last = days.length - 1;
    days.forEach((d, i) => {
      const span: SpanPos = last === 0 ? 'single'
        : i === 0 ? 'start'
        : i === last ? 'end'
        : 'mid';
      const list = byDate.get(d) || [];
      list.push({ e, span });
      byDate.set(d, list);
    });
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
      lines: (list || [])
        .map(({ e, span }) => ({
          id: e.id, title: e.title, type: e.type, completed: e.completed, span,
          startDate: e.date, projectId: e.projectId,
        }))
        // 跨日排最前，然后 日程 → 任务 → 项目
        .sort(compareLines),
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
export function lineColor(type: string, completed: boolean, projectId?: string): string {
  if (completed) return '#B4B2A9';           // 已完成 → 灰
  if (projectId) return '#7F77DD';          // 属于项目 → 紫
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
 * 「日程 / 任务」数的是**当前这个月**的（跟月历看到的一致）；
 * 「完成」数的是**过往累计**已完成的 —— 所以它可以远大于前三个。
 *
 * 「项目」数的是**项目个数**（累计，不是本月）。
 * 为什么不是本月：项目本身没有日期（它是「这些事属于它」的容器，
 * 不是某天发生的事），没有月份可归 —— 跟「完成」一个口径。
 *
 * 「日程 / 任务」里**不含**挂在项目下的事 ——
 * 那些事在项目格里体现（在项目卡里能看到它下面有几条）。
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
    event: inMonth.filter(e => e.type === 'event' && !e.projectId).length,
    task: inMonth.filter(e => e.type === 'task' && !e.projectId).length,
    project: events.filter(e => e.type === 'project').length,
    completed: done.filter(e => e.type !== 'project').length,
  };
}
