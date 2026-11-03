// 月历逻辑的单测
//
// 为什么必须有：网格计算（哪天落在第几格、上个月补几天、
// 6 行会不会够放）是那种「算错了不报错、只是显示乱」的地方。
// 埋在组件里就只能靠肉眼比对日历 —— 很容易漏。

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMonthGrid, monthStats, lineColor, monthLabel, spanDays,
  type MonthEvent,
} from '../src/lib/monthLogic.ts';

function ev(partial: Partial<MonthEvent> = {}): MonthEvent {
  return {
    id: 'x', title: 't', date: '2026-11-02', time: '', endTime: '',
    location: '', people: '', type: 'event', completed: false,
    ...partial,
  };
}

describe('buildMonthGrid —— 网格算得对不对', () => {
  test('固定 6 行 42 格（换月时高度不变）', () => {
    const g = buildMonthGrid(2026, 11, [], new Date(2026, 10, 2));
    assert.equal(g.cells.length, 42);
  });

  test('11 月 1 号是周日 → 周一开头要补 6 格上个月', () => {
    // 2026-11-01 确实是周日
    const g = buildMonthGrid(2026, 11, [], new Date(2026, 10, 2));
    // 前 6 格是上个月的尾巴：10/26 … 10/31
    assert.equal(g.cells[0].day, 26);
    assert.equal(g.cells[5].day, 31);
    assert.equal(g.cells[0].inMonth, false);
    assert.equal(g.cells[0].date, null, '补位格没有日期，不能被点');
    // 第 7 格是 11/1（周日列）
    assert.equal(g.cells[6].day, 1);
    assert.equal(g.cells[6].date, '2026-11-01');
    assert.equal(g.cells[6].inMonth, true);
  });

  test('11 月 2 号落在周一列（索引 7）', () => {
    const g = buildMonthGrid(2026, 11, [], new Date(2026, 10, 2));
    assert.equal(g.cells[7].day, 2);
    assert.equal(g.cells[7].date, '2026-11-02');
  });

  test('今天被正确标记，且只有一个', () => {
    const g = buildMonthGrid(2026, 11, [], new Date(2026, 10, 2));
    const todays = g.cells.filter(c => c.isToday);
    assert.equal(todays.length, 1);
    assert.equal(todays[0].date, '2026-11-02');
  });

  test('不是本月的今天不算今天（比如看 12 月时）', () => {
    const g = buildMonthGrid(2026, 12, [], new Date(2026, 10, 2));
    assert.equal(g.cells.filter(c => c.isToday).length, 0);
  });

  test('2 月（28 天）也能铺满 42 格', () => {
    const g = buildMonthGrid(2026, 2, [], new Date(2026, 1, 10));
    assert.equal(g.cells.length, 42);
    const inMonth = g.cells.filter(c => c.inMonth);
    assert.equal(inMonth.length, 28);
  });

  test('闰年 2 月 29 天', () => {
    const g = buildMonthGrid(2028, 2, [], new Date(2028, 1, 10));
    assert.equal(g.cells.filter(c => c.inMonth).length, 29);
  });

  test('每天的事挂到对应的格子里', () => {
    const events = [
      ev({ id: 'a', date: '2026-11-07', title: '开会' }),
      ev({ id: 'b', date: '2026-11-07', title: '买菜' }),
      ev({ id: 'c', date: '2026-11-07', title: '体检' }),
    ];
    const g = buildMonthGrid(2026, 11, events, new Date(2026, 10, 2));
    const day7 = g.cells.find(c => c.date === '2026-11-07');
    assert.ok(day7);
    assert.equal(day7.lines.length, 3, '7 号有三件事 → 三条横线');
  });
  test('没有事的格子 lines 为空', () => {
    const g = buildMonthGrid(2026, 11, [], new Date(2026, 10, 2));
    const cell = g.cells.find(c => c.date === '2026-11-15');
    assert.ok(cell);
    assert.equal(cell.lines.length, 0);
  });
});

describe('monthStats —— 四宫格怎么算', () => {
  const events: MonthEvent[] = [
    ev({ id: '1', date: '2026-11-02', type: 'event' }),
    ev({ id: '2', date: '2026-11-07', type: 'event' }),
    ev({ id: '3', date: '2026-11-08', type: 'task' }),
    ev({ id: '4', date: '2026-10-15', type: 'event' }),      // 上个月
    ev({ id: '5', date: '2026-11-09', type: 'project' }),
    ev({ id: '6', date: '2026-11-10', type: 'task', completed: true }),
    ev({ id: '7', date: '2026-09-01', type: 'task', completed: true }), // 更早
  ];

  test('日程/任务/项目数的是本月', () => {
    const s = monthStats(events, 2026, 11);
    assert.equal(s.event, 2, '11 月有两条日程');
    assert.equal(s.task, 2, '11 月有两条任务（含已完成那条）');
    assert.equal(s.project, 1, '11 月有一个项目');
  });

  test('完成数的是过往累计（不限本月）', () => {
    const s = monthStats(events, 2026, 11);
    assert.equal(s.completed, 2, '9 月那条也算 —— 过往累计');
  });

  test('上个月的不算进本月的日程', () => {
    const s = monthStats(events, 2026, 11);
    assert.equal(s.event, 2, '10/15 那条不算');
  });

  test('空月份全是 0', () => {
    const s = monthStats([], 2026, 11);
    assert.deepEqual(s, { event: 0, task: 0, project: 0, completed: 0 });
  });
});

describe('lineColor —— 横线的颜色', () => {
  test('日程是橙（主色）、任务是雾青绿、项目是紫', () => {
    assert.equal(lineColor('event', false), '#ED6A3B');
    assert.equal(lineColor('task', false), '#4E7D6C');
    assert.equal(lineColor('project', false), '#7F77DD');
  });

  test('已完成的一律灰 —— 一眼看出做完没', () => {
    assert.equal(lineColor('event', true), '#B4B2A9');
    assert.equal(lineColor('task', true), '#B4B2A9');
  });

  test('未知类型用中性灰，不瞎猜', () => {
    assert.equal(lineColor('whatever', false), '#888780');
  });
});

describe('monthLabel —— 月份名', () => {
  test('不带年份', () => {
    assert.equal(monthLabel(11), '11月');
    assert.equal(monthLabel(1), '1月');
  });
});

// ---------------------------------------------------------------------------
// 划线排序：日程 → 任务 → 项目
//
// 为什么要有这条：一天里可能同时有日程、任务、项目好几条线，
// 全靠颜色认容易看花。固定次序让「日程」永远在最上面。
// ---------------------------------------------------------------------------

describe('格子里划线的排列次序', () => {
  test('日程 → 任务，从上至下', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'k', date: '2026-11-02', type: 'task' }),
      ev({ id: 'e', date: '2026-11-02', type: 'event' }),
    ], new Date(2026, 10, 2));
    const cell = g.cells.find(c => c.date === '2026-11-02')!;
    assert.deepEqual(cell.lines.map(l => l.type), ['event', 'task']);
  });

  test('项目实体不进月历 —— 它是容器，不是某天发生的事', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'p', date: '2026-11-02', type: 'project' }),
      ev({ id: 'e', date: '2026-11-02', type: 'event' }),
    ], new Date(2026, 10, 2));
    const cell = g.cells.find(c => c.date === '2026-11-02')!;
    assert.deepEqual(cell.lines.map(l => l.id), ['e']);
  });

  test('输入顺序打乱也不影响结果（排序是稳定的规则，不靠运气）', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 't1', date: '2026-11-02', type: 'task' }),
      ev({ id: 'e1', date: '2026-11-02', type: 'event' }),
      ev({ id: 't2', date: '2026-11-02', type: 'task' }),
      ev({ id: 'p1', date: '2026-11-02', type: 'event', projectId: 'proj-1' }),
    ], new Date(2026, 10, 2));
    const cell = g.cells.find(c => c.date === '2026-11-02')!;
    // 单日档：日程 → 任务 → 项目
    assert.deepEqual(cell.lines.map(l => l.type), ['event', 'task', 'task', 'event']);
    // 同类型内部保持输入顺序（t1 在 t2 前面）
    assert.deepEqual(cell.lines.map(l => l.id), ['e1', 't1', 't2', 'p1']);
  });

  test('没见过的类型排最后，不抢前三类的位置', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'x', date: '2026-11-02', type: 'note' }),
      ev({ id: 'e', date: '2026-11-02', type: 'event' }),
    ], new Date(2026, 10, 2));
    const cell = g.cells.find(c => c.date === '2026-11-02')!;
    assert.deepEqual(cell.lines.map(l => l.id), ['e', 'x']);
  });

  test('完成的记录仍留在自己那一类里，不单独沉底', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'k', date: '2026-11-02', type: 'task', completed: true }),
      ev({ id: 'e', date: '2026-11-02', type: 'event' }),
    ], new Date(2026, 10, 2));
    const cell = g.cells.find(c => c.date === '2026-11-02')!;
    assert.deepEqual(cell.lines.map(l => l.id), ['e', 'k']);
  });
});

// ---------------------------------------------------------------------------
// 跨日事件：一件事占好几天，月历上要连成一条
// ---------------------------------------------------------------------------

describe('跨日事件占哪几天', () => {
  test('没有结束日期 → 只占一天', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'a', date: '2026-11-21' }),
    ], new Date(2026, 10, 2));
    const days = g.cells.filter(c => c.lines.some(l => l.id === 'a'));
    assert.equal(days.length, 1);
    assert.equal(days[0].lines[0].span, 'single');
  });

  test('21 号到 23 号 → 三天都有线，位置依次是 start / mid / end', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'a', date: '2026-11-21', endDate: '2026-11-23' }),
    ], new Date(2026, 10, 2));
    const d21 = g.cells.find(c => c.date === '2026-11-21')!;
    const d22 = g.cells.find(c => c.date === '2026-11-22')!;
    const d23 = g.cells.find(c => c.date === '2026-11-23')!;
    assert.equal(d21.lines[0].span, 'start');
    assert.equal(d22.lines[0].span, 'mid');
    assert.equal(d23.lines[0].span, 'end');
    // 20 号和 24 号不能有它
    assert.equal(g.cells.find(c => c.date === '2026-11-20')!.lines.length, 0);
    assert.equal(g.cells.find(c => c.date === '2026-11-24')!.lines.length, 0);
  });

  test('跨到下个月：11 月这边算 mid（从上月延续过来的）', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'a', date: '2026-10-28', endDate: '2026-11-03' }),
    ], new Date(2026, 10, 2));
    // 11/1 落在跨度中间 → mid
    assert.equal(g.cells.find(c => c.date === '2026-11-01')!.lines[0].span, 'mid');
    // 11/3 是最后一天 → end
    assert.equal(g.cells.find(c => c.date === '2026-11-03')!.lines[0].span, 'end');
    // 10 月那边才是 start —— 位置按整个跨度算，不按当前月算
    const g10 = buildMonthGrid(2026, 10, [
      ev({ id: 'a', date: '2026-10-28', endDate: '2026-11-03' }),
    ], new Date(2026, 10, 2));
    assert.equal(g10.cells.find(c => c.date === '2026-10-28')!.lines[0].span, 'start');
  });

  test('结束日期等于开始日期 → 仍是单天，不是跨日', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'a', date: '2026-11-21', endDate: '2026-11-21' }),
    ], new Date(2026, 10, 2));
    assert.equal(g.cells.find(c => c.date === '2026-11-21')!.lines[0].span, 'single');
  });

  test('结束日期早于开始日期（脏数据）→ 当单天处理，不画出一串线', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'a', date: '2026-11-21', endDate: '2026-11-19' }),
    ], new Date(2026, 10, 2));
    const days = g.cells.filter(c => c.lines.some(l => l.id === 'a'));
    assert.equal(days.length, 1);
    assert.equal(days[0].lines[0].span, 'single');
  });

  test('结束日期离谱（隔了一年）→ 跨度封顶 60 天，不把月历撑爆', () => {
    // spanDays 本身封顶 60 天
    assert.equal(spanDays('2026-11-21', '2027-11-21').length, 60);
    // 月历里只出现本月内的那些天（11/21 ~ 11/30 共 10 天）
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'a', date: '2026-11-21', endDate: '2027-11-21' }),
    ], new Date(2026, 10, 2));
    const days = g.cells.filter(c => c.lines.some(l => l.id === 'a'));
    assert.equal(days.length, 10);
    assert.equal(days[0].date, '2026-11-21');
    assert.equal(days[9].date, '2026-11-30');
  });

  test('跨日事件排在最前（优先级最高），再按类型排', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'span', date: '2026-11-21', endDate: '2026-11-23', type: 'event' }),
      ev({ id: 'k', date: '2026-11-22', type: 'task' }),
      ev({ id: 'e', date: '2026-11-22', type: 'event' }),
    ], new Date(2026, 10, 2));
    const d22 = g.cells.find(c => c.date === '2026-11-22')!;
    // 跨日的在最上面；下面是 日程 → 任务
    assert.deepEqual(d22.lines.map(l => l.id), ['span', 'e', 'k']);
  });

  test('五个档位：跨日非项目 → 跨日项目 → 单日日程 → 单日任务 → 单日项目', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'spanPlain', date: '2026-11-20', endDate: '2026-11-25' }),
      ev({ id: 'spanProj', date: '2026-11-21', endDate: '2026-11-26', projectId: 'proj-1' }),
      ev({ id: 'singleEvt', date: '2026-11-22', type: 'event' }),
      ev({ id: 'singleTask', date: '2026-11-22', type: 'task' }),
      ev({ id: 'singleProj', date: '2026-11-22', type: 'event', projectId: 'proj-1' }),
    ], new Date(2026, 10, 2));
    const d22 = g.cells.find(c => c.date === '2026-11-22')!;
    assert.deepEqual(d22.lines.map(l => l.id), ['spanPlain', 'spanProj', 'singleEvt', 'singleTask', 'singleProj']);
  });

  test('两个跨日事件之间按开始日期排', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'later', date: '2026-11-20', endDate: '2026-11-25' }),
      ev({ id: 'earlier', date: '2026-11-18', endDate: '2026-11-22' }),
    ], new Date(2026, 10, 2));
    const d21 = g.cells.find(c => c.date === '2026-11-21')!;
    assert.deepEqual(d21.lines.map(l => l.id), ['earlier', 'later']);
  });

  test('同类型的单日之间保持输入顺序（不替用户重排）', () => {
    const g = buildMonthGrid(2026, 11, [
      ev({ id: 'second', date: '2026-11-02', type: 'event' }),
      ev({ id: 'first', date: '2026-11-02', type: 'event' }),
    ], new Date(2026, 10, 2));
    const cell = g.cells.find(c => c.date === '2026-11-02')!;
    assert.deepEqual(cell.lines.map(l => l.id), ['second', 'first']);
  });
});
