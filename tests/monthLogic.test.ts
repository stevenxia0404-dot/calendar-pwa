// 月历逻辑的单测
//
// 为什么必须有：网格计算（哪天落在第几格、上个月补几天、
// 6 行会不会够放）是那种「算错了不报错、只是显示乱」的地方。
// 埋在组件里就只能靠肉眼比对日历 —— 很容易漏。

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMonthGrid, monthStats, lineColor, monthLabel,
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
