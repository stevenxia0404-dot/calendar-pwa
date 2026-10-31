// 周视图的纯逻辑单测
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  toDateString,
  startOfWeek,
  weekDates,
  timeToMinutes,
  weekDayLabel,
  groupByDate,
  eventBlockGeometry,
  AXIS_START,
  AXIS_END,
  PX_PER_HOUR,
} from '../src/lib/weekLogic.ts';

describe('周起始 —— 周一为一周之首', () => {
  test('周三基准日 → 本周一', () => {
    // 2026-10-28 是周三
    assert.equal(toDateString(startOfWeek(new Date(2026, 9, 28))), '2026-10-26');
  });

  test('周一本身就是周一', () => {
    assert.equal(toDateString(startOfWeek(new Date(2026, 9, 26))), '2026-10-26');
  });

  test('周日归到上一个周一', () => {
    // 2026-11-01 是周日 → 本周从 10-26 起
    assert.equal(toDateString(startOfWeek(new Date(2026, 10, 1))), '2026-10-26');
  });

  test('跨月边界', () => {
    // 2026-11-02 是周一 → 本周从 11-02 起
    assert.equal(toDateString(startOfWeek(new Date(2026, 10, 2))), '2026-11-02');
  });

  test('跨年边界', () => {
    // 2027-01-01 是周五 → 本周从 2026-12-28 起
    assert.equal(toDateString(startOfWeek(new Date(2027, 0, 1))), '2026-12-28');
  });
});

describe('一周七天 —— 连续且不重不漏', () => {
  test('基准日是周三，仍返回周一到周日', () => {
    const dates = weekDates(new Date(2026, 9, 28));
    assert.deepEqual(dates, [
      '2026-10-26', '2026-10-27', '2026-10-28', '2026-10-29',
      '2026-10-30', '2026-10-31', '2026-11-01',
    ]);
  });

  test('跨月的一周', () => {
    const dates = weekDates(new Date(2026, 10, 2));
    assert.equal(dates[0], '2026-11-02');
    assert.equal(dates[6], '2026-11-08');
  });

  test('跨年的一周', () => {
    const dates = weekDates(new Date(2027, 0, 1));
    assert.equal(dates[0], '2026-12-28');
    assert.equal(dates[6], '2027-01-03');
  });

  test('总是 7 天，且日期严格递增', () => {
    for (const anchor of [new Date(2026, 0, 1), new Date(2026, 5, 15), new Date(2026, 11, 31)]) {
      const dates = weekDates(anchor);
      assert.equal(dates.length, 7);
      for (let i = 1; i < dates.length; i++) {
        assert.ok(dates[i] > dates[i - 1], `${anchor.toDateString()} 的周日期应递增`);
      }
    }
  });
});

describe('时间定位 —— 用于时间轴上放事件块', () => {
  test('正常时间', () => {
    assert.equal(timeToMinutes('08:50'), 8 * 60 + 50);
    assert.equal(timeToMinutes('00:00'), 0);
    assert.equal(timeToMinutes('23:59'), 23 * 60 + 59);
  });

  test('空串表示无时间', () => {
    assert.equal(timeToMinutes(''), null);
  });

  test('非法值不崩', () => {
    assert.equal(timeToMinutes('abc'), null);
    assert.equal(timeToMinutes('25:00'), null);
    assert.equal(timeToMinutes('10:70'), null);
  });
});

describe('星期标签', () => {
  test('周一到周日', () => {
    assert.equal(weekDayLabel('2026-10-26'), '一');
    assert.equal(weekDayLabel('2026-10-28'), '三');
    assert.equal(weekDayLabel('2026-11-01'), '日');
  });
});

describe('按日期分组 —— 有时间的排前面', () => {
  const events = [
    { id: '1', title: '无时间A', date: '2026-10-28', time: '', endTime: '', location: '', people: '' },
    { id: '2', title: '十点', date: '2026-10-28', time: '10:00', endTime: '', location: '', people: '' },
    { id: '3', title: '八点', date: '2026-10-28', time: '08:00', endTime: '', location: '', people: '' },
    { id: '4', title: '别天', date: '2026-10-29', time: '09:00', endTime: '', location: '', people: '' },
  ];

  test('按日期分开', () => {
    const map = groupByDate(events);
    assert.equal(map.get('2026-10-28')?.length, 3);
    assert.equal(map.get('2026-10-29')?.length, 1);
    assert.equal(map.get('2026-10-30'), undefined);
  });

  test('有时间的按时间升序，无时间的排最后', () => {
    const list = groupByDate(events).get('2026-10-28')!;
    assert.deepEqual(list.map(e => e.title), ['八点', '十点', '无时间A']);
  });
});

describe('事件块几何 —— 时间轴上的位置与高度', () => {
  test('开始时间换算成距顶像素', () => {
    const g = eventBlockGeometry('07:00', '');
    assert.ok(g);
    assert.equal(g.top, 0);
  });

  test('8 点在 7 点下方一小时的位置', () => {
    const g = eventBlockGeometry('08:00', '');
    assert.ok(g);
    assert.equal(g.top, PX_PER_HOUR);
  });

  test('有结束时间则高度 = 时长', () => {
    const g = eventBlockGeometry('10:00', '11:30');
    assert.ok(g);
    assert.equal(g.height, 1.5 * PX_PER_HOUR);
  });

  test('无结束时间给最小高度', () => {
    const g = eventBlockGeometry('10:00', '');
    assert.ok(g);
    assert.equal(g.height, 18);
  });

  test('结束早于开始（脏数据）不崩，给最小高度', () => {
    const g = eventBlockGeometry('11:00', '10:00');
    assert.ok(g);
    assert.equal(g.height, 18);
  });

  test('无时间的事件不上时间轴', () => {
    assert.equal(eventBlockGeometry('', ''), null);
  });

  test('早于刻度起点（7:00）的不画', () => {
    assert.equal(eventBlockGeometry('06:00', ''), null);
  });

  test('晚于刻度终点（21:00）的不画', () => {
    assert.equal(eventBlockGeometry('22:00', ''), null);
  });

  test('刻度范围端点能画', () => {
    assert.ok(eventBlockGeometry('07:00', ''));
    assert.ok(eventBlockGeometry('21:00', ''));
  });

  test('刻度范围是 7 点到 21 点', () => {
    assert.equal(AXIS_START, 7);
    assert.equal(AXIS_END, 21);
  });
});
