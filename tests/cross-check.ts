// 独立交叉验证：用一份「朴素参考实现」核对 dateParser 的日期计算
//
// 为什么要写这个：dateParser.test.ts 与 dateParser.ts 是同一套思路写出来的，
// 两者一起错的话测试是发现不了的。这里用完全不同的实现方式
// （穷举日历 + 直接查表）重算一遍日期，两边不一致就说明至少有一边错。
//
// 这不是单元测试的一部分，是开发期的一次性核对脚本。

import { parseText } from '../src/lib/dateParser.ts';

const BASE = new Date(2026, 9, 28); // 周三

// —— 独立的日期计算：直接用 Date 算，不复用 dateParser 的任何逻辑 ——

function refToday() { return '2026-10-28'; }

function refOffset(n: number) {
  const d = new Date(2026, 9, 28);
  d.setDate(d.getDate() + n);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

// 上周一 = 10-19, 本周三 = 10-28, 下周五 = 11-06
function refWeek(weekOffset: number, weekday: number) {
  // 基准日是周三，本周一 = 10-26
  const monday = 26;
  const day = monday + weekOffset * 7 + weekday;
  const d = new Date(2026, 9, day);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

const WEEKDAY_NUM: Record<string, number> = { 一: 0, 二: 1, 三: 2, 四: 3, 五: 4, 六: 5, 日: 6 };

// 待核对清单：[输入, 期望日期, 期望时间, 期望描述, 期望 confirmed]
const CASES: [string, string, string, string, number][] = [
  ['今天体检', refToday(), '', '体检', 1],
  ['明天体检', refOffset(1), '', '体检', 1],
  ['后天体检', refOffset(2), '', '体检', 1],
  ['昨天体检', refOffset(-1), '', '体检', 1],
  ['前天体检', refOffset(-2), '', '体检', 1],
  ['大后天体检', refOffset(3), '', '体检', 1],
  ['3天后体检', refOffset(3), '', '体检', 1],
  ['5天前体检', refOffset(-5), '', '体检', 1],
  ['上周一体检', refWeek(-1, 0), '', '体检', 1],
  ['上周三体检', refWeek(-1, 2), '', '体检', 1],
  ['上周五体检', refWeek(-1, 4), '', '体检', 1],
  ['本周五体检', refWeek(0, 4), '', '体检', 1],
  ['下周五体检', refWeek(1, 4), '', '体检', 1],
  ['下周一体检', refWeek(1, 0), '', '体检', 1],
  ['上周日体检', refWeek(-1, 6), '', '体检', 1],
  ['下周日体检', refWeek(1, 6), '', '体检', 1],
];

let fail = 0;
console.log('=== 交叉验证：dateParser vs 朴素参考实现 ===');
console.log('');

for (const [input, expDate, expTime, expTitle, expConfirmed] of CASES) {
  const r = parseText(input, { baseDate: BASE });
  const ok = r.date === expDate && r.time === expTime && r.title === expTitle && r.dateConfirmed === expConfirmed;
  if (!ok) {
    fail++;
    console.log(`✗ ${input}`);
    console.log(`    期望 date=${expDate} time=${expTime} title="${expTitle}" confirmed=${expConfirmed}`);
    console.log(`    实际 date=${r.date} time=${r.time} title="${r.title}" confirmed=${r.dateConfirmed}`);
  } else {
    console.log(`✓ ${input.padEnd(14)} → ${r.date} ${r.time || '(无时间)'} "${r.title}"`);
  }
}

// 逐个核对 WEEKDAY_NUM 与 refWeek 的一致性
console.log('');
console.log('=== 星期映射核对 ===');
for (const [cn, num] of Object.entries(WEEKDAY_NUM)) {
  // 用「本周X」验证：本周一应等于 10-26
  const r = parseText(`本周${cn}体检`, { baseDate: BASE });
  const expected = refWeek(0, num);
  const ok = r.date === expected;
  if (!ok) {
    fail++;
    console.log(`✗ 本周${cn} → ${r.date}，期望 ${expected}`);
  } else {
    console.log(`✓ 本周${cn} → ${r.date}`);
  }
}

console.log('');
console.log(fail === 0 ? '交叉验证全部一致 ✓' : `交叉验证发现 ${fail} 处不一致 ✗`);
process.exit(fail === 0 ? 0 : 1);
