// 范围导出的单测
// 其中最重要的一项是 XLSX 的「写 → 读回环」——
// 自己写的文件格式对不对，静态看 XML 看不出来，只有读回来逐格比对才知道。
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  filterByRange,
  sortRows,
  toMatrix,
  toCsv,
  toText,
  escapeCsvField,
  toExportRow,
  weekBounds,
  monthBounds,
  EXPORT_COLUMNS,
} from '../src/lib/exportLib.ts';
import type { ExportRow } from '../src/lib/exportLib.ts';
import { buildXlsx } from '../src/lib/xlsxWriter.ts';

const row = (over: Partial<ExportRow> = {}): ExportRow => ({
  date: '2026-10-28',
  time: '09:00',
  endTime: '10:30',
  title: '初始训练-模拟航班',
  location: '青浦B777经济静态舱',
  people: '张教员',
  raw: '今天下午要把 B777 的乘务应急检查表改完',
  ...over,
});

const BASE = new Date(2026, 9, 31); // 2026-10-31 是周六

describe('范围筛选', () => {
  const rows = [
    row({ date: '2026-10-31', title: '今天' }),
    row({ date: '2026-10-29', title: '本周四' }),
    row({ date: '2026-10-26', title: '本周一' }),
    row({ date: '2026-10-25', title: '上周日' }),
    row({ date: '2026-10-01', title: '本月一号' }),
    row({ date: '2026-09-30', title: '上月' }),
  ];

  test('今天：只含当天', () => {
    const out = filterByRange(rows, 'today', BASE);
    assert.equal(out.length, 1);
    assert.equal(out[0].title, '今天');
  });

  test('本周：周一至周日', () => {
    const out = filterByRange(rows, 'week', BASE);
    // 10-26(一) 到 11-01(日)：本周一、本周四、今天都在范围内
    assert.equal(out.length, 3);
    assert.deepEqual(out.map(r => r.title), ['本周一', '本周四', '今天']);
  });

  test('本月：整月', () => {
    const out = filterByRange(rows, 'month', BASE);
    // 10-01、10-25、10-26、10-29、10-31
    assert.equal(out.length, 5);
  });

  test('上月的不含在内', () => {
    const out = filterByRange(rows, 'month', BASE);
    assert.ok(!out.some(r => r.title === '上月'));
  });

  test('自定义区间', () => {
    const out = filterByRange(rows, 'custom', BASE, { from: '2026-10-01', to: '2026-10-29' });
    // 10-01、10-25、10-26、10-29（10-31 与 09-30 不在区间内）
    assert.equal(out.length, 4);
  });

  test('周起止：周一为一周之首', () => {
    const b = weekBounds(BASE);
    assert.equal(b.from, '2026-10-26');
    assert.equal(b.to, '2026-11-01');
  });

  test('月起止', () => {
    const b = monthBounds(BASE);
    assert.equal(b.from, '2026-10-01');
    assert.equal(b.to, '2026-10-31');
  });
});

describe('排序', () => {
  test('同一天：有时间的按时间升序，无时间的排最后', () => {
    const list = sortRows([
      row({ title: '无时间', time: '' }),
      row({ title: '十点', time: '10:00' }),
      row({ title: '八点', time: '08:00' }),
    ]);
    assert.deepEqual(list.map(r => r.title), ['八点', '十点', '无时间']);
  });

  test('不同天：按日期', () => {
    const list = sortRows([row({ date: '2026-10-30' }), row({ date: '2026-10-28' })]);
    assert.equal(list[0].date, '2026-10-28');
  });
});

describe('导出内容 —— 固定七列，不带完成状态', () => {
  test('表头就是七项', () => {
    assert.deepEqual(EXPORT_COLUMNS, ['日期', '开始时间', '结束时间', '事项', '地点', '人员', '原话']);
  });

  test('每行七列，且不含完成状态列', () => {
    const m = toMatrix([row()]);
    assert.equal(m.length, 2);
    assert.equal(m[0].length, 7);
    assert.equal(m[1].length, 7);
    assert.ok(!m[0].includes('完成'));
    assert.ok(!m[0].includes('状态'));
  });

  test('第七列是原话', () => {
    const m = toMatrix([row()]);
    assert.equal(m[1][6], '今天下午要把 B777 的乘务应急检查表改完');
  });

  test('toExportRow 丢掉内部字段', () => {
    const r = toExportRow({
      date: '2026-10-31', time: '09:00', endTime: '', title: 't',
      location: '', people: '', raw: 'r',
      completed: true, type: 'task', updatedAt: 123, id: 'x', synced: true,
    } as never);
    assert.deepEqual(Object.keys(r).sort(), ['date', 'endTime', 'location', 'people', 'raw', 'time', 'title']);
  });
});

describe('CSV 转义', () => {
  test('普通字段不加引号', () => {
    assert.equal(escapeCsvField('abc'), 'abc');
  });

  test('含逗号的字段要包引号', () => {
    assert.equal(escapeCsvField('备注,带逗号'), '"备注,带逗号"');
  });

  test('字段内的双引号写成两个', () => {
    // 前后各一个引号是包裹，字段内原有的两个引号各变两个
    assert.equal(escapeCsvField('含"引号"的'), '"含""引号""的"');
  });

  test('含换行的字段要包引号', () => {
    assert.equal(escapeCsvField('第一行\n第二行'), '"第一行\n第二行"');
  });

  test('整份 CSV 带 BOM，行间用 CRLF', () => {
    const csv = toCsv([row()]);
    assert.ok(csv.startsWith('﻿'));
    assert.ok(csv.includes('\r\n'));
  });

  test('含逗号的标题不会把行拆错列', () => {
    const csv = toCsv([row({ title: '课,含逗号' })]);
    const dataLine = csv.split('\r\n')[1];
    // 没有特殊字符的字段不加引号，含逗号的必须加 —— 否则整行会被拆错列
    assert.ok(dataLine.startsWith('2026-10-28,09:00,10:30,"课,含逗号"'));
    assert.ok(dataLine.includes('"课,含逗号"'));
  });
});

describe('纯文本导出 —— 写周报最顺手的形态', () => {
  test('按天分组，一天一个小节', () => {
    const txt = toText([
      row({ date: '2026-10-28', time: '08:50', endTime: '10:30', title: '初始训练' }),
      row({ date: '2026-10-28', time: '', title: '整理材料' }),
      row({ date: '2026-10-29', time: '09:00', endTime: '', title: '团队周会' }),
    ]);
    assert.ok(txt.includes('2026-10-28（周三）'));
    assert.ok(txt.includes('2026-10-29（周四）'));
    assert.ok(txt.includes('08:50-10:30  初始训练'));
    assert.ok(txt.includes('  整理材料'));
    assert.ok(txt.includes('09:00  团队周会'));
  });

  test('空区间给一句人话，不给空白', () => {
    assert.equal(toText([]), '（这个区间没有记录）');
  });
});

describe('XLSX —— 写 → 读回环', () => {
  // 用 read-excel-file 读回来逐格比对。
  // read-excel-file 是第 2 步换进来的只读库，正好当验证工具用。
  test('写出来的 xlsx 能被 read-excel-file 读回来，内容逐格一致', async () => {
    const { readSheet } = await import('read-excel-file/universal');
    const matrix = toMatrix([
      row(),
      row({ date: '2026-10-29', time: '', endTime: '', title: '含,逗号', location: '', people: '', raw: '' }),
      row({ date: '2026-10-30', time: '14:00', endTime: '', title: '含"引号"&<>', location: 'C楼201', people: '全组', raw: '原话带 & 符号' }),
    ]);

    const bytes = buildXlsx(matrix);
    assert.ok(bytes.length > 0);

    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const read = await readSheet(ab as ArrayBuffer);

    assert.equal(read.length, matrix.length);
    for (let r = 0; r < matrix.length; r++) {
      for (let c = 0; c < matrix[r].length; c++) {
        const got = read[r][c];
        const want = matrix[r][c];
        assert.equal(got === null || got === undefined ? '' : String(got), want,
          `第 ${r + 1} 行第 ${c + 1} 列不一致：期望「${want}」，实际「${got}」`);
      }
    }
  });

  test('中文表头与中文内容都能读回来', async () => {
    const { readSheet } = await import('read-excel-file/universal');
    const matrix = toMatrix([row()]);
    const bytes = buildXlsx(matrix);
    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const read = await readSheet(ab as ArrayBuffer);
    assert.deepEqual(read[0].slice(0, 7), ['日期', '开始时间', '结束时间', '事项', '地点', '人员', '原话']);
    assert.equal(read[1][3], '初始训练-模拟航班');
  });

  test('空单元格读回来是空而不是 undefined 字符串', async () => {
    const { readSheet } = await import('read-excel-file/universal');
    const bytes = buildXlsx([['a', 'b'], ['x', '']]);
    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const read = await readSheet(ab as ArrayBuffer);
    // 空单元格读回来是 null，不是字符串 'undefined'
    assert.equal(read[1][1], null);
  });

  test('列名超过 Z 用 AA', async () => {
    const { readSheet } = await import('read-excel-file/universal');
    const wide = [Array.from({ length: 28 }, (_, i) => 'c' + i)];
    wide.push(Array.from({ length: 28 }, (_, i) => 'v' + i));
    const bytes = buildXlsx(wide);
    const ab = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const read = await readSheet(ab as ArrayBuffer);
    assert.equal(read[1][26], 'v26');
    assert.equal(read[1][27], 'v27');
  });
});
