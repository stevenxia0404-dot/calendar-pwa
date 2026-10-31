// 课表导入解析的单测
// 重点是那条原则：只认明确的列，不猜。
// 「猜」会用不确定覆盖确定 —— Excel 里写好的时间本来是对的，
// 标题里出现「3点」就把它覆盖掉是纯粹的破坏。
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseImportRows,
  looksLikeHeader,
  mapColumns,
  normalizeDate,
  normalizeTime,
} from '../src/lib/importParser.ts';
import { parseCsvLine, escapeCsvField, toCsvLine } from '../src/lib/csv.ts';

describe('CSV 原语', () => {
  test('普通行按逗号切分', () => {
    assert.deepEqual(parseCsvLine('a,b,c'), ['a', 'b', 'c']);
  });

  test('引号包起来的字段里逗号不算分隔符', () => {
    assert.deepEqual(parseCsvLine('a,"b,c",d'), ['a', 'b,c', 'd']);
  });

  test('字段里的两个引号还原成一个', () => {
    assert.deepEqual(parseCsvLine('a,"含""引号""的",d'), ['a', '含"引号"的', 'd']);
  });

  test('转义与解析是互逆的', () => {
    for (const v of ['普通', '含,逗号', '含"引号"', '换\n行', '']) {
      const line = toCsvLine([v]);
      assert.deepEqual(parseCsvLine(line)[0], v, `「${v}」转义后解析不回来`);
    }
  });

  test('escapeCsvField 与 toCsvLine 一致', () => {
    assert.equal(escapeCsvField('含,逗号'), '"含,逗号"');
    assert.equal(toCsvLine(['a', '含,逗号']), 'a,"含,逗号"');
  });
});

describe('值归一化 —— 只认标准格式，不猜', () => {
  test('日期只认 YYYY-MM-DD', () => {
    assert.equal(normalizeDate('2026-11-02'), '2026-11-02');
    assert.equal(normalizeDate('2026/11/02'), '');
    assert.equal(normalizeDate('11月2日'), '');
    assert.equal(normalizeDate('下周二'), '');
    assert.equal(normalizeDate(''), '');
  });

  test('时间认 H:mm 与 HH:mm，其它不认', () => {
    assert.equal(normalizeTime('08:50'), '08:50');
    assert.equal(normalizeTime('8:50'), '08:50');
    assert.equal(normalizeTime('下午3点'), '');
    assert.equal(normalizeTime('25:00'), '');
    assert.equal(normalizeTime(''), '');
  });
});

describe('表头识别', () => {
  test('标准表头是表头', () => {
    assert.equal(looksLikeHeader('日期,开始时间,结束时间,事项,地点,人员,备注'), true);
  });

  test('没有日期列的表头也是表头', () => {
    assert.equal(looksLikeHeader('时间,事项,地点'), true);
  });

  test('第一格是合法日期 → 是数据不是表头', () => {
    assert.equal(looksLikeHeader('2026-11-04,,,整理文档,,,培训材料归档'), false);
  });

  test('带时间的数据行不是表头', () => {
    assert.equal(looksLikeHeader('2026-11-02,08:50,10:30,初始训练,青浦,张教员,备注'), false);
  });

  test('普通数据不是表头', () => {
    assert.equal(looksLikeHeader('2026-11-02,08:50,初始训练'), false);
  });

  test('空行不是表头', () => {
    assert.equal(looksLikeHeader(''), false);
  });
});

describe('列映射', () => {
  test('标准表头映射正确', () => {
    const idx = mapColumns(['日期', '开始时间', '结束时间', '事项', '地点', '人员', '备注']);
    assert.deepEqual(idx, { date: 0, time: 1, endTime: 2, content: 3, location: 4, people: 5, note: 6 });
  });

  test('「结束时间」不会被「时间」抢走', () => {
    const idx = mapColumns(['日期', '时间', '结束时间', '事项']);
    assert.equal(idx.time, 1);
    assert.equal(idx.endTime, 2);
  });

  test('表头顺序不同也能对上', () => {
    const idx = mapColumns(['事项', '日期', '开始时间']);
    assert.equal(idx.content, 0);
    assert.equal(idx.date, 1);
    assert.equal(idx.time, 2);
  });

  test('同义词能认出来', () => {
    const idx = mapColumns(['日期', '内容', '位置', '参与人']);
    assert.equal(idx.content, 1);
    assert.equal(idx.location, 2);
    assert.equal(idx.people, 3);
  });
});

describe('行解析 —— 核心是「不猜」', () => {
  test('标题里出现「3点」，不会覆盖时间列', () => {
    // 这是最要紧的一条：Excel 里写的是 08:50，标题里恰好有「3点」，
    // 旧实现会把它改成 03:00 或 15:00 —— 用不确定覆盖确定。
    const rows = parseImportRows(
      '日期,开始时间,结束时间,事项,地点,人员,备注\n2026-11-02,08:50,10:30,3点开会,C楼201,全组,',
      true,
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0].time, '08:50');
    assert.equal(rows[0].endTime, '10:30');
    assert.equal(rows[0].title, '3点开会');
  });

  test('标题里有日期词也不会覆盖日期列', () => {
    const rows = parseImportRows(
      '日期,开始时间,事项\n2026-11-02,08:50,改上周五的排班',
      true,
    );
    assert.equal(rows[0].date, '2026-11-02');
    assert.equal(rows[0].title, '改上周五的排班');
  });

  test('日期格式不对 → 留空等人补，不落今天', () => {
    const rows = parseImportRows('日期,事项\n2026/11/02,初始训练', true);
    assert.equal(rows[0].date, '');
  });

  test('没有时间 → 归为待办', () => {
    const rows = parseImportRows('日期,开始时间,事项\n2026-11-04,,整理材料', true);
    assert.equal(rows[0].type, 'task');
    assert.equal(rows[0].time, '');
  });

  test('有时间 → 归为日程', () => {
    const rows = parseImportRows('日期,开始时间,事项\n2026-11-04,09:00,整理材料', true);
    assert.equal(rows[0].type, 'event');
  });

  test('没有表头时按标准七列的位置读', () => {
    const rows = parseImportRows('2026-11-02,08:50,10:30,初始训练,青浦,张教员,备注', false);
    assert.equal(rows[0].title, '初始训练');
    assert.equal(rows[0].date, '2026-11-02');
  });

  test('带表头时按表头名读，顺序可以不同', () => {
    const rows = parseImportRows('事项,日期,开始时间\n初始训练,2026-11-02,08:50', true);
    assert.equal(rows[0].title, '初始训练');
    assert.equal(rows[0].date, '2026-11-02');
    assert.equal(rows[0].time, '08:50');
  });

  test('空行跳过', () => {
    const rows = parseImportRows('日期,事项\n2026-11-02,甲\n\n2026-11-03,乙', true);
    assert.equal(rows.length, 2);
  });

  test('原话优先取备注，没有就用事项', () => {
    const rows = parseImportRows('日期,开始时间,事项,备注\n2026-11-02,08:50,甲,这是原话', true);
    assert.equal(rows[0].raw, '这是原话');
    const rows2 = parseImportRows('日期,开始时间,事项\n2026-11-02,08:50,甲', true);
    assert.equal(rows2[0].raw, '甲');
  });

  test('含逗号的标题解析回来还是一条', () => {
    const rows = parseImportRows('日期,开始时间,事项\n2026-11-02,08:50,"课,含逗号"', true);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].title, '课,含逗号');
  });
});
