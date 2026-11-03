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
  cellToParts,
  cellToText,
  xlsxRowToTemplateCells,
} from '../src/lib/importParser.ts';
import { parseCsvLine, escapeCsvField, toCsvLine, detectDelimiter } from '../src/lib/csv.ts';

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

describe('值归一化 —— 年份必须明确，写法可以不同', () => {
  test('日期认得各种写法，都归到 YYYY-MM-DD', () => {
    assert.equal(normalizeDate('2026-11-02'), '2026-11-02');
    assert.equal(normalizeDate('2026/11/02'), '2026-11-02');
    assert.equal(normalizeDate('2026/11/2'), '2026-11-02');
    assert.equal(normalizeDate('2026.11.02'), '2026-11-02');
    assert.equal(normalizeDate('2026年11月2日'), '2026-11-02');
    assert.equal(normalizeDate('2026年11月02日'), '2026-11-02');
  });

  test('没有年份不认 —— 那是猜', () => {
    assert.equal(normalizeDate('11月2日'), '');
    assert.equal(normalizeDate('11/2'), '');
  });

  test('相对词不认 —— 那是猜', () => {
    assert.equal(normalizeDate('下周二'), '');
    assert.equal(normalizeDate('明天'), '');
    assert.equal(normalizeDate('后天'), '');
  });

  test('不存在的日期不认', () => {
    assert.equal(normalizeDate('2026-02-30'), '');
    assert.equal(normalizeDate('2026-13-01'), '');
    assert.equal(normalizeDate('2026/00/10'), '');
  });

  test('时间认 H:mm 与 HH:mm，其它不认', () => {
    assert.equal(normalizeTime('08:50'), '08:50');
    assert.equal(normalizeTime('8:50'), '08:50');
    assert.equal(normalizeTime('下午3点'), '');
    assert.equal(normalizeTime('25:00'), '');
    assert.equal(normalizeTime('08:70'), '');
    assert.equal(normalizeTime(''), '');
  });

  test('一个格里既有日期又有时间 → 两边都拆出来', () => {
    assert.equal(normalizeDate('2026/11/20 08:50'), '2026-11-20');
    assert.equal(normalizeTime('2026/11/20 08:50'), '08:50');
    assert.equal(normalizeDate('2026-11-20T08:50:00'), '2026-11-20');
    assert.equal(normalizeTime('2026-11-20T08:50:00'), '08:50');
  });
});

describe('分隔符 —— 从 Excel 复制过来的是制表符', () => {
  test('逗号和制表符都能认', () => {
    assert.equal(detectDelimiter('a,b,c'), ',');
    assert.equal(detectDelimiter('a\tb\tc'), '\t');
    // 引号里的不算
    assert.equal(detectDelimiter('"a\tb",c,d'), ',');
  });

  test('制表符分隔的整块文本能解析', () => {
    // 从 Excel 复制一片区域到剪贴板，粘出来长这样
    const text = '日期\t开始时间\t结束时间\t事项\t地点\t人员\t备注\n'
      + '2026/11/20\t8:50\t10:30\t初始训练\t青浦B777\t张教员\n'
      + '2026/11/21\t12:50\t13:50\t团队周会\tC楼201\t全组';
    const rows = parseImportRows(text, true);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].date, '2026-11-20');
    assert.equal(rows[0].time, '08:50');
    assert.equal(rows[0].endTime, '10:30');
    assert.equal(rows[0].title, '初始训练');
    assert.equal(rows[0].location, '青浦B777');
    assert.equal(rows[0].people, '张教员');
    assert.equal(rows[1].date, '2026-11-21');
    assert.equal(rows[1].time, '12:50');
  });

  test('制表符行末尾的空列不能被吃掉', () => {
    // 备注列是空的 —— 整行 trim 会把末尾的制表符连同那一列一起吃掉
    const text = '日期\t事项\t备注\n2026/11/20\t整理文档\t';
    const rows = parseImportRows(text, true);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].date, '2026-11-20');
    assert.equal(rows[0].title, '整理文档');
    assert.equal(rows[0].raw, '整理文档', '备注为空时原话退回用事项');
  });

  test('逗号分隔的老路没变', () => {
    const rows = parseImportRows('日期,开始时间,事项\n2026-11-02,08:50,初始训练', true);
    assert.equal(rows[0].date, '2026-11-02');
    assert.equal(rows[0].time, '08:50');
    assert.equal(rows[0].title, '初始训练');
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
    assert.deepEqual(idx, { date: 0, time: 1, endTime: 2, endDate: -1, content: 3, location: 4, people: 5, note: 6 });
  });

  test('「结束日期」列能被认出来，而且不会被「日期」抢走', () => {
    const idx = mapColumns(['日期', '结束日期', '开始时间', '结束时间', '事项']);
    assert.equal(idx.date, 0);
    assert.equal(idx.endDate, 1);
    assert.equal(idx.time, 2);
    assert.equal(idx.endTime, 3);
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
    // 「下周二」这种相对词不认（要猜），但年份明确的写法认
    assert.equal(parseImportRows('日期,事项\n下周二,初始训练', true)[0].date, '');
    assert.equal(parseImportRows('日期,事项\n2026/11/02,初始训练', true)[0].date, '2026-11-02');
    // 确实不存在的日期也不认
    assert.equal(parseImportRows('日期,事项\n2026-02-30,初始训练', true)[0].date, '');
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

// ==================== xlsx 单元格取值 ====================
//
// 背景：用户在 Excel 里填了课表模板，导进来时间全没了。
//
// 根因不是模板，是读取代码：Excel 里的「时间」也是 Date 对象
// （1899-12-30T08:50:00Z，日期部分只是 Excel 的纪元哨兵），
// 而 cellToText 对 Date 只有一条规则 —— 一律拍成 YYYY-MM-DD。
// 于是 8:50 变成 "1899-12-30"，时间整个丢掉，
// 记录还被静默降级成「没时间的」（不上时间轴）。
//
// 这组测试锁住「Excel 的时间是 Date，不是文本」这件事。

/** 与 read-excel-file 一致的序列号 → Date 换算 */
function excelSerialToDate(serial: number): Date {
  const daysBeforeUnixEpoch = 25569;
  return new Date(Math.floor((serial - daysBeforeUnixEpoch) * 86400000));
}

/** Excel 的「纯时间」单元格：日期部分落在纪元哨兵上 */
function excelTime(h: number, min: number): Date {
  return excelSerialToDate((h * 60 + min) / (24 * 60));
}

/** Excel 的日期单元格（零点） */
function excelDate(y: number, m: number, d: number): Date {
  const days = Math.round((Date.UTC(y, m - 1, d) - Date.UTC(1899, 11, 30)) / 86400000);
  return excelSerialToDate(days);
}

describe('cellToParts —— 把单元格里的日期与时间拆出来', () => {
  test('纯时间单元格取出时间（这次 bug 的核心）', () => {
    const p = cellToParts(excelTime(8, 50));
    assert.equal(p.time, '08:50');
    assert.equal(p.date, '', '纪元哨兵不是日期，不能当成 1899 年的日期导进去');
  });

  test('日期单元格取出日期，且不误判成「零点的事」', () => {
    const p = cellToParts(excelDate(2026, 11, 20));
    assert.equal(p.date, '2026-11-20');
    assert.equal(p.time, '', '纯日期不该被当成零点的时间');
  });

  test('日期和时间在同一个单元格里 → 两边都取到', () => {
    const serial = Math.round((Date.UTC(2026, 10, 20) - Date.UTC(1899, 11, 30)) / 86400000);
    const p = cellToParts(excelSerialToDate(serial + (8 * 60 + 50) / (24 * 60)));
    assert.equal(p.date, '2026-11-20');
    assert.equal(p.time, '08:50');
  });

  test('1904 纪元（Mac 旧版）的纯时间也能取到', () => {
    const p = cellToParts(new Date(Date.UTC(1904, 0, 1, 8, 50)));
    assert.equal(p.time, '08:50');
    assert.equal(p.date, '');
  });

  test('文本单元格：8:50 → 08:50', () => {
    assert.deepEqual(cellToParts('8:50'), { date: '', time: '08:50' });
  });

  test('文本单元格：2026-11-20 → 只出日期', () => {
    assert.deepEqual(cellToParts('2026-11-20'), { date: '2026-11-20', time: '' });
  });

  test('文本单元格：ISO 带时间 → 两边都出', () => {
    assert.deepEqual(cellToParts('2026-11-20T08:50:00'), { date: '2026-11-20', time: '08:50' });
  });

  test('斜杠写法认得 —— 写法不同但年份明确，不是猜', () => {
    assert.deepEqual(cellToParts('2026/11/20'), { date: '2026-11-20', time: '' });
  });

  test('相对词仍不认 —— 那才是猜', () => {
    assert.deepEqual(cellToParts('下周二'), { date: '', time: '' });
    assert.deepEqual(cellToParts('11月2日'), { date: '', time: '' });
  });

  test('数字序列号：一天的小数部分 = 纯时间', () => {
    const p = cellToParts((8 * 60 + 50) / (24 * 60));
    assert.equal(p.time, '08:50');
    assert.equal(p.date, '');
  });

  test('大数字分不清是日期还是普通数字，不猜', () => {
    assert.deepEqual(cellToParts(46284), { date: '', time: '' });
  });

  test('空值', () => {
    assert.deepEqual(cellToParts(null), { date: '', time: '' });
    assert.deepEqual(cellToParts(undefined), { date: '', time: '' });
    assert.deepEqual(cellToParts(''), { date: '', time: '' });
  });
});

describe('整行转换 —— 复刻用户那张课表', () => {
  // 用户下载模板后填的内容：
  //   日期 | 开始时间 | 结束时间 | 事项 | 地点 | 人员 | 备注
  //   2026/11/20 | 8:50 | 10:30 | 初始训练 | 青浦B777经济舱 | 张教员 |
  //   2026/11/21 | 12:50 | 13:50 | 团队周会 | C楼201 | 全组 |
  //   2026/11/22 |      |        | 整理文档 |           |       | 培训材料归档
  const idx = mapColumns(['日期', '开始时间', '结束时间', '事项', '地点', '人员', '备注']);

  test('第一行：日期时间地点人员全部对上', () => {
    const row = [
      excelDate(2026, 11, 20), excelTime(8, 50), excelTime(10, 30),
      '初始训练-模拟航班', '青浦B777经济舱', '张教员', '',
    ];
    assert.deepEqual(
      xlsxRowToTemplateCells(row, idx),
      ['2026-11-20', '08:50', '10:30', '初始训练-模拟航班', '青浦B777经济舱', '张教员', '', ''],
    );
  });

  test('三行整张表都对', () => {
    const rows = [
      [excelDate(2026, 11, 20), excelTime(8, 50), excelTime(10, 30), '初始训练-模拟航班', '青浦B777经济舱', '张教员', ''],
      [excelDate(2026, 11, 21), excelTime(12, 50), excelTime(13, 50), '团队周会', 'C楼201', '全组', ''],
      [excelDate(2026, 11, 22), '', '', '整理文档', '', '', '培训材料归档'],
    ];
    const out = rows.map(r => xlsxRowToTemplateCells(r, idx));
    assert.deepEqual(out[0].slice(0, 3), ['2026-11-20', '08:50', '10:30']);
    assert.deepEqual(out[1].slice(0, 3), ['2026-11-21', '12:50', '13:50']);
    assert.deepEqual(out[2].slice(0, 3), ['2026-11-22', '', '']);
    assert.equal(out[2][6], '培训材料归档');
  });

  test('转成 CSV 再解析回来，时间还在（往返不丢）', () => {
    const row = [
      excelDate(2026, 11, 20), excelTime(8, 50), excelTime(10, 30),
      '初始训练', '青浦B777经济舱', '张教员', '',
    ];
    const csv = '日期,开始时间,结束时间,事项,地点,人员,备注\n'
      + toCsvLine(xlsxRowToTemplateCells(row, idx));
    const drafts = parseImportRows(csv, true);
    assert.equal(drafts.length, 1);
    assert.equal(drafts[0].date, '2026-11-20');
    assert.equal(drafts[0].time, '08:50');
    assert.equal(drafts[0].endTime, '10:30');
    // 关键：有时间就该是带时间轴的事，不能被静默降级成待办
    assert.equal(drafts[0].type, 'event');
  });

  test('本来就没时间的行，仍然是「没时间」', () => {
    const row = [excelDate(2026, 11, 22), '', '', '整理文档', '', '', '培训材料归档'];
    const csv = '日期,开始时间,结束时间,事项,地点,人员,备注\n'
      + toCsvLine(xlsxRowToTemplateCells(row, idx));
    const drafts = parseImportRows(csv, true);
    assert.equal(drafts[0].time, '');
    assert.equal(drafts[0].type, 'task');
  });

  test('一个单元格里带日期和时间，时间列空着 → 时间取出来', () => {
    const serial = Math.round((Date.UTC(2026, 10, 20) - Date.UTC(1899, 11, 30)) / 86400000);
    const row = [excelSerialToDate(serial + (8 * 60 + 50) / (24 * 60)), '', '', '整理文档', '', '', ''];
    const cells = xlsxRowToTemplateCells(row, idx);
    assert.equal(cells[0], '2026-11-20');
    assert.equal(cells[1], '08:50', '时间就在那个单元格里，不该丢');
  });
});
