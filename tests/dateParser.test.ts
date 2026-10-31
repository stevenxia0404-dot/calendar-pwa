// 规则解析模块的单元测试
//
// 验收标准来自 v4.0 产品说明 表 T13（基准日 2026-10-28 周三）。
// 每条用例都必须通过，否则第 4 步不算完成。

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseText, toDateString } from '../src/lib/dateParser.ts';

// 基准日：2026-10-28 周三
const BASE = new Date(2026, 9, 28);

function p(text: string) {
  return parseText(text, { baseDate: BASE });
}

describe('表 T13 — 解析示例对照', () => {
  test('1. 日期锚点句首剥离；时段配不上钟点故保留', () => {
    const r = p('今天下午要把 B777 的乘务应急检查表改完');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.time, '');
    assert.equal(r.title, '下午要把 B777 的乘务应急检查表改完');
    assert.equal(r.raw, '今天下午要把 B777 的乘务应急检查表改完');
    assert.equal(r.dateConfirmed, 1);
  });

  test('2. 时段加钟点转时间并一起剥离', () => {
    const r = p('下午3点开会');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.time, '15:00');
    assert.equal(r.title, '开会');
    assert.equal(r.raw, '下午3点开会');
  });

  test('3. 中文数字加时段组合', () => {
    const r = p('晚上八点吃饭');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.time, '20:00');
    assert.equal(r.title, '吃饭');
  });

  test('4. 日期锚点句首剥离，原话全文保留', () => {
    const r = p('上周三 带学员走了 B777 应急演练');
    assert.equal(r.date, '2026-10-21');
    assert.equal(r.time, '');
    assert.equal(r.title, '带学员走了 B777 应急演练');
    assert.equal(r.raw, '上周三 带学员走了 B777 应急演练');
  });

  test('5. 日期锚点在句中，保留', () => {
    const r = p('上周五的排班改了');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.time, '');
    assert.equal(r.title, '上周五的排班改了');
    assert.equal(r.raw, '上周五的排班改了');
  });

  test('6. 时段配不上钟点故保留', () => {
    const r = p('明天上午把应急检查表发给王教员');
    assert.equal(r.date, '2026-10-29');
    assert.equal(r.time, '');
    assert.equal(r.title, '上午把应急检查表发给王教员');
  });

  test('7. 相对天数换算后剥离', () => {
    const r = p('3天后体检');
    assert.equal(r.date, '2026-10-31');
    assert.equal(r.title, '体检');
  });

  test('8. 下周加星期换算后剥离', () => {
    const r = p('下周五交表');
    assert.equal(r.date, '2026-11-06');
    assert.equal(r.title, '交表');
  });

  test('9. 本周加星期换算后剥离', () => {
    const r = p('本周五组会');
    assert.equal(r.date, '2026-10-30');
    assert.equal(r.title, '组会');
  });

  test('10. 绝对日期，已过则次年', () => {
    const r = p('10月5号交表');
    assert.equal(r.date, '2027-10-05');
    assert.equal(r.title, '交表');
  });

  test('11. 口语前缀移除加日期锚点剥离', () => {
    const r = p('嗯那个今天好像带学员看了客舱');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.title, '好像带学员看了客舱');
  });

  test('12. 无匹配 → 待确认（"过两天"不在封闭集合）', () => {
    const r = p('过两天再说');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.time, '');
    assert.equal(r.title, '过两天再说');
    assert.equal(r.dateConfirmed, 0);
    assert.equal(r.raw, '过两天再说');
  });
});

describe('日期锚点 — 封闭集合扩充', () => {
  test('今天 / 明天 / 后天 / 昨天 / 前天 / 大后天', () => {
    assert.equal(p('今天体检').date, '2026-10-28');
    assert.equal(p('明天体检').date, '2026-10-29');
    assert.equal(p('后天体检').date, '2026-10-30');
    assert.equal(p('昨天体检').date, '2026-10-27');
    assert.equal(p('前天体检').date, '2026-10-26');
    assert.equal(p('大后天体检').date, '2026-10-31');
  });

  test('N天前', () => {
    assert.equal(p('5天前体检').date, '2026-10-23');
    assert.equal(p('两天前体检').date, '2026-10-26');
  });

  test('上周一 / 上周日', () => {
    // 基准日周三，上周一 = 10-19，上周日 = 10-25
    assert.equal(p('上周一开会').date, '2026-10-19');
    assert.equal(p('上周日开会').date, '2026-10-25');
  });

  test('下个月X号 / 上个月X号', () => {
    assert.equal(p('下个月3号交表').date, '2026-11-03');
    assert.equal(p('上个月28号交表').date, '2026-09-28');
  });

  test('X月X日 与 X/X', () => {
    assert.equal(p('11月15号交表').date, '2026-11-15');
    assert.equal(p('12/20交表').date, '2026-12-20');
  });

  test('未来日期不滚到明年', () => {
    assert.equal(p('11月5号交表').date, '2026-11-05');
  });
});

describe('时间解析', () => {
  test('24 小时制 HH:mm', () => {
    const r = p('15:30 开会');
    assert.equal(r.time, '15:30');
    assert.equal(r.title, '开会');
  });

  test('上午9点', () => {
    const r = p('上午9点体检');
    assert.equal(r.time, '09:00');
  });

  test('中午12点', () => {
    const r = p('中午12点吃饭');
    assert.equal(r.time, '12:00');
  });

  test('下午12点 → 12:00（不是 24:00）', () => {
    const r = p('下午12点吃饭');
    assert.equal(r.time, '12:00');
  });

  test('3点半 → 15:30', () => {
    const r = p('下午3点半开会');
    assert.equal(r.time, '15:30');
  });

  test('无时段词的纯「3点」是歧义，不猜', () => {
    const r = p('3点开会');
    assert.equal(r.time, '');
    assert.equal(r.title, '3点开会');
  });

  test('日期 + 时间同时出现', () => {
    const r = p('明天下午3点开会');
    assert.equal(r.date, '2026-10-29');
    assert.equal(r.time, '15:00');
    assert.equal(r.title, '开会');
  });
});

describe('降级行为 — 必须可修正而非必须成功', () => {
  test('完全无法解析：落基准日 + 待确认 + 原话保留', () => {
    const r = p('随便说点什么');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.dateConfirmed, 0);
    assert.equal(r.raw, '随便说点什么');
    assert.equal(r.title, '随便说点什么');
  });

  test('空输入不崩', () => {
    const r = p('');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.title, '');
    assert.equal(r.raw, '');
  });

  test('纯空白不崩', () => {
    const r = p('   ');
    assert.equal(r.title, '');
  });

  test('「过两天」这类模糊表达判为待确认（不猜）', () => {
    const r = p('过两天再说');
    assert.equal(r.dateConfirmed, 0);
  });

  test('「月底」不在封闭集合，判为待确认', () => {
    const r = p('月底交表');
    assert.equal(r.dateConfirmed, 0);
    assert.equal(r.title, '月底交表');
  });

  test('「下个月吧」不在封闭集合，判为待确认', () => {
    const r = p('下个月吧再说');
    assert.equal(r.dateConfirmed, 0);
  });

  test('只有时间没有日期锚点：语义上是今天，算已确认', () => {
    // 「下午3点开会」隐含今天下午，日期落基准日，用户意图明确
    const r = p('下午3点开会');
    assert.equal(r.date, '2026-10-28');
    assert.equal(r.time, '15:00');
    assert.equal(r.dateConfirmed, 1);
  });

  test('只有时间没有日期锚点，且无任何线索时才待确认', () => {
    const r = p('开会');
    assert.equal(r.dateConfirmed, 0);
  });
});

describe('界面语言规范 — 相对词用完即弃', () => {
  test('句首锚点不进描述', () => {
    for (const text of ['今天体检', '明天体检', '后天体检', '上周三体检', '3天后体检', '下周五体检']) {
      const r = p(text);
      assert.ok(!r.title.includes('今天'), `"${text}" 的描述不应含「今天」`);
      assert.ok(!r.title.includes('明天'), `"${text}" 的描述不应含「明天」`);
      assert.ok(!r.title.includes('后天'), `"${text}" 的描述不应含「后天」`);
      assert.ok(!r.title.includes('上周'), `"${text}" 的描述不应含「上周」`);
      assert.ok(!r.title.includes('3天后'), `"${text}" 的描述不应含「3天后」`);
      assert.ok(!r.title.includes('下周五'), `"${text}" 的描述不应含「下周五」`);
    }
  });

  test('原话永远完整保留', () => {
    const inputs = [
      '今天下午要把 B777 的乘务应急检查表改完',
      '上周三 带学员走了 B777 应急演练',
      '过两天再说',
      '下午3点开会',
    ];
    for (const text of inputs) {
      assert.equal(p(text).raw, text);
    }
  });

  test('描述里不含类型名（event/task/note 等内部概念）', () => {
    const r = p('今天整理培训材料');
    assert.ok(!/event|task|note/i.test(r.title));
  });
});

describe('时间戳与基准日', () => {
  test('toDateString 用本地时区', () => {
    assert.equal(toDateString(new Date(2026, 9, 28)), '2026-10-28');
    assert.equal(toDateString(new Date(2026, 0, 1)), '2026-01-01');
  });

  test('基准日跨月边界：1月30日 + 3天', () => {
    const r = parseText('3天后体检', { baseDate: new Date(2026, 0, 30) });
    assert.equal(r.date, '2026-02-02');
  });

  test('基准日跨年边界：12月30日 + 3天', () => {
    const r = parseText('3天后体检', { baseDate: new Date(2026, 11, 30) });
    assert.equal(r.date, '2027-01-02');
  });

  test('闰年：2024-02-28 + 1天', () => {
    const r = parseText('明天体检', { baseDate: new Date(2024, 1, 28) });
    assert.equal(r.date, '2024-02-29');
  });
});
